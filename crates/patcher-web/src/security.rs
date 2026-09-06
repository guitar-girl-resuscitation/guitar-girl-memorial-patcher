//! Bounded admission control. Only an explicitly trusted socket peer may
//! supply the single client-IP header; arbitrary X-Forwarded-For is never used.
use axum::{
    Json,
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use ipnet::IpNet;
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityConfig {
    pub public_origin: Option<String>,
    pub trusted_proxies: Vec<IpNet>,
    pub client_ip_header: String,
    pub require_trusted_proxy: bool,
    pub allow_lan_proxy: bool,
    pub requests_per_minute: u32,
    pub api_per_minute: u32,
    pub uploads_per_ten_minutes: u32,
    pub downloads_per_ten_minutes: u32,
    pub failures_before_ban: u32,
    pub failure_window_seconds: u64,
    pub ban_seconds: u64,
    pub max_tracked_ips: usize,
    pub max_in_flight: usize,
    pub max_in_flight_per_ip: usize,
}
impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            public_origin: None,
            trusted_proxies: vec![],
            client_ip_header: "x-real-ip".into(),
            require_trusted_proxy: false,
            allow_lan_proxy: false,
            requests_per_minute: 60,
            api_per_minute: 20,
            uploads_per_ten_minutes: 2,
            downloads_per_ten_minutes: 4,
            failures_before_ban: 8,
            failure_window_seconds: 600,
            ban_seconds: 900,
            max_tracked_ips: 8192,
            max_in_flight: 32,
            max_in_flight_per_ip: 4,
        }
    }
}
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
#[derive(Clone, Copy)]
enum Class {
    General,
    Api,
    Upload,
    Download,
}
impl Class {
    fn of(path: &str) -> Self {
        if path == "/api/v1/patch" {
            Self::Upload
        } else if path.starts_with("/api/v1/download/") {
            Self::Download
        } else if path.starts_with("/api/") {
            Self::Api
        } else {
            Self::General
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::General => "page",
            Self::Api => "control",
            Self::Upload => "upload",
            Self::Download => "download",
        }
    }
}
struct Bucket {
    tokens: f64,
    updated: Instant,
}
impl Bucket {
    fn new(cap: u32, now: Instant) -> Self {
        Self {
            tokens: cap as f64,
            updated: now,
        }
    }
    fn take(&mut self, cap: u32, period: u64, now: Instant) -> Result<(), u64> {
        self.tokens = (self.tokens
            + now.saturating_duration_since(self.updated).as_secs_f64() * cap as f64
                / period as f64)
            .min(cap as f64);
        self.updated = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(((1.0 - self.tokens) * period as f64 / cap as f64)
                .ceil()
                .max(1.0) as u64)
        }
    }
}
struct Client {
    buckets: [Bucket; 4],
    last_seen: Instant,
    failures: u32,
    failure_start: Instant,
    banned_until: Option<Instant>,
    in_flight: usize,
}
impl Client {
    fn new(c: &SecurityConfig, now: Instant) -> Self {
        Self {
            buckets: [
                Bucket::new(c.requests_per_minute, now),
                Bucket::new(c.api_per_minute, now),
                Bucket::new(c.uploads_per_ten_minutes, now),
                Bucket::new(c.downloads_per_ten_minutes, now),
            ],
            last_seen: now,
            failures: 0,
            failure_start: now,
            banned_until: None,
            in_flight: 0,
        }
    }
}
struct Ledger {
    clients: HashMap<IpAddr, Client>,
    last_sweep: Instant,
}
pub struct Security {
    config: SecurityConfig,
    authority: Option<String>,
    ledger: Mutex<Ledger>,
    permits: Arc<Semaphore>,
}
impl Security {
    pub fn new(config: SecurityConfig) -> Result<Arc<Self>, String> {
        for n in [
            config.requests_per_minute,
            config.api_per_minute,
            config.uploads_per_ten_minutes,
            config.downloads_per_ten_minutes,
            config.failures_before_ban,
        ] {
            if !(1..=10000).contains(&n) {
                return Err("security limits must be in 1..10000".into());
            }
        }
        if !(1..=65536).contains(&config.max_tracked_ips)
            || !(1..=256).contains(&config.max_in_flight)
            || !(1..=config.max_in_flight).contains(&config.max_in_flight_per_ip)
            || !(1..=86400).contains(&config.ban_seconds)
            || !(1..=86400).contains(&config.failure_window_seconds)
        {
            return Err("invalid security memory/concurrency/time limits".into());
        }
        if !["x-real-ip", "cf-connecting-ip"].contains(&config.client_ip_header.as_str())
            || config.trusted_proxies.len() > 64
            || config.trusted_proxies.iter().any(|n| n.prefix_len() == 0)
            || (config.require_trusted_proxy && config.trusted_proxies.is_empty())
        {
            return Err(
                "invalid trusted proxy configuration; never trust all addresses or XFF chains"
                    .into(),
            );
        }
        let authority = if let Some(origin) = &config.public_origin {
            let uri: axum::http::Uri = origin.parse().map_err(|_| "invalid publicOrigin")?;
            let authority = uri.authority().ok_or("publicOrigin needs an authority")?;
            if uri.scheme_str() != Some("https")
                || authority.as_str().contains('@')
                || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
                || origin.ends_with('/')
            {
                return Err(
                    "publicOrigin must be https://host[:port], without path or trailing slash"
                        .into(),
                );
            }
            Some(authority.as_str().to_ascii_lowercase())
        } else {
            None
        };
        let now = Instant::now();
        Ok(Arc::new(Self {
            permits: Arc::new(Semaphore::new(config.max_in_flight)),
            config,
            authority,
            ledger: Mutex::new(Ledger {
                clients: HashMap::new(),
                last_sweep: now,
            }),
        }))
    }
    pub fn validate_listen(&self, address: SocketAddr) -> Result<(), String> {
        if self.config.allow_lan_proxy {
            let private = |ip: IpAddr| match canonical(ip) {
                IpAddr::V4(v) => v.is_private(),
                IpAddr::V6(v) => v.is_unique_local(),
            };
            let exact_private_peer = |n: &IpNet| {
                n.prefix_len() == (if n.addr().is_ipv4() { 32 } else { 128 }) && private(n.addr())
            };
            if self.authority.is_none()
                || !self.config.require_trusted_proxy
                || self.config.client_ip_header != "cf-connecting-ip"
                || !self.config.trusted_proxies.iter().any(exact_private_peer)
                || self.config.trusted_proxies.iter().any(|n| {
                    !matches!(n.to_string().as_str(), "127.0.0.1/32" | "::1/128")
                        && !exact_private_peer(n)
                })
                || !(address.ip().is_loopback()
                    || address.ip().is_unspecified()
                    || private(address.ip()))
            {
                return Err("LAN proxy requires HTTPS publicOrigin, CF-Connecting-IP, requireTrustedProxy and exact private proxy IPs (/32 or /128)".into());
            }
            return Ok(());
        }
        if !address.ip().is_loopback() {
            return Err("listen must be loopback; public ingress is Cloudflare Tunnel only".into());
        }
        if self.authority.is_some()
            && (!self.config.require_trusted_proxy
                || self.config.client_ip_header != "cf-connecting-ip"
                || self.config.trusted_proxies.is_empty()
                || self
                    .config
                    .trusted_proxies
                    .iter()
                    .any(|n| !matches!(n.to_string().as_str(), "127.0.0.1/32" | "::1/128")))
        {
            return Err(
                "public ingress requires CF-Connecting-IP from the local tunnel connector only"
                    .into(),
            );
        }
        Ok(())
    }
    fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> Result<IpAddr, Box<Response>> {
        let peer = canonical(peer);
        let trusted = self
            .config
            .trusted_proxies
            .iter()
            .any(|net| net.contains(&peer));
        if !trusted {
            if self.config.require_trusted_proxy {
                return Err(reject(StatusCode::FORBIDDEN, "trusted proxy required", None).into());
            }
            return Ok(peer);
        }
        let values = headers.get_all(&self.config.client_ip_header);
        let mut values = values.iter();
        let ip = values
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<IpAddr>().ok());
        if ip.is_none() || values.next().is_some() {
            // Misconfigured proxy != abusive visitor: never ban the shared proxy.
            return Err(reject(
                StatusCode::BAD_GATEWAY,
                "trusted proxy client IP missing or invalid",
                None,
            )
            .into());
        }
        Ok(canonical(ip.unwrap()))
    }
    fn admit(&self, ip: IpAddr, class: Class, now: Instant) -> Result<(), Box<Response>> {
        let mut ledger = self.ledger.lock().unwrap();
        if now.saturating_duration_since(ledger.last_sweep) >= Duration::from_secs(60) {
            let ttl = Duration::from_secs(self.config.failure_window_seconds.max(600) + 60);
            ledger.clients.retain(|_, c| {
                c.in_flight != 0
                    || c.banned_until.is_some_and(|until| until > now)
                    || now.saturating_duration_since(c.last_seen) < ttl
            });
            ledger.last_sweep = now;
        }
        if !ledger.clients.contains_key(&ip) && ledger.clients.len() >= self.config.max_tracked_ips
        {
            return Err(reject(
                StatusCode::SERVICE_UNAVAILABLE,
                "admission capacity reached",
                Some(60),
            )
            .into());
        }
        let c = ledger
            .clients
            .entry(ip)
            .or_insert_with(|| Client::new(&self.config, now));
        c.last_seen = now;
        if let Some(until) = c.banned_until {
            if until > now {
                return Err(reject(
                    StatusCode::TOO_MANY_REQUESTS,
                    "temporarily banned",
                    Some(until.duration_since(now).as_secs() + 1),
                )
                .into());
            }
            c.banned_until = None;
            c.failures = 0;
        }
        if c.in_flight >= self.config.max_in_flight_per_ip {
            return Err(reject(
                StatusCode::TOO_MANY_REQUESTS,
                "too many active requests",
                Some(5),
            )
            .into());
        }
        let budget = match class {
            Class::General => None,
            Class::Api => Some((1, self.config.api_per_minute, 60)),
            Class::Upload => Some((2, self.config.uploads_per_ten_minutes, 600)),
            Class::Download => Some((3, self.config.downloads_per_ten_minutes, 600)),
        };
        c.buckets[0]
            .take(self.config.requests_per_minute, 60, now)
            .map_err(|s| {
                reject(
                    StatusCode::TOO_MANY_REQUESTS,
                    "request rate exceeded",
                    Some(s),
                )
            })?;
        if let Some((i, cap, seconds)) = budget {
            c.buckets[i].take(cap, seconds, now).map_err(|s| {
                reject(
                    StatusCode::TOO_MANY_REQUESTS,
                    "operation rate exceeded",
                    Some(s),
                )
            })?;
        }
        c.in_flight += 1;
        Ok(())
    }
    fn failed(&self, ip: IpAddr, status: StatusCode, now: Instant) {
        if !matches!(
            status.as_u16(),
            400 | 401 | 403 | 404 | 405 | 413 | 415 | 422
        ) {
            return;
        }
        let mut ledger = self.ledger.lock().unwrap();
        let Some(c) = ledger.clients.get_mut(&ip) else {
            return;
        };
        if c.failures == 0
            || now.saturating_duration_since(c.failure_start)
                >= Duration::from_secs(self.config.failure_window_seconds)
        {
            c.failure_start = now;
            c.failures = 0;
        }
        c.failures += 1;
        // Only parsed IP and fixed reason are logged: no URI, tokens or input.
        tracing::warn!(target: "ggfm_security", "GGFM_ABUSE client_ip={} reason=client_rejected", ip);
        if c.failures >= self.config.failures_before_ban {
            c.banned_until = Some(now + Duration::from_secs(self.config.ban_seconds));
            tracing::warn!(target: "ggfm_security", "GGFM_BAN client_ip={} seconds={}", ip, self.config.ban_seconds);
        }
    }
    fn leave(&self, ip: IpAddr) {
        if let Some(c) = self.ledger.lock().unwrap().clients.get_mut(&ip) {
            c.in_flight = c.in_flight.saturating_sub(1);
        }
    }
}
struct Lease {
    security: Arc<Security>,
    ip: IpAddr,
    _permit: OwnedSemaphorePermit,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.security.leave(self.ip);
    }
}

fn reject(status: StatusCode, message: &str, retry: Option<u64>) -> Response {
    let mut response = (status, Json(serde_json::json!({"error": message}))).into_response();
    if let Some(seconds) = retry {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, seconds.to_string().parse().unwrap());
    }
    response
}
fn response_headers(response: &mut Response, https: bool) {
    let retryable = matches!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
    );
    let h = response.headers_mut();
    if retryable && !h.contains_key(header::RETRY_AFTER) {
        h.insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
    }
    for (name, value) in [
        ("cache-control", "private, no-store, max-age=0"),
        ("cdn-cache-control", "no-store"),
        ("cloudflare-cdn-cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=()",
        ),
    ] {
        h.insert(name, HeaderValue::from_static(value));
    }
    if https {
        h.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000"),
        );
    }
}

pub async fn protect(
    State(security): State<Arc<Security>>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = protect_inner(security.clone(), request, next).await;
    response_headers(&mut response, security.authority.is_some());
    response
}
#[derive(Clone, Copy)]
pub struct ResolvedClientIp(pub IpAddr);

async fn protect_inner(security: Arc<Security>, mut request: Request, next: Next) -> Response {
    let Some(peer) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|p| p.0.ip())
    else {
        return reject(
            StatusCode::INTERNAL_SERVER_ERROR,
            "transport peer unavailable",
            None,
        );
    };
    let ip = match security.client_ip(peer, request.headers()) {
        Ok(ip) => ip,
        Err(r) => return *r,
    };
    request.extensions_mut().insert(ResolvedClientIp(ip));
    let class = Class::of(request.uri().path());
    let permit = match security.permits.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return reject(StatusCode::SERVICE_UNAVAILABLE, "server busy", Some(5)),
    };
    if let Err(r) = security.admit(ip, class, Instant::now()) {
        return *r;
    }
    let lease = Lease {
        security: security.clone(),
        ip,
        _permit: permit,
    };
    let mut denied = None;
    if let Some(authority) = &security.authority {
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .or_else(|| request.uri().authority().map(|a| a.as_str()));
        if !host.is_some_and(|h| h.eq_ignore_ascii_case(authority)) {
            denied = Some(reject(StatusCode::BAD_REQUEST, "unexpected host", None));
        }
        if request.headers().get(header::ORIGIN).is_some_and(|o| {
            Some(o.as_bytes()) != security.config.public_origin.as_ref().map(|s| s.as_bytes())
        }) {
            denied = Some(reject(
                StatusCode::FORBIDDEN,
                "cross-origin request denied",
                None,
            ));
        }
    }
    if request.uri().path().starts_with("/api/")
        && request
            .headers()
            .get("sec-fetch-site")
            .is_some_and(|v| v == "cross-site")
    {
        denied = Some(reject(
            StatusCode::FORBIDDEN,
            "cross-site API request denied",
            None,
        ));
    }
    if request.uri().to_string().len() > 2048 {
        denied = Some(reject(
            StatusCode::BAD_REQUEST,
            "request target too long",
            None,
        ));
    }
    let limit = if matches!(class, Class::Upload) {
        768_u64 * 1024 * 1024
    } else {
        2 * 1024 * 1024
    };
    if request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|n| n > limit)
    {
        denied = Some(reject(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large",
            None,
        ));
    }
    let response = if let Some(r) = denied {
        r
    } else if matches!(class, Class::Upload) {
        next.run(request).await // upload and each build tool already have bounded timeouts
    } else {
        match tokio::time::timeout(Duration::from_secs(15), next.run(request)).await {
            Ok(r) => r,
            Err(_) => reject(StatusCode::REQUEST_TIMEOUT, "request timed out", None),
        }
    };
    security.failed(ip, response.status(), Instant::now());
    tracing::info!(target: "ggfm_security", client_ip = %ip, operation = class.label(),
                   status = response.status().as_u16(), "request completed");
    // A slow download still owns its slots after response headers are returned.
    // Dropping/cancelling the body releases both leases. No unbounded queue.
    let (parts, body) = response.into_parts();
    let stream = body
        .into_data_stream()
        .take_until(tokio::time::sleep(Duration::from_secs(1800)))
        .map(move |chunk| {
            let _keep_alive = &lease;
            chunk
        });
    Response::from_parts(parts, Body::from_stream(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, middleware, routing::get};
    use tower::ServiceExt;
    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }
    fn config() -> SecurityConfig {
        SecurityConfig::default()
    }

    #[test]
    fn forged_proxy_headers_never_override_untrusted_peer() {
        let s = Security::new(config()).unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "192.0.2.99".parse().unwrap());
        h.insert("x-forwarded-for", "192.0.2.98".parse().unwrap());
        h.insert("cf-connecting-ip", "192.0.2.97".parse().unwrap());
        assert_eq!(s.client_ip(ip("192.0.2.1"), &h).unwrap(), ip("192.0.2.1"));
        assert_eq!(
            s.client_ip(ip("::ffff:192.0.2.1"), &h).unwrap(),
            ip("192.0.2.1")
        );
    }
    #[test]
    fn trusted_proxy_requires_exactly_one_valid_ip_and_can_require_proxy_ingress() {
        let mut c = config();
        c.trusted_proxies = vec!["127.0.0.1/32".parse().unwrap()];
        c.require_trusted_proxy = true;
        let s = Security::new(c).unwrap();
        let mut h = HeaderMap::new();
        assert!(s.client_ip(ip("127.0.0.1"), &h).is_err());
        h.insert("x-real-ip", "2001:db8::1".parse().unwrap());
        assert_eq!(s.client_ip(ip("127.0.0.1"), &h).unwrap(), ip("2001:db8::1"));
        assert!(s.client_ip(ip("192.0.2.1"), &h).is_err());
        h.append("x-real-ip", "192.0.2.1".parse().unwrap());
        assert!(s.client_ip(ip("127.0.0.1"), &h).is_err());
    }
    #[test]
    fn bad_configuration_fails_at_startup() {
        for network in ["0.0.0.0/0", "::/0"] {
            let mut c = config();
            c.trusted_proxies = vec![network.parse().unwrap()];
            assert!(Security::new(c).is_err());
        }
        for origin in [
            "http://example.org",
            "https://example.org/",
            "https://example.org/api",
            "https://user@example.org",
            "https://example.org?bad=1",
        ] {
            let mut c = config();
            c.public_origin = Some(origin.into());
            assert!(Security::new(c).is_err(), "{origin}");
        }
        let s = Security::new(config()).unwrap();
        assert!(s.validate_listen("0.0.0.0:8080".parse().unwrap()).is_err());
        assert!(s.validate_listen("127.0.0.1:8080".parse().unwrap()).is_ok());
    }
    #[test]
    fn lan_proxy_is_explicit_and_requires_exact_private_peers() {
        let mut c = config();
        c.public_origin = Some("https://example.org".into());
        c.allow_lan_proxy = true;
        c.require_trusted_proxy = true;
        c.client_ip_header = "cf-connecting-ip".into();
        c.trusted_proxies = vec![
            "127.0.0.1/32".parse().unwrap(),
            "10.0.0.1/32".parse().unwrap(),
        ];
        let s = Security::new(c.clone()).unwrap();
        assert!(s.validate_listen("0.0.0.0:19078".parse().unwrap()).is_ok());
        assert!(
            s.validate_listen("10.0.100.8:19078".parse().unwrap())
                .is_ok()
        );
        assert!(s.validate_listen("8.8.8.8:19078".parse().unwrap()).is_err());
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "192.0.2.10".parse().unwrap());
        assert_eq!(s.client_ip(ip("10.0.0.1"), &h).unwrap(), ip("192.0.2.10"));
        assert!(s.client_ip(ip("10.0.0.2"), &h).is_err());
        assert!(s.client_ip(ip("10.0.0.1"), &HeaderMap::new()).is_err());
        for network in ["10.0.0.0/8", "8.8.8.8/32", "::/0"] {
            let mut bad = c.clone();
            bad.trusted_proxies = vec![network.parse().unwrap()];
            assert!(
                Security::new(bad)
                    .and_then(|s| s.validate_listen("0.0.0.0:19078".parse().unwrap()))
                    .is_err()
            );
        }
        for change in 0..4 {
            let mut bad = c.clone();
            match change {
                0 => bad.allow_lan_proxy = false,
                1 => bad.require_trusted_proxy = false,
                2 => bad.client_ip_header = "x-forwarded-for".into(),
                _ => bad.public_origin = None,
            }
            assert!(
                Security::new(bad)
                    .and_then(|s| s.validate_listen("0.0.0.0:19078".parse().unwrap()))
                    .is_err()
            );
        }
    }
    #[test]
    fn public_example_requires_cloudflare_tunnel_and_loopback() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../config/patcher.example.json")).unwrap();
        let c: SecurityConfig = serde_json::from_value(v["security"].clone()).unwrap();
        let s = Security::new(c.clone()).unwrap();
        assert!(s.validate_listen("127.0.0.1:8080".parse().unwrap()).is_ok());
        assert!(s.validate_listen("0.0.0.0:8080".parse().unwrap()).is_err());
        for change in 0..3 {
            let mut bad = c.clone();
            match change {
                0 => bad.require_trusted_proxy = false,
                1 => bad.client_ip_header = "x-real-ip".into(),
                _ => bad.trusted_proxies = vec!["10.0.0.0/8".parse().unwrap()],
            }
            assert!(
                Security::new(bad)
                    .unwrap()
                    .validate_listen("127.0.0.1:8080".parse().unwrap())
                    .is_err()
            );
        }
    }
    #[tokio::test]
    async fn cloudflare_visitors_have_independent_bans_not_a_shared_connector_ban() {
        let mut c = config();
        c.public_origin = Some("https://example.org".into());
        c.trusted_proxies = vec!["127.0.0.1/32".parse().unwrap()];
        c.client_ip_header = "cf-connecting-ip".into();
        c.require_trusted_proxy = true;
        c.failures_before_ban = 2;
        let s = Security::new(c).unwrap();
        s.validate_listen("127.0.0.1:8080".parse().unwrap())
            .unwrap();
        let app = router(s.clone());
        let cf = |path: &str, visitor: &str| {
            let mut r = request(path, None);
            r.extensions_mut().insert(ConnectInfo(
                "127.0.0.1:23456".parse::<SocketAddr>().unwrap(),
            ));
            r.headers_mut()
                .insert("cf-connecting-ip", visitor.parse().unwrap());
            r
        };
        for _ in 0..2 {
            let r = app
                .clone()
                .oneshot(cf("/missing", "192.0.2.1"))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::NOT_FOUND);
        }
        assert_eq!(
            app.clone()
                .oneshot(cf("/", "192.0.2.1"))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            app.clone()
                .oneshot(cf("/", "192.0.2.2"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert!(
            !s.ledger
                .lock()
                .unwrap()
                .clients
                .contains_key(&ip("127.0.0.1"))
        );
        assert_eq!(
            app.oneshot(request("/", None)).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    #[test]
    fn failures_ban_only_the_offender_then_expire_without_wall_clock_dependence() {
        let mut c = config();
        c.failures_before_ban = 2;
        c.ban_seconds = 30;
        let s = Security::new(c).unwrap();
        let now = Instant::now();
        let a = ip("192.0.2.1");
        let b = ip("192.0.2.2");
        s.admit(a, Class::Api, now).unwrap();
        s.leave(a);
        s.failed(a, StatusCode::UNAUTHORIZED, now);
        s.failed(a, StatusCode::UNPROCESSABLE_ENTITY, now);
        let blocked = s.admit(a, Class::Api, now).err().unwrap();
        assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(blocked.headers().contains_key(header::RETRY_AFTER));
        s.admit(b, Class::Api, now).unwrap();
        s.leave(b);
        s.admit(a, Class::Api, now + Duration::from_secs(31))
            .unwrap();
        s.leave(a);
    }
    #[test]
    fn capacity_busy_expiry_and_build_errors_do_not_count_as_abuse() {
        let s = Security::new(config()).unwrap();
        let now = Instant::now();
        let a = ip("192.0.2.1");
        s.admit(a, Class::Api, now).unwrap();
        s.leave(a);
        for code in [408, 409, 410, 429, 500, 502, 503, 504] {
            for _ in 0..10 {
                s.failed(a, StatusCode::from_u16(code).unwrap(), now);
            }
        }
        assert_eq!(s.ledger.lock().unwrap().clients[&a].failures, 0);
        s.admit(a, Class::Api, now).unwrap();
        s.leave(a);
    }
    #[test]
    fn upload_bucket_refills_and_identity_table_is_bounded() {
        let mut c = config();
        c.uploads_per_ten_minutes = 1;
        c.max_tracked_ips = 1;
        let s = Security::new(c).unwrap();
        let now = Instant::now();
        let a = ip("192.0.2.1");
        s.admit(a, Class::Upload, now).unwrap();
        s.leave(a);
        assert_eq!(
            s.admit(a, Class::Upload, now).err().unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        s.admit(a, Class::Upload, now + Duration::from_secs(600))
            .unwrap();
        s.leave(a);
        assert_eq!(
            s.admit(ip("192.0.2.2"), Class::Api, now + Duration::from_secs(600))
                .err()
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(s.ledger.lock().unwrap().clients.len(), 1);
    }
    #[test]
    fn expired_entries_are_pruned_but_live_bans_and_streams_are_not() {
        let mut c = config();
        c.max_tracked_ips = 1;
        c.failures_before_ban = 1;
        c.ban_seconds = 3600;
        let s = Security::new(c).unwrap();
        let now = Instant::now();
        let a = ip("192.0.2.1");
        s.admit(a, Class::Api, now).unwrap();
        s.leave(a);
        s.failed(a, StatusCode::UNAUTHORIZED, now);
        assert!(
            s.admit(ip("192.0.2.2"), Class::Api, now + Duration::from_secs(1000))
                .is_err()
        );
        s.admit(ip("192.0.2.2"), Class::Api, now + Duration::from_secs(4000))
            .unwrap();
    }
    fn router(s: Arc<Security>) -> Router {
        Router::new()
            .route("/", get(|| async { "test" }))
            .route(
                "/api/v1/download/{token}",
                get(|| async { "synthetic result" }),
            )
            .layer(middleware::from_fn_with_state(s, protect))
    }
    fn request(path: &str, origin: Option<&str>) -> Request {
        let mut r = Request::builder()
            .uri(path)
            .header("host", "example.org")
            .body(Body::empty())
            .unwrap();
        r.extensions_mut().insert(ConnectInfo(
            "192.0.2.1:23456".parse::<SocketAddr>().unwrap(),
        ));
        if let Some(o) = origin {
            r.headers_mut().insert(header::ORIGIN, o.parse().unwrap());
        }
        r
    }
    #[tokio::test]
    async fn body_keeps_concurrency_slot_and_all_responses_disable_cdn_caching() {
        let mut c = config();
        c.max_in_flight = 1;
        c.max_in_flight_per_ip = 1;
        c.public_origin = Some("https://example.org".into());
        let s = Security::new(c).unwrap();
        let app = router(s.clone());
        let first = app
            .clone()
            .oneshot(request("/api/v1/download/test", None))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(first.headers()["cdn-cache-control"], "no-store");
        assert_eq!(first.headers()["referrer-policy"], "no-referrer");
        assert!(first.headers().contains_key("strict-transport-security"));
        assert_eq!(s.permits.available_permits(), 0);
        let second = app.clone().oneshot(request("/", None)).await.unwrap();
        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            second.headers()["cache-control"]
                .to_str()
                .unwrap()
                .contains("no-store")
        );
        drop(first);
        assert_eq!(s.permits.available_permits(), 1);
        assert_eq!(
            app.oneshot(request("/", None)).await.unwrap().status(),
            StatusCode::OK
        );
    }
    #[tokio::test]
    async fn origin_host_and_browser_cross_site_guards_are_enforced() {
        let mut c = config();
        c.public_origin = Some("https://example.org".into());
        let app = router(Security::new(c).unwrap());
        assert_eq!(
            app.clone()
                .oneshot(request("/", Some("https://foreign.example")))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut bad = request("/", None);
        bad.headers_mut()
            .insert("host", "foreign.example".parse().unwrap());
        assert_eq!(
            app.clone().oneshot(bad).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
        let mut bad = request("/api/v1/download/test", None);
        bad.headers_mut()
            .insert("sec-fetch-site", "cross-site".parse().unwrap());
        assert_eq!(
            app.clone().oneshot(bad).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.oneshot(request("/", Some("https://example.org")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    #[tokio::test]
    async fn oversized_requests_are_rejected_before_a_handler_and_errors_do_not_leak_paths() {
        let app = router(Security::new(config()).unwrap());
        let mut r = request("/", None);
        r.headers_mut()
            .insert("content-length", "9999999".parse().unwrap());
        assert_eq!(
            app.oneshot(r).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let r = crate::WebError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "private/path/to/signing".into(),
        )
        .into_response();
        let bytes = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("private/path"));
    }
}
