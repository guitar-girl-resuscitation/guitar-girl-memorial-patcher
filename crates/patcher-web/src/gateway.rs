//! Stable, streaming ingress. Only an operator-owned route file can select
//! upstreams; no client-supplied URL is ever used as an upstream address.
use super::*;
use axum::{extract::ConnectInfo, middleware::Next};
use std::sync::{Mutex as StdMutex, atomic::{AtomicUsize, Ordering}};

#[derive(Deserialize)]
struct Routes { active: u32, targets: BTreeMap<u32, u16>, legacy: Option<u32> }
#[derive(Clone)]
struct Gateway {
    routes: PathBuf, key: String, client: reqwest::Client,
    counts: Arc<StdMutex<BTreeMap<u32, Arc<AtomicUsize>>>>,
}
struct Flight(Arc<AtomicUsize>);
impl Drop for Flight { fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); } }

pub fn tag_token(token: &str) -> String {
    match std::env::var("GGFM_ROUTE_REVISION").ok().and_then(|v| v.parse::<u32>().ok()) {
        Some(revision) => format!("g{revision}.{token}"), None => token.to_owned(),
    }
}
pub fn untag_token(token: &str) -> &str {
    token.split_once('.').filter(|(head, _)| head.strip_prefix('g').is_some_and(|v| v.parse::<u32>().is_ok()))
        .map_or(token, |(_, tail)| tail)
}
fn token_revision(token: &str) -> Option<u32> {
    token.split_once('.')?.0.strip_prefix('g')?.parse().ok()
}
pub fn build_lock() -> std::io::Result<Option<fs::File>> {
    let Some(path) = std::env::var_os("GGFM_BUILD_LOCK") else { return Ok(None) };
    let file = fs::OpenOptions::new().create(true).truncate(false).read(true).write(true).open(path)?;
    file.lock()?;
    Ok(Some(file))
}
pub async fn worker_guard(request: Request, next: Next) -> Response {
    if let Ok(key) = std::env::var("GGFM_GATEWAY_KEY") {
        let local = request.extensions().get::<ConnectInfo<SocketAddr>>().is_some_and(|p| p.0.ip().is_loopback());
        if !local || request.headers().get("x-ggfm-gateway-key").is_none_or(|v| v.as_bytes() != key.as_bytes()) {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    next.run(request).await
}
fn clean_headers(headers: &mut HeaderMap) {
    let nominated: Vec<String> = headers.get_all(header::CONNECTION).iter()
        .filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',').map(|v| v.trim().to_owned())).collect();
    for name in nominated { headers.remove(name); }
    for name in ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "x-ggfm-gateway-key", "x-ggfm-client-ip"] {
        headers.remove(name);
    }
}
async fn forward(State(state): State<Gateway>, mut request: Request) -> Result<Response, WebError> {
    let path = request.uri().path().to_owned();
    let mut revision = path.strip_prefix("/api/v1/download/").and_then(token_revision);
    if path == "/api/v1/prebuilt/prove" {
        let (mut parts, body) = request.into_parts();
        let data = axum::body::to_bytes(body, 2 * 1024 * 1024).await
            .map_err(|_| WebError(StatusCode::BAD_REQUEST, "invalid proof body".into()))?;
        let value: serde_json::Value = serde_json::from_slice(&data)
            .map_err(|_| WebError(StatusCode::BAD_REQUEST, "invalid proof JSON".into()))?;
        revision = value["proof"]["nonce"].as_str().and_then(token_revision);
        parts.headers.remove(header::CONTENT_LENGTH);
        request = Request::from_parts(parts, Body::from(data));
    }
    let bytes = tokio::fs::read(&state.routes).await.map_err(internal)?;
    if bytes.len() > 8192 { return Err(WebError(StatusCode::SERVICE_UNAVAILABLE, "invalid route table".into())); }
    let routes: Routes = serde_json::from_slice(&bytes).map_err(internal)?;
    let continuation = path.starts_with("/api/v1/download/") || path == "/api/v1/prebuilt/prove";
    let selected = if continuation {
        revision.or(routes.legacy).ok_or_else(|| WebError(StatusCode::GONE, "previous token expired; retry from the page".into()))?
    } else { routes.active };
    // The first migration may still be serving a worker without the shared
    // build lock. Keep its prepared downloads online, but don't start old builds.
    if path == "/api/v1/patch" && routes.legacy == Some(selected) {
        return Err(WebError(StatusCode::SERVICE_UNAVAILABLE, "initial worker migration; retry shortly".into()));
    }
    let port = routes.targets.get(&selected).filter(|v| **v != 0)
        .ok_or_else(|| WebError(StatusCode::GONE, "previous download or challenge expired; retry from the page".into()))?;
    let counter = state.counts.lock().unwrap().entry(selected).or_default().clone();
    counter.fetch_add(1, Ordering::SeqCst);
    let flight = Flight(counter);
    let ip = request.extensions().get::<security::ResolvedClientIp>()
        .ok_or_else(|| WebError(StatusCode::INTERNAL_SERVER_ERROR, "client identity missing".into()))?.0;
    let target = format!("http://127.0.0.1:{port}{}", request.uri().path_and_query().map_or("/", |v| v.as_str()));
    let (parts, body) = request.into_parts();
    let mut headers = parts.headers;
    clean_headers(&mut headers);
    headers.insert("x-ggfm-client-ip", ip.to_string().parse().map_err(internal)?);
    headers.insert("x-ggfm-gateway-key", state.key.parse().map_err(internal)?);
    let response = state.client.request(parts.method, target).headers(headers)
        .body(reqwest::Body::wrap_stream(body.into_data_stream())).send().await.map_err(internal)?;
    let status = response.status();
    let mut headers = response.headers().clone();
    clean_headers(&mut headers);
    let stream = response.bytes_stream().map(move |chunk| { let _hold = &flight; chunk });
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

pub async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let config: Config = serde_json::from_slice(&fs::read(std::env::var_os("GGFM_PATCHER_CONFIG").ok_or("gateway config missing")?)?)?;
    let routes = PathBuf::from(std::env::var_os("GGFM_GATEWAY_ROUTES").ok_or("gateway routes missing")?);
    let stats = routes.with_extension("stats.json");
    let key = std::env::var("GGFM_GATEWAY_KEY")?;
    if key.len() != 64 { return Err("invalid gateway key".into()); }
    let security = security::Security::new(config.security.clone())?;
    let address: SocketAddr = config.listen.parse()?;
    security.validate_listen(address)?;
    let state = Gateway { routes, key, counts: Arc::new(StdMutex::new(BTreeMap::new())),
        client: reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3)).timeout(Duration::from_secs(3600)).build()? };
    let counts = state.counts.clone();
    tokio::spawn(async move {
        loop {
            let snapshot: BTreeMap<u32, usize> = counts.lock().unwrap().iter().map(|(k,v)| (*k, v.load(Ordering::SeqCst))).collect();
            let temporary = stats.with_extension("new");
            if let Ok(bytes) = serde_json::to_vec(&snapshot) {
                if tokio::fs::write(&temporary, bytes).await.is_ok() { let _ = tokio::fs::rename(&temporary, &stats).await; }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let app = Router::new().fallback(forward).with_state(state)
        .layer(axum::middleware::from_fn_with_state(security, security::protect));
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "stable blue/green gateway ready");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(super::shutdown_signal()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lock_child() {
        if let Ok(marker) = std::env::var("GGFM_TEST_LOCK_MARKER") {
            let _lock = build_lock().unwrap();
            fs::write(marker, b"acquired").unwrap();
        }
    }
    #[test]
    fn heavy_build_lock_serializes_separate_processes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("build.lock");
        let marker = dir.path().join("acquired");
        let file = fs::OpenOptions::new().create(true).truncate(false).read(true).write(true).open(&path).unwrap();
        file.lock().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "gateway::tests::lock_child"])
            .env("GGFM_BUILD_LOCK", &path).env("GGFM_TEST_LOCK_MARKER", &marker).spawn().unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let premature = marker.exists();
        drop(file);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if child.try_wait().unwrap().is_none() { child.kill().unwrap(); }
        assert!(child.wait().unwrap().success());
        assert!(!premature);
        assert_eq!(fs::read(marker).unwrap(), b"acquired");
    }
    #[test]
    fn generation_token_is_not_a_url_or_upstream_selector() {
        assert_eq!(token_revision("g42.ABCD"), Some(42));
        assert_eq!(untag_token("g42.ABCD"), "ABCD");
        assert_eq!(token_revision("http://evil.invalid"), None);
        assert_eq!(untag_token("LEGACY"), "LEGACY");
    }
    #[test]
    fn hop_headers_and_injected_identity_are_removed() {
        let mut h = HeaderMap::new();
        h.insert("connection", "upgrade, x-remove".parse().unwrap());
        h.insert("x-remove", "bad".parse().unwrap());
        h.insert("x-ggfm-client-ip", "bad".parse().unwrap());
        h.insert("host", "example.org".parse().unwrap());
        clean_headers(&mut h);
        assert_eq!(h.len(), 1);
        assert!(h.contains_key("host"));
    }
}
