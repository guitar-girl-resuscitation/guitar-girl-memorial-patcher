# Public deployment: Cloudflare only

Supported topology:

```text
Browser -> Cloudflare HTTPS / WAF -> Cloudflare Tunnel
        -> cloudflared on the same host -> 127.0.0.1:8080 (Rust)
```

No public origin port, second CDN, direct-origin fallback, nginx, or OS
Fail2ban daemon is required. The application implements failure-to-ban itself.
This is single-process deployment tooling, not a distributed abuse service or
a guarantee against DDoS. No Cloudflare account is configured by installing it.

## Host and tunnel setup

### Alternative: Cloudflare -> Nginx on another LAN host -> Patcher

Explicitly enable `security.allowLanProxy: true`, set `listen` to
`0.0.0.0:19078` (or the Patcher's private address), and keep `publicOrigin`
as a plain HTTPS origin, `requireTrustedProxy: true` and
`clientIpHeader: "cf-connecting-ip"`. `trustedProxies` must contain the
Nginx socket peer's exact private IP (`/32` for IPv4 or `/128` for IPv6),
plus `127.0.0.1/32` and `::1/128` for supervisor health checks. Subnet-wide
trust and public proxy IPs are rejected in this mode. The default remains
loopback-only; the following Tunnel instructions describe that default.

Restrict the Patcher port at the firewall to that Nginx host. On the Nginx
public ingress, only accept Cloudflare traffic (or use an authenticated
Tunnel). Pass `Host` and the original `CF-Connecting-IP` header through;
never substitute Nginx's own address for the visitor IP. Without this ingress
restriction a visitor could forge Cloudflare headers. Patcher peer checks
cannot authenticate Cloudflare on behalf of an exposed Nginx.

The managed supervisor now inherits `listen`, `trustedProxies`,
`clientIpHeader`, `requireTrustedProxy`, and `allowLanProxy` from the primary
config on restart. Do not edit generation snapshots. Origin, signing identity,
runtime artifact paths and Android version counters remain unchanged.
Wildcard health checks use loopback and ignore HTTP proxy environment variables.
LAN deployments reject old update workers lacking LAN capability before
stopping the active worker.

1. Complete [DEPLOYMENT.md](DEPLOYMENT.md): pinned Patch checkout, matched Server
   artifacts, signing setup and private work/cache directories are still required.
2. Run one Patcher process as an unprivileged dedicated user. Review
   `deploy/ggfm-patcher.service` for Linux paths and cgroup limits. Provision its
   user and directories before installing the unit. Give work/cache a disk quota;
   a memory limit is not a disk limit. Keep keys/configuration read-only to the
   service except where the signing tools require reads. No game data belongs
   in a repository, Release or publicly mounted directory.
3. Create a named Cloudflare Tunnel for a dedicated hostname. Install the
   official `cloudflared` connector and adapt `deploy/cloudflared.yml`. Keep its
   credentials outside this checkout, readable only by its service account.
   Follow [Cloudflare's tunnel setup](https://developers.cloudflare.com/tunnel/advanced/local-management/create-local-tunnel/).
4. Set `security.publicOrigin` to the exact HTTPS origin without a trailing slash,
   `requireTrustedProxy=true`, `clientIpHeader=cf-connecting-ip`, and trust only
   `127.0.0.1/32` and/or `::1/128`. The supplied example uses these values. The
   Patcher rejects non-loopback listeners and incompatible public configurations.
   Do not publish a Docker port to all interfaces. Run the connector in the same
   host/network namespace; separate-network-container recipes are not supported.
5. Validate without starting a tunnel:
   `cloudflared tunnel --config /etc/cloudflared/ggfm.yml ingress validate`.
   Check hostname routing with the corresponding `ingress rule` command.
   The final catch-all must return 404. See the
   [configuration reference](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/).
6. Configure DNS to the tunnel and enable HTTPS-only access at Cloudflare. Keep
   external ingress closed; permit the connector's required outbound traffic.
   Do not switch to DNS-only to make a failed upload work. Never expose port 8080,
   connector metrics, signing directories or the prepared-cache directory.

The trust boundary is the local connector, not a visitor-supplied header.
Untrusted peers cannot supply identity; missing, duplicated or invalid client-IP
headers from a trusted peer fail closed. The application does not parse an XFF
chain. Disable Pseudo IPv4 **Overwrite Headers**, do not remove visitor IP headers,
and do not put untrusted Workers on this hostname. Local processes able to call
the trusted loopback service are inside this boundary; isolate the host from
untrusted tenants. [Cloudflare header semantics](https://developers.cloudflare.com/fundamentals/reference/http-headers/)
describe Workers and header-transform caveats.

## Cloudflare dashboard rules

Apply to the dedicated Patcher hostname, not unrelated sites in the zone:

- Force HTTPS. Enable the managed security/WAF rules available on your plan.
- Add a **Bypass cache** rule for the entire hostname. Never enable Cache
  Everything or an Edge TTL override here. All responses also carry `no-store`,
  including errors and single-use download responses. The operator's private
  prepared cache avoids rebuilds; it is not a public CDN cache.
- Add an edge rate-limit rule using visitor IP, for example 60 requests/minute
  per IP for `/api/*`, with a temporary block. Cap expensive upload starts more
  tightly if your plan supports multiple rules. Actual rule availability and
  counting periods depend on the Cloudflare plan; application limits below
  remain active independently. Shared NAT users share a budget; tune from logs.
- Do not inject an interactive challenge page into binary download/proof/API
  responses: use rate-limit/block actions there. A challenge on the HTML entry
  page is acceptable. No Turnstile integration is currently implemented.
- Do not log complete `/api/v1/download/<token>` paths, request bodies, cookies
  or query strings to Logpush, Workers, analytics or access-log sinks. Restrict
  access and retention for unavoidable Cloudflare security-event records. The
  connector template uses fatal-only logs to avoid per-request URL diagnostics;
  use its loopback metrics and the sanitized Patcher logs for routine health.

## Application controls (defaults)

| Budget | Default |
| --- | --- |
| All requests per visitor | 60/minute |
| API control requests | 20/minute |
| Full uploads | 2/10 minutes |
| Downloads | 4/10 minutes |
| Active responses | 32 total, 4 per visitor |
| Heavy build workers | 1, no waiting queue |
| Tracked visitor addresses | 8192 maximum |
| Abuse threshold | 8 qualifying failures within 10 minutes |
| Temporary ban | 15 minutes, HTTP 429 + Retry-After |
| Upload | 768 MiB, 10 minutes total, 30 seconds idle |
| Non-upload handler / response stream | 15 seconds / 30 minutes |

Rates use refillable token buckets, so a short burst up to the stated budget is
allowed. Concurrency permits remain held until the response body is released;
a disconnected build retains its single worker slot until work exits. Tables
are bounded and expire idle entries. Capacity exhaustion returns 503, not an
unbounded queue. Limits and bans are in-memory and reset on process restart;
there is no persistent/distributed ban store or automatic Cloudflare IP-list sync.

400/401/403/404/405/413/415/422 responses contribute to the failure budget. Busy,
expired known proof/download, timeout, rate limit and server/build failures do
not. Replaying a consumed token is rejected. Logs emit parsed visitor IP and
fixed messages (`GGFM_ABUSE`, `GGFM_BAN`); no URI, proof bytes or bearer token.
The ban is enforced against the visitor at the application, **not** against
Cloudflare's edge IP in a host firewall. An ordinary iptables Fail2ban action
would not block that visitor through a tunnel and is deliberately not shipped.

Host and browser Origin are checked against the configured HTTPS origin.
Cross-site API requests are refused. Headers disable framing, MIME sniffing and
referrer disclosure. Internal failures return a generic error to clients; full
tool diagnostics stay in private operator logs. These are layers, not substitutes
for patched host dependencies, resource quotas and safe signing-key handling.

## Large XAPK uploads: current limitation

Cloudflare Tunnel **does not remove** Cloudflare HTTP request limits. As checked
on 2026-09-06, the documented upload limits are Free/Pro 100 MB, Business 200 MB,
and Enterprise up to 5 GB (zone settings can be lower).
[Cloudflare upload limits](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-413/)
apply before our 768 MiB limit. Builds also use a synchronous HTTP response;
Cloudflare's default proxy read timeout is 120 seconds, with eligible Enterprise
configuration required for a longer response deadline.
[Cloudflare timeout limits](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/error-524/)
also include write deadlines. Raising only the Rust timeout does not help.

For a normal Cloudflare deployment, use **operator-prebuilt mode**: validate and
build the authorized source once before listening, then visitors upload only
small possession proofs and receive a protected streaming download. The browser
still checks its local file hash first. Deployment is opt-in; possession proof
does not establish distribution rights.

Without a valid operator source, the application still falls back to full upload.
That mode requires a Cloudflare plan/configuration permitting the *entire* XAPK
and the measured end-to-end build duration. Do not advertise it as Free-plan
compatible. Chunked/resumable uploads and asynchronous build polling are not yet
implemented. A 413/524 is an unsuccessful request, not a successful build result.

## Acceptance before exposing your hostname

1. Run `cargo test --workspace --locked -j2`, `node tools/test-browser-sha256.mjs`
   and `python tools/test_deployment.py`. CI runs these checks. They do not alter
   any firewall, Cloudflare account, tunnel or production service.
2. Validate your substituted tunnel configuration and confirm the hostname's
   fallback, HTTPS policy, cache bypass and blocked direct-origin access.
3. From your own browser, verify a prepared proof/download works. A consumed
   token must not download a cached copy. Inspect response cache headers and
   Cloudflare cache status; responses must not be HIT/REVALIDATED.
4. Confirm logs identify your visitor address, not loopback/a Cloudflare edge.
   Review a controlled staging failure/ban and its expiry; don't run load or ban
   tests on a shared production IP. Check the UI's Retry-After hint.
5. If enabling full upload, test the real supported XAPK through Cloudflare,
   including tool execution time and a canceled browser. No second worker should
   start while the first build is still alive. Check filesystem/cgroup limits.
6. Audit Git history and each Release with the supplied release guards. Generated
   games, source packages, tables, dumps, private saves and signing material stay
   private. Deployment acceptance is separate from source/unit-test success.
