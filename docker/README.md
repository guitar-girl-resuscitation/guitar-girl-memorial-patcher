# Docker deployment — Guitar Girl Memorial Patcher

English · [简体中文](README.zh-CN.md)

This release is a **Docker build context**, not a preloaded image or game package.
It includes a Dockerfile, compiled Patcher and a matching embedded Server/Patch
runtime. The image build fetches a pinned Patch source commit and hash-verified
Android tools. No original XAPK, generated game or signing key is included.

## Build and start (Linux amd64)

Download `ggfm-patcher-docker-linux-amd64.zip` and its `.sha256` file from the same
Release. Verify the checksum, extract to a new directory and run there:

```sh
sha256sum -c ggfm-patcher-docker-linux-amd64.zip.sha256
unzip ggfm-patcher-docker-linux-amd64.zip -d ggfm-docker
cd ggfm-docker
docker build --platform linux/amd64 -t ggfm-patcher:local .
mkdir -p data input
sudo chown 10001:10001 data
docker run -d --name ggfm-patcher --restart unless-stopped \
  --cpus 2 --memory 4g --pids-limit 160 \
  --security-opt no-new-privileges --cap-drop ALL \
  -p 127.0.0.1:8088:8080 \
  -e GGFM_PUBLIC_ORIGIN=https://patch.example.org \
  --mount type=bind,source="$(pwd)/data",target=/data \
  --mount type=bind,source="$(pwd)/input",target=/input,readonly \
  ggfm-patcher:local
docker logs -f ggfm-patcher
```

Replace the public HTTPS origin (no trailing slash). Build requires Internet
access to Ubuntu packages, GitHub, Google's Android tools and Python packages.
The runtime is Linux amd64 only. Review the licenses for these dependencies.

Wait for `READY: port 8080`. Only one instance may use a data directory.
The service uses UID/GID 10001. A named volume such as `-v ggfm-data:/data` can
replace the data bind mount and does not need the host chown step.

| Mount | Mode | Purpose |
| --- | --- | --- |
| `/data` | Read/write, persistent | Signing key/password, package identity, work and output cache |
| `/input` | Read-only, optional | Operator-provided `original.xapk` |

Reserve at least 12 GB on the data filesystem and enforce a disk quota for
public deployments. This volume contains packaging state, not players' saves.

## Optional one-time preparation

Place your supported original XAPK at `input/original.xapk` **before starting**
the container. Ensure UID 10001 can read it. Its SHA-256 must be:

```text
E395AD8A0BF09EA9425D7751388D61C31E9B63411640A716432AC97940BB9FAC
```

A valid original enables startup preparation once per build identity. Visitors
prove possession of their own original via local hash and fresh random chunks,
then download the cached output. They do not trigger another heavy build.
Restarting the same release reuses validated output.

If the file is absent or invalid, the site runs in complete-upload mode:
visitors must upload a matching full XAPK and one worker processes it. Invalid
operator input is logged; it never grants access to an unverified cached build.
The health check accepts either working mode.

Do not modify input/cache files while serving. Restart after a deliberate
source change. Possession checks are not proof of distribution rights.

## Your existing nginx / Cloudflare

The container contains no nginx. The host port is deliberately loopback-only.
Use Cloudflare Tunnel to the local port, or your own host nginx behind
Cloudflare. In the latter case, restrict nginx ingress to Cloudflare (firewall
allowlist or authenticated origin), otherwise visitors can forge the trusted
`CF-Connecting-IP` header and evade per-IP controls. Do not expose port 8088
directly to the Internet.

Inside your existing HTTPS `server {}`:

```nginx
location / {
    proxy_pass http://127.0.0.1:8088;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;
    proxy_set_header X-Forwarded-For "";
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_cache off;
    proxy_next_upstream off;
    client_max_body_size 768m;
    proxy_read_timeout 1800s;
    proxy_send_timeout 30s;
}
```

Bypass Cloudflare caching for this hostname. API/download tokens must not be
cached. Built-in limits and failure bans remain active; bans are process-local.
Cloudflare body-size/time limits still apply: nginx settings and Tunnel cannot
override them. Prefer prebuilt mode for this large XAPK on lower-tier plans.
No chunked full-upload or asynchronous build API is currently provided.

## Updates and persistence

A new release embeds a new Android revision automatically; there is no
`revision: 1` to edit. See [VERSIONING.md](VERSIONING.md). Rebuild the new release's
Docker context, then replace the container while mounting **the same data
directory/volume** and keeping the same public origin and application ID.

Never delete `data/signing`, regenerate its key, or use `docker compose down -v`
as an upgrade step. Loss of the key prevents seamless Android updates.
The default package ID is derived from the persistent signing certificate;
`GGFM_APPLICATION_ID` optionally chooses a memorial self-hosted suffix on first
startup. Changing an established signing identity/package ID is rejected.

An updated runtime/version creates a new cached output, but does not change
already installed games. Players download and install the new splits together.
Do not distribute private caches or bake mounted game input into public images.
