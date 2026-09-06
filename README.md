# Guitar Girl Memorial Patcher

English · [简体中文](README.zh-CN.md)

Architecture support and source-package limitations: [Android ABI selection](docs/ANDROID_ABI.md).

A verified CLI and single-worker web patcher for **Guitar Girl Fan Memorial Build**. It turns a supported, user-supplied original XAPK into a standalone memorial package with an embedded Rust server.

This repository and its public Releases contain tools, **not the original or patched game**.

Linux/Docker deployments can now keep a stable supervisor while automatically
updating the worker and compiled Patch/Server runtime. A preloaded original is
rebuilt before activating a new generation; signing identity and monotonic
Android versions persist. See [managed updates](docs/DEPLOYMENT.md#managed-linux--docker-runtime).

## The three repositories

| Repository | Responsibility |
| --- | --- |
| [Server](https://github.com/guitar-girl-resuscitation/guitar-girl-memorial-server) | Rust gameplay, protocol, SQLite saves and the Android server library |
| [Patch](https://github.com/guitar-girl-resuscitation/guitar-girl-memorial-patch) | Original client integration, memorial UI, identity isolation and verified transformation rules |
| [Patcher](https://github.com/guitar-girl-resuscitation/guitar-girl-memorial-patcher) | CLI/web packaging, source verification, resource extraction, signing and downloads |

At runtime, the patched Unity client talks to the embedded Rust server over authenticated loopback. The patching website is **not** a game server and does not need to stay online for play.

## For players

1. Obtain the supported original package that you are entitled to use. Current support is **8.0.0 / Android ARM64**, identified by the exact SHA-256 below.
2. Open a trusted deployment or run your own. Select your original XAPK; the browser hashes it locally.
3. In full-upload mode, upload the validated package and wait for patching. In operator-prebuilt mode, pass the fresh file-possession challenge and download the cached build without uploading the whole package.
4. Install the resulting XAPK with a compatible split-package installer. All splits belong together; installing only the base APK is insufficient.
5. Launch **Guitar Girl Fan Memorial Build**, start its local runtime, and play. Root, LSPosed and a separately hosted game server are not required.

```text
Supported original XAPK SHA-256
E395AD8A0BF09EA9425D7751388D61C31E9B63411640A716432AC97940BB9FAC
```

A filename or version label is not sufficient. Unknown hashes and mismatching splits are rejected. The supported input is defined by [Patch's compatibility manifest](patch/compatibility/8.0.0.json), not by an arbitrary package download.

Keep the same application ID and signing certificate for updates that preserve installed data. Another deployment's key/package may create a separate app or be unable to update your installation. Export saves before uninstalling; do not assume official/experimental saves are compatible.

## Packaging pipeline

```text
User XAPK
  → whole-file / split / structure verification
  → private extraction and master.sqlite generation
  → verified Patch transforms + precompiled Server/runtime injection
  → application ID, label and split metadata rewrite
  → zipalign + one certificate for every split
  → final XAPK verification and download
```

The Rust workspace separates `patcher-core`, the CLI and the web host. `patch/` is a pinned Git submodule, not a copied fork of Patch. Server artifacts are selected by ABI and SHA-256 and are not compiled per visitor.

Checks cover archive traversal/size limits, relevant binary/data fingerprints, transformation preconditions, package identity, policy agreement and split certificates. A failed precondition stops the build.

## Build and basic CLI use

Use Git with submodules, the CI-pinned Rust toolchain (currently 1.96.0), Python 3.11+ and Node.js for browser hashing tests.

```sh
git clone --recurse-submodules https://github.com/guitar-girl-resuscitation/guitar-girl-memorial-patcher
cd guitar-girl-memorial-patcher
git submodule update --init --checkout
cargo test --workspace --locked -j2
cargo build --workspace --locked --release -j2
node tools/test-browser-sha256.mjs
python tools/test_deployment.py
```

Linux examples; Windows binaries have an `.exe` suffix:

```sh
./target/release/ggfm-patcher hash /private/original.xapk
./target/release/ggfm-patcher verify /private/original.xapk patch/compatibility/8.0.0.json
./target/release/ggfm-patcher plan --help
./target/release/ggfm-patcher patch --help
```

`hash` prints the digest, `verify` checks compatibility, `plan` records a versioned build plan, and `patch` runs the real transformation. The patch command requires explicit runtime/tool paths, hashes and signing configuration; it never silently uses an attached phone.

## Run the web service

### Recommended: Docker release with mounted directories

Download and checksum-verify `ggfm-patcher-docker-linux-amd64.zip` from
[Releases](https://github.com/guitar-girl-resuscitation/guitar-girl-memorial-patcher/releases).
Extract it to a new directory and run there (replace the public HTTPS origin):

```sh
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

`data/` persists the signing identity, cache and work files: keep it across
upgrades. Optionally place a supported `original.xapk` in `input/` before
starting; it is mounted read-only and prepared once. Without a valid original,
the site accepts complete verified uploads instead. Wait for `READY`.

The image contains no game, and requires no host Java/Android/Python setup.
The Docker build needs network access to fetch its pinned source/tools. Attach
your external nginx or Cloudflare Tunnel to port 8088; never expose this trusted
proxy entry directly to the Internet. See the [Docker deployment guide](docker/README.md)
for nginx/Cloudflare restrictions, permissions, disk space and updates.

### Native/manual deployment

Read [deployment setup](docs/DEPLOYMENT.md) and [public hosting requirements](docs/PUBLIC_DEPLOYMENT.md) before publishing a service.

1. Obtain the compiled Patch runtime for the exact clean `patch/` commit. Read its `dependencies.json` and obtain the **matching** Server artifact. Verify every digest and ABI; never mix independently moving Nightlies.
2. Install Java 21, Android platform/build-tools 35.0.0, a compatible apktool JAR and a private Python environment with `patch/tools/requirements.lock.txt`.
3. Create a private signing keystore outside the repository/web root. Self-hosters use their own application-ID suffix and certificate. Preserve that key across upgrades.
4. Copy [config/patcher.example.json](config/patcher.example.json) to a private location. Replace **all** placeholder paths, hashes, versions, signer fingerprint and public origin. The example's Windows paths must be changed on Linux.
5. Supply the password environment variables named in the config using your service's secret mechanism. Never put passwords into Git or a public command transcript.
6. Start the service:

```sh
export GGFM_PATCHER_CONFIG=/srv/ggfm/private/patcher.json
export RUST_LOG=info
# Inject GGFM_KEYSTORE_PASSWORD and GGFM_KEY_PASSWORD securely.
./target/release/ggfm-patcher-web
```

The service validates dependencies before opening its loopback listener. Use one process and one heavy worker. Releases provide a native CLI/web archive and a resource-free Docker build context; neither contains the game.

### Two deployment modes

| Mode | Operator provides | Visitor provides | Heavy work |
| --- | --- | --- | --- |
| Full upload | Tools, runtime and signer only | Entire matching original XAPK | Once per accepted upload |
| Operator-prebuilt | Also a private matching original XAPK | Local hash and fresh random file chunks | Once per validated build identity; cached afterward |

Set `prebuilt.operatorSourceXapk` to a private original file to opt into prebuilt mode. The service validates it and prepares/verifies the output at startup. Without a usable operator source it falls back to full uploads.

The possession challenge uses eight random 64 KiB ranges, expires after three minutes and is single-use. The resulting download token lasts ten minutes and is single-use. Reporting a known public hash alone is not enough.

Cache identity includes source, exact Patch/Server versions and hashes, policy, application ID, signer and relevant tooling. Source/cache files must remain immutable while serving; replace them through a deliberate deployment restart. Never expose source, work, cache or signing directories as static files. Cached output contains game assets and must not be uploaded to GitHub.

### Public ingress, limits and failure bans

The native public configuration uses a **local Cloudflare Tunnel** connector. The Docker guide additionally covers host nginx behind Cloudflare. Visitor identity is trusted only through the configured proxy boundary. Keep the origin inaccessible directly and follow the deployment document's origin/cache checks.

- Per-IP request/API/upload/download limits and global/per-IP in-flight limits.
- Eight qualifying failures within ten minutes trigger a fifteen-minute in-process ban. This is not an OS Fail2ban daemon or a Cloudflare account firewall rule; restarting resets this in-memory state.
- API/download responses are non-cacheable. Configure Cloudflare cache bypass for the deployment hostname; do not use Cache Everything.
- One heavy worker; a busy worker rejects new uploads with HTTP 503.
- Upload: 768 MiB maximum, ten-minute total timeout, thirty-second idle timeout.
- Archive: 64 entries, 1.5 GiB expanded; per-request work quota 6 GiB; external tool timeout fifteen minutes.

Cloudflare's own upload/body and proxy timeout limits still apply; Tunnel does not bypass them. The supported XAPK exceeds common lower-tier upload limits, so prefer operator-prebuilt mode there. Full uploads need a plan/path that actually accommodates the file and processing time. Chunked upload and asynchronous job submission are not implemented. See the public deployment document before choosing full-upload mode.

A chunk challenge checks possession, not copyright permission. Operators must separately consider whether they may distribute the resulting package.

## Releases and upstream updates

Android versions come from the release build: workflow run N produces
`versionCode = 800000 + N` and `8.0.0-memorial.N`. New runs increase the version;
re-runs and repeated downloads retain it. Omit `versions.revision` in deployment
config (remove an old fixed `1`); mismatching overrides fail closed. Inspect
`ggfm-patcher version`, `/healthz` or the release manifest for the actual version.
Keep the same package ID and signing key for in-place Android updates. See
[versioning and local builds](docs/VERSIONING.md). This is not an in-game auto-updater.

[Releases](https://github.com/guitar-girl-resuscitation/guitar-girl-memorial-patcher/releases) provide `ggfm-patcher-linux-x64.zip` and its SHA-256 file. Successful main builds replace the single Nightly; version tags create versioned releases. Archives contain packaging tools, not game packages or private keys.

The upstream-update workflow runs every six hours or manually. It verifies a published Patch release, updates only the pinned gitlink and dependency record, tests the change, then dispatches a new build. It does **not** update a running deployment, replace a signing key or install anything on a player's phone. Operators deploy matched versions deliberately.

## Testing and troubleshooting

- Hash/manifest failure: check the original input; do not disable guards.
- ABI/policy failure: use the exact runtime pair recorded by Patch.
- HTTP 503: wait for the single worker; do not start duplicate processes to evade its memory bound.
- HTTP 413 or proxy timeout: check Cloudflare limits and use prebuilt mode where appropriate.
- Installation conflict: check package ID and certificate; do not erase saves as a first troubleshooting step.

For an explicitly selected test device, `python tools/smoke-test-android.py output.xapk --serial YOUR_ADB_SERIAL` installs all splits and checks process survival. It does not replace full gameplay acceptance testing.

## Scope, contributions and licensing

This is an unofficial fan memorial/interoperability project, not an official service or an endorsement by the original developers or publisher. It does not recover official accounts, cloud saves, payments or retired online services. Some historical server-only values are memorial compatibility choices, not a claim of complete original-server fidelity.

Project code is licensed under [AGPL-3.0-or-later](LICENSE); third-party components retain their own licenses. This does not license the original game. Supply only an original package you are entitled to use.

Do not submit APK/XAPK files, AssetBundles, original DEX/IL2CPP binaries, full decompiler exports, captured proprietary master tables, private saves or signing secrets. Report bugs with the component version/commit, chapter, reproducible steps and redacted diagnostic logs. For behavior changes, add a contract/regression test and keep both README languages in sync.

## Web language

The Patcher website supports English and Simplified Chinese, automatically
selects a language from the browser, and remembers the language selector choice
when browser storage is available. Other browser languages fall back to English.
Raw server diagnostic messages remain English. Changing language does not
restart verification or invalidate a ready download link.

The homepage also displays the active Server, Patch and Patcher source commits
and source update dates (UTC). These describe the deployed configuration and
compiled worker, not GitHub's moving latest release. Dates missing from older
artifacts are shown as “Not recorded”; pinned metadata is used only for matching
full commits. Server/Patch content may change independently of the worker.
