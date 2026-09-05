# Deployment and release contract

## Patch reference

The release checkout must expose the Patch repository at `patch/` and pin a
full Git commit. Clone the release with:

```text
git clone --recurse-submodules https://github.com/guitar-girl-resuscitation/guitar-girl-memorial-patcher
cd guitar-girl-memorial-patcher
git submodule update --init --checkout
```

Production configuration must match that exact clean Patch checkout and never
use the all-zero development sentinel. Download Server and Patch artifacts as a
matched pair: the native Patch is built against the Server SHA and both embed
the same policy fingerprint. The runtime library is shipped as `libggfm_server.so`.

## Modes

Full upload mode hashes in the browser, streams at most 768 MiB, verifies the
complete XAPK again on the server, and builds in a request-scoped temporary
directory. The temporary upload and intermediates are removed when the worker
finishes, even if the browser disconnected. Exactly one heavy worker may run;
new uploads receive HTTP 503 while it is busy. Uploads time out after ten
minutes total or thirty seconds without a chunk.

Prebuilt mode is opt-in. The operator source remains outside the repository.
The browser must first match the public full-file hash, then answer a fresh,
single-use challenge containing eight random 64 KiB ranges. A successful proof
grants a ten-minute, one-use download token for an operator-verified cached
output. At startup, the server validates the operator source and builds or
verifies the cached output before enabling this mode. No valid operator file
means automatic full-upload mode, not a broken prebuilt button. The browser
selects the mode using `/healthz`; there is only one action button.

Do not expose cache, work, source or signing directories through a static web
server. Cached XAPKs contain game resources and must never become Release
assets or Git files. Prebuilt mode is an explicit operator opt-in; a chunk
challenge is a possession check, not proof of copyright permission.

Original/operator files and prepared results are immutable while running.
Replacing them requires restarting the patcher for full validation. Per-user
proof reads only challenged ranges, never rebuilds or hashes the entire output.
The cache identity includes the source SHA, exact Patch commit, Server SHA/ABI,
policy and bootstrap hashes, application ID, signer fingerprint, revision,
compatibility manifest, apktool and patcher executable. Changing a moving
Nightly label cannot accidentally reuse an older build.

## Limits and secrets

## Starting a deployment

1. Keep the `patch/` checkout at its pinned commit. Obtain its compiled runtime
   archive and read `dependencies.json` for the exact Server artifact/commit.
   Verify SHA-256 values; do not mix independently downloaded moving Nightlies.
2. Install Java 21, Android SDK platform/build-tools 35.0.0, a compatible apktool
   JAR, and Python 3.11. Install `patch/tools/requirements.lock.txt` into a private
   Python environment; no game resources are installed by these requirements.
3. Copy `config/patcher.example.json` outside the repository and replace every
   placeholder. Set absolute tool/runtime paths, the exact Patch commit, the
   matching hashes, the signing certificate fingerprint and an application-ID
   suffix for self-hosted signing. Keep the keystore outside the web root.
4. Set `GGFM_PATCHER_CONFIG` to that configuration and the two password
   environment variables named by it. Set `RUST_LOG=info` for diagnostic logs,
   then run `ggfm-patcher-web`. A bad dependency fails before the port opens.
5. Place an optional verified original at `prebuilt.operatorSourceXapk` and
   restart. Otherwise omit `prebuilt` or leave that path absent. Neither the
   source nor a prepatched XAPK is supplied by this project.

The service listens on loopback by default. Put a TLS reverse proxy in front
of it with a 768 MiB upload ceiling, streaming requests, suitable build timeouts,
and per-client request limits. Use a dedicated nonprivileged worker account
and a filesystem/container disk quota. Cache and temporary directories are
private; manage old deployment caches explicitly, never expose them as static
downloads. One process per deployment is required for the single-worker limit.

## Upstream updates

`Update verified Patch release` checks every six hours and can be run manually.
It accepts only a published Patch runtime whose digest and source commit match
the upstream Release, updates the gitlink and `config/upstream-patch.json`, runs
tests/content guards, then commits only those two pins. It explicitly dispatches
the build workflow after the bot push. A failed check cannot update main.

This updates source/build references, not a running deployment or its signing
key. Operators deliberately deploy a matched new runtime pair. No APK is ever
uploaded to GitHub by either workflow.

## Quotas

- archive entries: 64
- expanded XAPK: 1.5 GiB
- request workspace: 6 GiB
- each external tool: 15 minutes
- heavy workers: 1

Keystore passwords are read only from configured environment variables. The
official signing key belongs in deployment secrets or an HSM. A self-hosted
deployment without that key must use an application-id suffix and its own
certificate.

## Device smoke test

The patch pipeline itself is deterministic and never silently selects a phone.
Installation is an explicit release-gate action requiring a serial:

```text
python tools/smoke-test-android.py output.xapk --serial emulator-5554
```

The script installs all splits together, verifies the memorial package path,
launches it, and checks that the process remains alive. It does not uninstall
the official game or erase application data.
