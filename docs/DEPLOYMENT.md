# Deployment and release contract

Public deployments also require the configuration and verification checklist
in [PUBLIC_DEPLOYMENT.md](PUBLIC_DEPLOYMENT.md). The example now assumes a local
Cloudflare Tunnel connector and `https://patch.example.org`; replace that origin. For
loopback-only development, omit `security` to use the safe direct-peer defaults.

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

The service listens only on loopback. Public ingress is Cloudflare Tunnel only;
follow PUBLIC_DEPLOYMENT.md for cache rules, visitor identity and the important
Cloudflare full-upload size/timeout restrictions. Use a dedicated nonprivileged worker account
and a filesystem/container disk quota. Cache and temporary directories are
private; manage old deployment caches explicitly, never expose them as static
downloads. One process per deployment is required for the single-worker limit.

## Upstream updates

Android build numbering is automatic in compiled releases. Omit
`versions.revision` (remove the former fixed `1`) and let the embedded workflow
revision select the output version. Conflicting values fail before serving.
Preserve your application ID and keystore across updates. See
[VERSIONING.md](VERSIONING.md) for release/re-run semantics and local builds.

`Update verified Patch release` checks every six hours and can be run manually.
It accepts only a published Patch runtime whose digest and source commit match
the upstream Release, updates the gitlink and `config/upstream-patch.json`, runs
tests/content guards, then commits only those two pins. A pin-only bot push
does not rebuild the unchanged Patcher: running deployments fetch the new
verified Patch runtime independently. A failed check cannot update main.

That workflow updates source references. The independent Linux deployment
supervisor also updates running deployments; these are separate mechanisms.
No APK is ever uploaded to GitHub by either workflow.

### Managed Linux / Docker runtime

Docker starts the stable `run_managed.py` supervisor automatically. For a native
deployment, install that authored script once alongside the seeded binaries:

```sh
python3.11 /opt/ggfm/patcher/deploy/run_managed.py \
  --config /srv/ggfm/patcher.json \
  --binary /opt/ggfm/patcher/ggfm-patcher-web \
  --state /srv/ggfm/updates
```

Use the same private signing-password environment as the ordinary worker. Run
as a dedicated unprivileged Linux user; the state directory must be writable
only by that user. The included systemd unit supervises this entry point.
Keep configuration, source XAPK, signing directory, cache **and update state**
on persistent storage. Docker uses `/data/updates`; never recreate `/data` when
updating. Set Docker `--stop-timeout 3600` so an active patch job can drain.

The supervisor checks GitHub at startup and hourly. It verifies immutable asset
IDs, GitHub SHA-256, every archive member, exact source commits and Server/policy
pairing. Patch-only changes reuse the worker; worker-only changes reuse the
runtime. Native libraries are downloaded precompiled, never rebuilt per user.
Source transformation scripts use a clean, commit-specific Patch checkout.
A changed Python lock gets its own private environment. Java, Android tools,
Python and OS dependencies remain the base deployment's responsibility: an
incompatible worker API is rejected rather than silently upgrading the OS.

Each candidate reserves a monotonically increasing Android revision on disk.
The worker drains, then the candidate prebuilds the optional operator XAPK.
Only after prebuild and health checks succeed does the supervisor publish the
new generation. Failure restarts the previous generation; failed revisions
are not reused. A change of package ID, signer or origin is rejected on restart.
There is a maintenance interval during rebuild, not zero-downtime service.
The immutable generation configuration and last active pair survive restart.

To pause checks, set `GGFM_AUTO_UPDATE=0` (Docker or native), or use
`--no-updates`. The active generation still runs. No update deletes the old
signing key, original source or saves. Old generations/caches are retained:
set a filesystem quota and monitor disk usage; there is no automatic pruning.

`/api/v1/update` advertises only the running generation's version, application
ID and signer. Packages embed this deployment's validated HTTPS origin. The
client offers a browser link back to it, never silently downloads/installs or
uploads saves. A deployment version is allocated per generation, not per user
download or restart. Keep `versions.revision` unset in numbered releases;
`versions.deploymentRevision` is owned by the managed supervisor.

### 自动更新（中文）

Docker 默认使用独立入口自动检查 Patcher 与 Patch 的 GitHub 发布。
仅 Patch 更新时直接复用已编译 worker；仅 Patcher 更新时复用运行时。
新版先校验哈希与版本，再等待旧任务结束，预构建部署者原包，通过健康检查后
才启用。失败回退旧版本；期间会有维护窗口。每次有效候选分配持久化的递增
版本号，不随访客下载或进程重启增加，失败版本号也不复用。

原包、签名密钥、配置、缓存及 `/data/updates` 必须持久化，不能升级时清空。
用 `GGFM_AUTO_UPDATE=0` 可暂停更新。旧版本与缓存不会自动清理，请配置磁盘
配额并监控容量。基础系统依赖不兼容时拒绝更新，仍可能需要部署者更新基础镜像。
游戏内更新提示只返回产出此包的站点，不自动安装，也不会上传玩家存档。

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
