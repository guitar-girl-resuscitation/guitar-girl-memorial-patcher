# Android ABI selection / Android 架构选择

The pipeline supports ARM64 (`arm64-v8a`) and ARMv7 (`armeabi-v7a`) through
separate source profiles. The approved ARM64 APKPure source contains no V7
game library. The current V7 profile is an experimental private integration
container, not an allowlist for arbitrary V7 XAPK downloads.

当前流程通过独立源包配置支持 ARM64 和 ARMv7。原 ARM64 APKPure 包没有
V7 游戏库，不能直接转成 V7。V7 配置目前对应已校验原始 split 组成的私有
测试容器，并不代表任意 V7 XAPK 都可上传通过。

| Source ABI | Patch profile | Managed runtime asset |
| --- | --- | --- |
| arm64-v8a | compatibility/8.0.0.json | ggfm-patch-android-arm64.zip |
| armeabi-v7a | compatibility/8.0.0-armv7.json | ggfm-patch-android-armv7.zip |

The deployment's `compatibilityManifest` selects the ABI. The supervisor reads
`source.abi` from that file before selecting an update. Both the Patch and the
embedded Server dependency must match. Historical profiles without `source.abi`
remain ARM64; unknown ABIs fail closed. Do not change this setting alone while
leaving an incompatible operator source or native runtime configured.

部署用 `compatibilityManifest` 指定源包配置。更新器按其 `source.abi` 选择
正确产物，同时校验 Patch 与内嵌 Server 的架构；旧配置省略该字段仍视为
ARM64，未知架构拒绝更新。不能只改此字段而继续使用不匹配的原包或运行库。

Update metadata contains `androidAbi`. Clients check the device's supported
ABIs before offering the package. Signing identity and version checks still
apply. This does not change the package name, key, version counter or saves.

更新元数据包含 `androidAbi`，客户端只提示设备可运行的架构，且仍校验签名、
包名和递增版本。此改动不更换包名、密钥或存档。

## Optional universal ARM output / 可选双架构输出

The approved ARM64 source plus the verified original ARMv7 native split can
produce one XAPK containing a shared base/assets and both ABI splits. The CLI
accepts `--additional-native` (a JSON file matching `NativeSupplement`); web
configuration uses `artifacts.additionalNative`. All original and runtime hashes,
ELF ABIs and policy fingerprints are checked. Native entries are stored without
compression and aligned before signing with the existing deployment certificate.

Managed deployments can add `native-armv7.json` next to their operator config:
`{"schema":1,"splitFile":"input/config.armeabi_v7a.original.apk","sha256":"49848F553811A72379385A90CCC7CB3BBB0622FD39D13AAA757C1319071C69E6"}`.
The file is relative to that private directory and cannot escape it. Supply the
original split privately; this repository/releases do not contain it. Restart
the supervisor with auto-updates enabled. It fetches a universal-capable worker
and both runtime archives, requires matching Patch/Server commits, DEX and policy,
then prebuilds a new immutable generation. Failure retains the previous generation.
It does not rewrite the operator config, key, package name or version history.

现有 V8 原包无需替换。差量覆盖包在 `private/` 添加上述描述及已校验的 V7 原始
split，并更新 `worker/deploy/run_managed.py`。解压到原部署根目录后重启进程即可，
不需要重新 setup 或修改域名、代理、签名配置。自动更新必须开启；首次合包完成前
旧成品仍可能是 V8。`/healthz` 和 `/api/v1/update` 的 `androidAbis` 同时包含
`arm64-v8a`、`armeabi-v7a` 时才说明当前激活代支持双架构。后续自动更新保留双架构。
没有补充 V7 输入时仍只生成原配置架构，不应宣称支持纯 32 位手机。

Updated clients consume `androidAbis`; legacy `androidAbi` remains the primary ABI
for older clients. Installing the appropriate ABI split is the XAPK installer's
job. A single XAPK does not mean both native architectures run in one process.
