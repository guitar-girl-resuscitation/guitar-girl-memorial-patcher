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

Each current web deployment serves one profile. It does not yet merge two
originals into a universal XAPK or select multiple source profiles on one page.
Do not advertise a V8-only deployment as supporting 32-bit-only phones.

目前单个网页部署服务一个配置，不会自动合并两个原包为通用 XAPK，也没有
同页多源包选择。不要将只部署了 V8 原包的站点标为支持纯 32 位手机。
