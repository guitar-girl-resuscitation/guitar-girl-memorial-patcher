# Android update identity / Android 更新版本

## English

The release workflow embeds `github.run_number` into both Patcher binaries as
`GGFM_BUILD_REVISION`. This counter increases for every new invocation of the
same workflow; re-runs preserve it. Gaps from failed/PR builds are fine. Do not
reset or replace the workflow's numbering without choosing a range above all
previously published Android versionCodes.

Revision N gives every base/split manifest and XAPK metadata
`versionCode = 800000 + N` and `versionName = 8.0.0-memorial.N`.
Downloads, cache reuse and service restarts never allocate new numbers.
A manual workflow dispatch is a new build; a re-run retains its original number.

For releases, omit `versions.revision` in web config (zero also means automatic).
Remove the former example's fixed `revision: 1`. Numbered binaries reject a
different explicit value. CLI `--revision` likewise defaults to automatic.
`ggfm-patcher version` prints JSON; startup logs and `/healthz.androidVersion`
show the resolved identity. The release manifest and notes record it, and
packaging validates it against the workflow counter. An obsolete same-commit
re-run cannot replace a higher-numbered Nightly.

The resolved revision participates in the deployment fingerprint and output
cache. All splits and XAPK metadata are verified after rebuilding/signing.
The versionCode cannot exceed 2100000000. Hashes and request-time clocks are
never used as Android version codes.

Unnumbered local builds can hash/verify and run tests. For actual patching or
web startup, explicitly choose a development revision or embed it when building:

```sh
GGFM_BUILD_REVISION=123 cargo build --workspace --locked --release -j2
./target/release/ggfm-patcher version
```

PowerShell: `$env:GGFM_BUILD_REVISION = '123'` before the Cargo command.
Alternatively, unnumbered binaries accept `patch --revision N` or web config
`versions.revision: N`. Use a separate test package ID and signing key: a high
development version installed over production can block subsequent updates.
Changing runtime environment variables cannot relabel a numbered binary.

To update installed games, preserve package ID and signing key and install all
splits together. A higher versionCode permits a normal update without an
uninstall/data wipe; database compatibility remains Server's responsibility.
Patch deliberately keeps the legacy managed version at `8.0.0`: the original
client parses it numerically after removing dots. Android's human-readable
memorial suffix must not reach that compatibility surface.

This is versioning, not an in-game automatic updater. Players still install a
new package. Operators deliberately deploy a matched Patch/Server/runtime set.

## 简体中文

发布 workflow 将 `github.run_number` 编入两个 Patcher 可执行文件。每次新运行
递增；重跑同一次运行保持原编号，失败/PR 导致跳号不影响更新。以后若重建或
重置 workflow 编号，必须选择高于全部已发布 Android versionCode 的新编号区间。

第 N 次构建给全部 base/split 和 XAPK 元数据统一写入 `800000 + N` 版本码，
显示版本为 `8.0.0-memorial.N`。下载、缓存复用和服务重启不生成新编号；手动
触发 workflow 是新构建，重跑已有 workflow 则不是。

发布版省略配置中的 `versions.revision`（0 也表示自动），删除旧示例固定的 1。
显式值若与编译版本不一致，启动/打包直接报错；CLI 同样默认自动。
`ggfm-patcher version`、启动日志、`/healthz` 的 `androidVersion` 字段，以及
Release 清单/说明均能查看版本。发布前校验编号与流水线一致，旧运行即便指向
相同提交，也不能覆盖版本更高的 Nightly。

有效编号参与缓存身份，最终验证所有 split 和 XAPK 版本一致。版本码限制在
2100000000 以内，不使用下载时的时间或哈希作为 Android 版本码。

未编号的本地构建可以测试、计算哈希和验证原包；实际打包/开服需显式指定开发
编号，或像上方命令一样在编译时设置 `GGFM_BUILD_REVISION`。开发测试应使用
独立包名和签名，避免过高测试版本阻止正式更新。运行时改环境变量不能改变
已编号二进制的版本。

覆盖安装要保留包名、签名，并同时安装全部 split；不需要先卸载或清数据。
数据库兼容由 Server 单独负责。游戏内部的兼容版本仍为 `8.0.0`，不让带后缀
的 Android 显示版本进入原客户端的整数解析逻辑。

这不是游戏内自动更新功能：玩家仍要安装新包，部署者仍需主动更新匹配组件。
