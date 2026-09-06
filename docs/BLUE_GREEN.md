# Continuous ingress / 持续服务更新

The managed supervisor can keep a stable Rust HTTP gateway on the configured
public/LAN listener while worker generations bind private random loopback ports.
The gateway is the same `ggfm-patcher-web` executable in `--gateway` mode; no
additional Python packages, nginx modules or public ports are required.

For existing panel deployments, the incremental overlay supplies
`worker/ggfm-gateway` and `worker/deploy/run_managed.py`. Stop once, extract at the
deployment root and restart the original entry. It preserves operator config,
proxy trust, source packages, signing material, version counter and ARMv7 overlay.
The supervisor sets executable permissions on the new gateway itself. New
deployments whose bundled worker supports `blueGreen` use it automatically.

新版本后台打包，旧版继续提供页面和预置下载。新实例连续健康检查 30 秒后，
原子切换入口路由；失败不停止旧实例。发布后的新实例退出时，保留的旧实例
仍在则回滚。入口使用原有 Cloudflare/LAN 代理校验、限流、封禁与流式体积限制，
后端只监听本机并要求每次启动生成的内部令牌。无需改外部 Nginx。

Challenge nonces and download grants carry a generation prefix. Proofs and
downloads route to their issuing worker, independent of browser cookies/tabs.
Unknown/retired generations return 410 rather than silently reaching the new
worker. Legacy unprefixed grants are handled only during the initial migration.
Existing streams hold their old upstream connection through route changes.

旧实例至少保留 13 分钟（验证挑战 3 分钟 + 下载令牌 10 分钟），且必须没有
在途请求并安静满 10 分钟才退出：切换前已开始的慢上传可能稍后生成新令牌。
旧实例未排空时不再启动第三代，最多两个轻量服务实例。OS 文件锁跨实例串行化
所有重型打包，包括后台预生成；一次只能有一个重型任务。

检查更新默认每 5 分钟一次。已发布版本组合相同不会重建；旧实例仍在排空时，
下一次更新会等待，不保证每 5 分钟都部署一版。首次装入常驻入口、重启整个部署
或入口本身崩溃仍会短暂中断，并非所有故障下的高可用集群。第一次从不支持锁的
旧 worker 迁移时，预置下载保持可用，但完整上传暂时返回带 Retry-After 的 503，
直到支持跨实例锁的新 worker 上线；避免在旧进程中启动无法监管的重型构建。

The gateway executable stays fixed during unattended worker upgrades so the
listener and security counters do not restart. Gateway changes themselves need
a new overlay and one deployment restart. Worker/Patch updates remain automatic.
This does not automatically update an already installed Android application.
