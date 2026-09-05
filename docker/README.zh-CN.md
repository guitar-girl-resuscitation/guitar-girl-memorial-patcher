# Docker 部署 — Guitar Girl Memorial Patcher

[English](README.md) · 简体中文

此 Release 是 **Docker 构建目录**，不是预装镜像，也不是游戏包。它包含 Dockerfile、
已编译 Patcher 和匹配的 Server / Patch 运行时。构建镜像时获取固定提交的 Patch
源码和有哈希校验的 Android 工具，不包含原版 XAPK、游戏成品或签名密钥。

## 构建与启动（Linux amd64）

从同一 Release 下载 `ggfm-patcher-docker-linux-amd64.zip` 及其 `.sha256` 文件，
校验后解压到新目录，在该目录执行：

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

将 HTTPS origin 改成自己的域名，末尾不带斜杠。构建时需要联网访问 Ubuntu
软件源、GitHub、Google Android 工具和 Python 包；当前仅支持 Linux amd64。
请检查这些第三方依赖的许可。

等待出现 `READY: port 8080`。同一个数据目录只允许运行一个实例。
容器使用 UID/GID 10001；也可用 `-v ggfm-data:/data` 命名卷替代 data 绑定挂载，
此时无需执行宿主机 chown。

| 挂载点 | 模式 | 内容 |
| --- | --- | --- |
| `/data` | 持久化读写 | 签名密钥/密码、包名身份、工作目录及成品缓存 |
| `/input` | 可选，只读 | 部署者提供的 `original.xapk` |

数据文件系统至少预留 12 GB，公网部署还应设置磁盘配额。
这里保存的是打包站数据，不是玩家手机里的存档。

## 可选：原包预置，自动补丁一次

在**启动前**将受支持原包放入 `input/original.xapk`，确保 UID 10001 有读取权限。
SHA-256 必须是：

```text
E395AD8A0BF09EA9425D7751388D61C31E9B63411640A716432AC97940BB9FAC
```

原包有效时，启动阶段会按构建身份制作一次成品。访客选择自己的原包，经本地
哈希及随机分块持有校验后直接下载缓存，不会重复触发重型构建；相同 Release
重启后会验证并复用缓存。

原包不存在或无效时，网站正常运行于完整上传模式：用户必须完整上传匹配的
XAPK，由一个 worker 打补丁。无效预置原包会记录日志，不会放行未经验证的缓存。
健康检查同时支持这两种正常模式。

运行期间不要修改原包/缓存；有计划地更换原包后再重启。持有校验不等于分发许可。

## 外部 nginx / Cloudflare

容器不内置 nginx，只暴露一个端口，宿主机默认绑定回环。
可以通过 Cloudflare Tunnel 连接本机端口，或接在你现有的 nginx 后面再走
Cloudflare。后一种方式必须用防火墙白名单或受认证源站限制 nginx 只接收
Cloudflare 流量，否则访客可伪造可信的 `CF-Connecting-IP` 来绕过单 IP 限制。
不要把 8088 直接开放到公网。

在已有 HTTPS 的 `server {}` 中配置：

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

Cloudflare 对整个域名设置缓存绕过，不能缓存 API 或下载令牌。
内建限流与失败封禁继续生效，封禁状态是进程内的。
Cloudflare 自身请求体大小/超时仍生效，nginx 参数或 Tunnel 不能绕过它们；
这种较大的 XAPK 在低档套餐上优先使用预置模式。目前没有分块完整上传或异步任务接口。

## 更新和持久化

新 Release 自动内嵌递增 Android 版本，不用手改 `revision: 1`，详见
[VERSIONING.md](VERSIONING.md)。构建新 Release 的 Docker 目录，再替换容器，
继续挂载**同一个数据目录/卷**，保留公网 origin 与应用包名。

升级不要删除 `data/signing`、重新生成密钥，或执行 `docker compose down -v`。
丢失密钥会使新包无法无缝覆盖安装旧包。默认包名由持久签名证书派生；
首次启动可通过 `GGFM_APPLICATION_ID` 自选纪念版自部署包名后缀。
已有身份的签名/包名发生变化会被拒绝。

运行时/版本更新会创建新缓存，不会自动更新已经安装的游戏；玩家需要下载新包，
同时安装全部 split。不要公开私有缓存，也不要把挂载的原包烘焙进公开镜像。
