# Guitar Girl Memorial Patcher

[English](README.md) · 简体中文

为 **Guitar Girl Fan Memorial Build** 提供严格校验的 CLI 和单 worker 网页补丁工具，将用户提供的受支持原版 XAPK 制作成带内建 Rust 服务端的独立纪念版。

本仓库及公开 Release 提供的是工具，**不包含原游戏或修改后的游戏安装包**。

Linux / Docker 部署通过独立入口自动更新 worker 和已编译的 Patch / Server
运行时。有预置原包时先重新打包，校验成功才启用新版；保留签名身份与持久化的
递增 Android 版本号，失败回退。详见[自动更新部署说明](docs/DEPLOYMENT.md#自动更新中文)。

## 三个仓库分别做什么

| 仓库 | 职责 |
| --- | --- |
| [Server](https://github.com/guitar-girl-resuscitation/guitar-girl-memorial-server) | Rust 玩法、协议、SQLite 存档与 Android 内建服务端库 |
| [Patch](https://github.com/guitar-girl-resuscitation/guitar-girl-memorial-patch) | 自有客户端集成、纪念版界面、身份隔离与有校验的变换规则 |
| [Patcher](https://github.com/guitar-girl-resuscitation/guitar-girl-memorial-patcher) | CLI / 网页打包、原包验证、资源提取、签名和下载 |

游戏运行时，修改后的 Unity 客户端通过带认证的本机回环连接内建 Rust 服务端。补丁网站**不是游戏服务器**，游玩时不需要它持续在线。

## 玩家怎么用

1. 准备你有权使用的受支持原包。目前仅支持 **8.0.0 / Android ARM64**，必须匹配下方 SHA-256。
2. 使用可信部署或自行部署网站，选择原 XAPK，浏览器先在本地计算哈希。
3. 完整上传模式会上传原包并等待补丁；部署者预置模式通过随机文件分块持有校验后，直接下载缓存成品，不必上传整个原包。
4. 使用支持 split 安装包的安装器安装输出 XAPK。所有 split 必须一起安装，不能只装 base APK。
5. 打开 **Guitar Girl Fan Memorial Build**，启动本机运行时即可游玩，不需要 Root、LSPosed 或另行部署游戏服务器。

```text
受支持原版 XAPK 的 SHA-256
E395AD8A0BF09EA9425D7751388D61C31E9B63411640A716432AC97940BB9FAC
```

文件名或版本号相同并不足够。未知哈希或 split 不符会被拒绝；以 [Patch 兼容清单](patch/compatibility/8.0.0.json) 为准，不支持任意下载到的同名安装包。

保留相同 application ID 和签名证书才能正常覆盖升级并保留已安装数据。不同部署的签名/包名可能产生独立应用或无法互相覆盖。卸载前请导出存档，不应假设官方或旧实验存档兼容。

## 打包流程

```text
用户原版 XAPK
  → 整包 / split / 结构验证
  → 私有目录提取并生成 master.sqlite
  → 校验后执行 Patch 变换、注入预编译 Server 与运行时
  → 重写包名、显示名和 split 元数据
  → zipalign，全部 split 使用同一证书签名
  → 验证最终 XAPK 并提供下载
```

Rust workspace 分为 `patcher-core`、CLI 和网页服务。`patch/` 是固定提交的 Git 子模块，不复制维护另一份 Patch。Server 通过 ABI 和 SHA-256 选择预编译产物，不为每个访客现场编译。

校验包含归档路径穿越/大小限制、相关二进制和数据指纹、变换前置条件、应用身份、policy 一致性及 split 签名。任何前置条件失败都会停止。

## 构建和 CLI 基础用法

需要支持子模块的 Git、CI 固定的 Rust 工具链（当前 1.96.0）、Python 3.11+，以及运行浏览器哈希测试的 Node.js。

```sh
git clone --recurse-submodules https://github.com/guitar-girl-resuscitation/guitar-girl-memorial-patcher
cd guitar-girl-memorial-patcher
git submodule update --init --checkout
cargo test --workspace --locked -j2
cargo build --workspace --locked --release -j2
node tools/test-browser-sha256.mjs
python tools/test_deployment.py
```

以下为 Linux 示例；Windows 可执行文件带 `.exe` 后缀：

```sh
./target/release/ggfm-patcher hash /private/original.xapk
./target/release/ggfm-patcher verify /private/original.xapk patch/compatibility/8.0.0.json
./target/release/ggfm-patcher plan --help
./target/release/ggfm-patcher patch --help
```

`hash` 输出摘要，`verify` 检查兼容性，`plan` 记录版本化构建计划，`patch` 执行实际变换。实际打包要求显式指定运行时/工具路径、哈希和签名参数；不会悄悄使用已连接的手机。

## 运行网页服务

### 推荐：Docker Release，挂载目录部署

从 [Releases](https://github.com/guitar-girl-resuscitation/guitar-girl-memorial-patcher/releases)
下载并校验 `ggfm-patcher-docker-linux-amd64.zip`，解压到新目录，在其中执行
（将 HTTPS origin 替换为自己的域名）：

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

`data/` 持久保存签名身份、缓存和工作文件，升级时必须保留。
可以在启动前把匹配原包放入 `input/original.xapk`，只读挂载并自动制作一次成品；
没有有效原包就接受完整校验上传。等日志出现 `READY` 后再使用。

镜像不含游戏，不要求宿主机安装 Java / Android / Python；构建镜像时需要联网
下载固定源码/工具。你自己的 nginx 或 Cloudflare Tunnel 接本机 8088 即可，
不要将这个可信代理入口直接暴露公网。权限、空间、更新及 nginx / Cloudflare
限制详见 [Docker 部署说明](docker/README.zh-CN.md)。

### 原生 / 手动部署

公开部署前先阅读 [部署步骤](docs/DEPLOYMENT.md) 和 [公网安全要求](docs/PUBLIC_DEPLOYMENT.md)。

1. 获取与干净 `patch/` 准确提交对应的已编译运行时，读取其 `dependencies.json`，取得**匹配的** Server。核对全部摘要和 ABI，不要混用独立变化的 Nightly。
2. 安装 Java 21、Android platform / build-tools 35.0.0、兼容的 apktool JAR，以及私有 Python 环境中的 `patch/tools/requirements.lock.txt`。
3. 在仓库与 web root 之外建立私有签名 keystore。自部署使用自己的包名后缀与证书，更新时必须保留密钥。
4. 将 [config/patcher.example.json](config/patcher.example.json) 复制到私有位置，替换**全部**路径、哈希、版本、签名指纹和公网 origin 占位符。Linux 部署必须修改示例的 Windows 路径。
5. 使用服务的 secret 机制注入配置中指定的密码环境变量，不要把密码写入 Git 或公开命令记录。
6. 启动：

```sh
export GGFM_PATCHER_CONFIG=/srv/ggfm/private/patcher.json
export RUST_LOG=info
# 通过安全方式注入 GGFM_KEYSTORE_PASSWORD 和 GGFM_KEY_PASSWORD。
./target/release/ggfm-patcher-web
```

服务先验证依赖，之后才监听本机回环地址。部署只运行一个进程、一个重型 worker。Release 同时提供原生 CLI / 网页工具包和无游戏资源的 Docker 构建包，两者都不含游戏。

### 两种部署模式

| 模式 | 部署者提供 | 访客提供 | 重型工作 |
| --- | --- | --- | --- |
| 完整上传 | 工具、运行时和签名 | 完整、匹配的原版 XAPK | 每次接受的上传打包一次 |
| 部署者预置 | 另提供私有的匹配原 XAPK | 本地哈希和新鲜随机文件分块 | 每个验证后的构建身份制作一次，之后复用缓存 |

将 `prebuilt.operatorSourceXapk` 设为私有原包路径即可显式启用预置模式。服务启动时验证原包并准备/验证成品。不存在可用预置原包时，自动回退完整上传。

持有校验抽取 8 个随机 64 KiB 分块，三分钟过期、单次使用；通过后得到十分钟有效、单次使用的下载令牌。只上报公开哈希不够。

缓存身份包含原包、准确 Patch / Server 版本与哈希、policy、包名、签名和相关工具。运行时原包/缓存必须保持不变，更换时有计划地重启部署。不要把原包、工作、缓存或签名目录作为静态目录公开；缓存成品包含游戏资源，不得上传 GitHub。

### 公网入口、限制和失败封禁

原生公网配置使用**本机 Cloudflare Tunnel**，Docker 指南另覆盖 Cloudflare 后的宿主机 nginx。仅通过配置的可信代理边界接受访客身份；禁止绕过代理直连源站，并按部署文档验证 origin 和缓存规则。

- 按 IP 限制请求、API、上传和下载，并限制全局/单 IP 同时处理数。
- 十分钟内 8 次符合条件的失败会触发十五分钟的进程内封禁。这不是 OS Fail2ban，也不会修改 Cloudflare 账号防火墙规则；重启会清除内存封禁状态。
- API / 下载不可缓存，Cloudflare 对整个部署域名配置缓存绕过，不要使用 Cache Everything。
- 重型 worker 固定一个，忙时新上传返回 HTTP 503。
- 上传最大 768 MiB，总超时十分钟，空闲超时三十秒。
- 归档最多 64 项、展开上限 1.5 GiB；单请求工作目录配额 6 GiB；外部工具超时十五分钟。

Cloudflare 自身的上传大小和代理超时限制依然生效，Tunnel 不会绕开它们。受支持 XAPK 超过常见低档套餐上传限制，因此这些部署优先使用预置模式。完整上传必须确认实际套餐/链路能承载原包及处理时间。目前没有分块上传或异步任务提交；选择上传模式前请检查公网部署文档。

随机分块只证明持有文件，不证明版权许可；部署者仍需自行考虑是否有权分发成品。

## Release 与上游自动更新

Android 版本绑定发布构建：第 N 次 workflow 运行生成 `versionCode = 800000 + N`
和 `8.0.0-memorial.N`。新运行递增，重跑同一次运行或重复下载不变。部署配置中
省略 `versions.revision`（删除旧的固定 `1`），不匹配的覆盖值会直接报错。
可通过 `ggfm-patcher version`、`/healthz` 或 Release 清单查看实际版本。
覆盖更新需要保留包名和签名密钥，详见 [版本与本地构建说明](docs/VERSIONING.md)。
这不是游戏内自动更新器，玩家仍需取得并安装新包。

[Releases](https://github.com/guitar-girl-resuscitation/guitar-girl-memorial-patcher/releases) 提供 `ggfm-patcher-linux-x64.zip` 及 SHA-256 文件。main 构建成功后替换唯一 Nightly；标签生成版本化 Release。压缩包只有打包工具，不含游戏或私钥。

上游更新 workflow 每六小时或手动执行：验证已发布的 Patch，更新固定 gitlink 和依赖记录，测试后触发新构建。它**不会**更新正在运行的部署、替换签名密钥或给玩家手机安装应用；部署者应有计划地部署匹配版本。

## 测试和排错

- 哈希/清单失败：检查输入原包，不要关闭校验。
- ABI / policy 失败：使用 Patch 记录的准确组件组合。
- HTTP 503：等待单 worker，不要开重复进程绕过内存限制。
- HTTP 413 或代理超时：检查 Cloudflare 限制，必要时使用预置模式。
- 安装冲突：检查包名、证书，不要首先尝试删除存档。

显式选定测试设备后，可运行 `python tools/smoke-test-android.py output.xapk --serial YOUR_ADB_SERIAL` 安装全部 split 并检查进程存活。这不能代替完整的游戏内验收。

## 项目边界、贡献与许可

这是非官方的粉丝纪念版与互操作项目，与原开发商、发行商没有官方关联或背书。不恢复官方账号、云存档、支付或已退役的线上服务。部分历史服务端专有数值采用纪念版兼容值，不宣称完整复现原服全部数据。

项目代码采用 [AGPL-3.0-or-later](LICENSE)，第三方组件保留各自许可；该许可不覆盖原游戏。请只使用你有权使用的原始安装包。

请勿提交 APK/XAPK、AssetBundle、原版 DEX/IL2CPP 二进制、完整反编译导出、抓取的专有主表、私人存档或签名密钥。反馈问题请提供组件版本/提交、章节、复现步骤和脱敏诊断日志。修改行为时补充契约/回归测试，并同步维护两种语言的 README。
