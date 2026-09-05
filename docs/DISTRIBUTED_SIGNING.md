# Preserve the distributed application's identity / 保留已发布应用身份

The locally distributed `Guitar-Girl-Fan-Memorial-Build-20260906.xapk` was audited
with Android apksigner. Its base and both splits share:

- applicationId: `org.guitargirlresuscitation.memorial.selfhosted.ka698528c01eb`
- certificate SHA-256: `A698528C01EBD3205C5B6379D60A40F3157BA9EB7B14474DA21947C6E85FBCA6`
- initial Android versionCode: `800001`

Updates for recipients of that package MUST preserve the applicationId and
original private keystore, use a greater versionCode, and sign every split
with that same certificate. The private key/password are NOT release assets.
Earlier experimental Android keys are not valid update keys for this package.

The Docker `/data/signing` directory contains the deployment identity, key and
password. Keep the original directory across container/image updates. Moving
hosts requires a secure private transfer of that directory, not a fresh data
volume. Never regenerate a key to work around a missing signing file. The
bootstrap rejects partial signing-state loss before generating anything.

A clean independent deployment intentionally generates its own identity; it
cannot update this already-distributed package unless its operator securely
provisions the original key and matching applicationId. Public GitHub artifacts
do not and must not make every independent deployment share a private key.

已发出的 20260906 安装包采用上方固定包名与证书，不能再用早期测试密钥出更新包。
覆盖升级需要：原包名、原私钥、递增版本号、所有 split 同证书。不要卸载或清数据。

部署更新保留原 `/data/signing`；换服务器时私下安全转移，不重新生成。全新部署默认
生成不同身份，不能直接替换这批用户的安装包。签名私钥和密码绝不上传仓库或 Release。
