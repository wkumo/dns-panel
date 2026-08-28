# DNS Panel

使用 Go、原生 Web 前端和 SQLite 构建的自托管 DNS 管理面板。构建需要 Go 1.25 或更高版本。

## 启动

```bash
go run .
```

或使用 Docker：

```bash
docker compose up --build -d
```

访问 `http://localhost:48192`。首次登录账号和密码均为 `admin`，系统会要求修改账号、密码并填写邮箱。SQLite 数据通过 bind mount 持久化在 Compose 文件旁的 `data/` 目录，不使用 Docker named volume。

Linux 部署时可以通过 `DATA_PATH` 指定宿主机数据目录。容器入口会按 `PUID`/`PGID` 修复挂载目录权限，然后立即切换为对应的非 root 用户运行服务：

```bash
mkdir -p "$HOME/data"
printf 'PUID=%s\nPGID=%s\nDATA_PATH=%s/data\n' "$(id -u)" "$(id -g)" "$HOME" > .env
docker compose up -d
```

上述示例会把数据库保存在当前 Linux 用户可写的 `$HOME/data/dns-panel.db`。如果不设置 `DATA_PATH`，默认位置仍是 Compose 文件旁的 `./data/dns-panel.db`。备份时应先停止服务，再复制整个数据目录。

## Cloudflare 配置

创建 Cloudflare API Token 时至少授予以下权限，并将 Zone Resources 限制到需要管理的域名：

- Zone / Zone / Read
- Zone / DNS / Read
- Zone / DNS / Edit

在 API Key 页面选择 `cloudflare` 并填写 Token。新增域名时 Zone ID 可以留空；第一次最新化或同步时，面板会按域名查询 Zone 并保存 ID。

- 每次登录成功后自动从 Cloudflare 拉取 A、AAAA、CNAME、TXT、MX、CAA、SRV，并写入 SQLite。
- “保存并同步”会先以事务保存页面内容，再按本地状态创建、PATCH 更新或删除云端记录。
- DNS 管理保留“最新化所有域名”作为手动保底措施，执行前会在页面内要求确认。
- 页面会明确显示同步处理中、成功处理数量或失败原因；成功项立即标记为已同步，失败项保留以便修正后重试。
- A、AAAA、CNAME 记录可以通过“小黄云”复选框管理 Cloudflare 代理状态。

## 其他能力

- 用户会话、首次登录安全流程、账户资料修改与 SMTP 验证码
- 可设置最小长度，并可组合数字、大写字母、小写字母、符号密码规则；默认不限制
- 域名和七类 DNS 记录的批量草稿编辑
- 独立的域名管理页面，用于关联域名和 API Key；DNS 管理页面只展示这些已配置域名
- 域名和 API Key 均支持上移、下移并将顺序持久化到 SQLite
- 注册开关、注册邮箱验证码、账户资料验证码、登录通知邮件和 SMTP 测试
- 默认 DNS 记录类型通过 A、AAAA、CNAME、TXT、MX、CAA、SRV Checkbox 配置
- 全站页面通知取代浏览器弹窗，可配置显示 3 秒、5 秒或手动关闭
- 每个用户可设置名称过滤关键词和记录内容过滤关键词；DNS 管理默认隐藏命中项，并可临时勾选“显示已过滤记录”
- 每个用户可注册并管理多条 TOTP OTP 验证器和多条 WebAuthn Passkey
- 可统一启用强制二次认证，普通用户登录时可选择 OTP、Passkey 或邮箱验证码
- 管理员用户后台支持 50 条/页、OTP/Passkey 状态和强制密码重置
- 忘记密码邮件包含用户名和一小时有效的一次性重置链接
- HTTPS 监控汇总 A、AAAA、CNAME，支持端口、备注、排序、屏蔽、完整证书链检查、邮件和 Bark 告警

## OTP 与 Passkey

新增 OTP 后，面板会显示 Base32 密钥和 `otpauth://` 配置 URI。必须输入验证器生成的 6 位动态码后才会启用该记录，校验允许前后各一个 30 秒时间窗口。

Passkey 使用浏览器原生 WebAuthn API 和服务端保存的临时 challenge。默认本地配置为：

```text
PASSKEY_RP_ID=localhost
PASSKEY_ORIGINS=http://localhost:48192
```

部署到正式域名时必须修改为实际域名和 HTTPS Origin，例如：

```text
PASSKEY_RP_ID=dns.example.com
PASSKEY_ORIGINS=https://dns.example.com
```

多个允许来源用英文逗号分隔。除 `localhost` 外，浏览器要求 Passkey 页面使用 HTTPS。

密码重置邮件中的站点地址由 `PUBLIC_URL` 指定。正式部署示例：

```text
PUBLIC_URL=https://dns.example.com
```

## 二次认证与 SMTP

全局“用户与安全”只显示开放注册、强制二次认证和登录通知邮件。SMTP 参数保存后，先点击“测试连接”；只有连接和认证成功后才能启用强制二次认证。SMTP 参数发生变化时，系统会自动关闭强制二次认证，防止邮箱保底验证失效后锁住用户。

强制二次认证启用后，普通用户的密码登录只创建受限会话。用户可选择自己已经配置的 OTP、Passkey，或者发送邮箱验证码完成登录。管理员账号豁免。

## HTTPS 监控

HTTPS 监控每小时自动运行，也可在页面手动执行。默认访问 `https://主机:443`，每条记录可以修改端口和备注。检测包括网络可达性、TLS 握手、系统根证书链、证书域名以及生效/过期时间。

个人设置可填写 Bark Webhook URL，例如 `https://api.day.app/你的Key`。服务不可达或证书无效时，系统会发送邮件，并在配置 Bark 后以 JSON POST 发送 Bark 通知。
- Docker 多阶段构建，无 Node 运行依赖

## 尚未完成

阿里云、腾讯云的真实同步，以及 OTP 与 Passkey 验证流程尚未实现。

生产部署前还应使用主密钥加密 SQLite 中保存的 API Secret，并在反向代理层启用 HTTPS。
