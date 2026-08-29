# DNS Panel

使用 Go、原生 Web 前端和 SQLite 构建的自托管 DNS 管理面板。构建需要 Go 1.25 或更高版本。

## Linux 构建、测试与发布到 Docker Hub

以下示例假设源码位于 `/opt/dns-panel-build`，Docker Hub 用户名为 `YOUR_DOCKER_ID`，发布版本为 `v1.0.0`。

### 1. 准备源码和数据目录

```bash
cd /opt/dns-panel-build
git pull

export PUID="$(id -u)"
export PGID="$(id -g)"
export DATA_PATH="/opt/dns-panel-build/data"
```

构建上下文通过 `.dockerignore` 排除 `data/` 和 `*.db`，SQLite 数据不会进入镜像。运行时 `DATA_PATH` 会绑定到容器 `/data`；入口脚本先修复目录权限，再以 `PUID:PGID` 降权运行服务。

### 2. 运行源代码测试

如果服务器安装了 Go 1.25 或更高版本：

```bash
go test ./...
```

没有安装 Go 时，可以直接使用官方 Go 容器运行测试：

```bash
docker run --rm \
  -v "$PWD:/src" \
  -w /src \
  golang:1.25-alpine \
  go test ./...
```

### 3. 构建本机架构镜像

```bash
docker compose down
docker compose build --no-cache
docker image inspect dns-panel:latest >/dev/null
```

### 4. 本地容器测试

```bash
docker compose up -d
docker compose ps
docker compose logs --tail=100 dns-panel
curl --fail http://127.0.0.1:48192/api/policy
```

浏览器访问 `http://服务器IP:48192`，至少验证登录、SMTP、Cloudflare 拉取/同步、SQLite 持久化和容器重启：

```bash
docker compose restart dns-panel
test -f "$DATA_PATH/dns-panel.db"
curl --fail http://127.0.0.1:48192/api/policy
```

### 5. 登录 Docker Hub

先在 Docker Hub 创建 `dns-panel` 仓库和具有 Read/Write 权限的 Access Token，然后在服务器执行：

```bash
docker login --username YOUR_DOCKER_ID
```

密码位置粘贴 Access Token，不要把 Token 写进源码、Compose 或 Shell 历史。

### 6A. 发布当前服务器架构

服务器和目标机器都是 `linux/amd64` 时：

```bash
docker tag dns-panel:latest wkkm/dns-panel:v0.0.4
docker tag dns-panel:latest wkkm/dns-panel:latest
docker push wkkm/dns-panel:v0.0.4
docker push wkkm/dns-panel:latest
```

### 6B. 发布 AMD64 与 ARM64（推荐公开发布时使用）

```bash
docker buildx create --name dns-panel-builder --driver docker-container --use --bootstrap
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t wkkm/dns-panel:v0.0.2 \
  -t wkkm/dns-panel:latest \
  --push .

docker buildx imagetools inspect wkkm/dns-panel:v0.0.2
```

### 7. 在正式服务器部署已发布镜像

正式服务器的 Compose 应删除 `build: .`，并固定版本：

```yaml
services:
  dns-panel:
    image: wkkm/dns-panel:v1.0.0
    restart: unless-stopped
    ports:
      - "48192:48192"
    environment:
      PUID: ${PUID:-1000}
      PGID: ${PGID:-1000}
    volumes:
      - ${DATA_PATH:-./data}:/data
```

部署与升级：

```bash
export PUID="$(id -u)"
export PGID="$(id -g)"
export DATA_PATH="/opt/dns-panel/data"

docker compose pull
docker compose up -d
docker compose ps
docker compose logs --tail=100 dns-panel
```

发布新版本时使用新标签，例如 `v1.0.1`；正式服务器不要只依赖 `latest`，这样可以把 Compose 标签改回上一版本快速回滚。升级前先停止服务并备份整个数据目录：

```bash
docker compose stop dns-panel
tar czf "dns-panel-data-$(date +%F-%H%M%S).tar.gz" -C "$DATA_PATH" .
docker compose start dns-panel
```

## 启动

```bash
go run .
```

或使用 Docker：

```bash
docker compose up --build -d
```

访问 `http://localhost:48192`。首次登录账号和密码均为 `admin`，系统会要求修改账号、密码并填写邮箱。SQLite 数据通过 bind mount 持久化在 Compose 文件旁的 `data/` 目录，不使用 Docker named volume。

### API 凭据主密钥

SQLite 中的 API Key/Secret 使用 AES-256-GCM 加密保存。每条字段使用独立随机 Nonce，并绑定字段类型作为认证数据；应用仅在调用云厂商、显示脱敏后缀或生成密码加密备份时于内存中解密。已有数据库中的明文凭据会在升级后的首次启动时自动事务迁移。

本地开发未配置密钥时，应用会自动创建 `DATA_DIR/master.key`（权限 `0600`）。生产环境应将密钥放在数据库目录之外，并通过只读文件注入：

```bash
sudo install -d -m 700 /etc/dns-panel
openssl rand -base64 32 | sudo tee /etc/dns-panel/master.key >/dev/null
sudo chmod 600 /etc/dns-panel/master.key
```

在生产服务器创建 `docker-compose.override.yml`：

```yaml
services:
  dns-panel:
    environment:
      DNS_PANEL_MASTER_KEY: ""
      DNS_PANEL_MASTER_KEY_FILE: /run/secrets/dns-panel-master-key
    volumes:
      - /etc/dns-panel/master.key:/run/secrets/dns-panel-master-key:ro
```

然后执行 `docker compose up -d`。也可以用 `DNS_PANEL_MASTER_KEY` 直接传入 Base64 密钥，但文件方式可避免密钥出现在 Compose 配置和环境变量中。密钥丢失后 API 凭据无法恢复；密钥错误或密文被篡改时应用会拒绝启动。备份时应分别安全保存数据库和主密钥，不能把主密钥写入导出的 JSON。

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
- DNS、HTTPS、域名、API Key 和用户管理页面支持 Header 关键字即时筛选
- 个人中心支持 AES-256-GCM 加密导入/导出；管理员备份额外包含全部全局设置

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

阿里云、腾讯云的真实同步尚未实现。

生产部署时还应在反向代理层启用 HTTPS。
