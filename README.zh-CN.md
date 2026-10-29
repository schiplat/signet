# Signet

统一身份认证（SSO / OIDC IdP）服务。

> 语言：简体中文 · [English](./README.md)

- **生产入口（未来）**：`https://sso.example.com`
- **开发默认 Issuer**：`http://localhost:8443`（`SIGNET_ISSUER` 可配）
- **首个接入方**：Cella（内网子系统）；客户端统一走通用申请渠道（Dashboard → Clients 或 RFC 7591 动态注册），无内置预置

> 命名说明：本项目为 SSO，**不是**阿里云 Object Storage（OSS）。

## Quick Start

有三种把服务跑起来的方式。**推荐使用 release 二进制**：每个 [GitHub Release](https://github.com/schiplat/signet/releases) 都提供自包含的 `linux-amd64` / `linux-arm64` / `macos-arm64` 可执行文件，Dashboard 已在编译期嵌入——单个文件加一个 PostgreSQL 即可运行，无需 Rust / Node 工具链；数据库迁移也已内置，启动时自动执行。

**方式 A：release 二进制（推荐）**

```bash
# 1. 到 GitHub Releases 下载对应平台产物（以页面上最新 tag 为准），例如：
curl -fLO https://github.com/schiplat/signet/releases/download/v0.4.3/signet-0.4.3-macos-arm64
chmod +x signet-0.4.3-macos-arm64 && mv signet-0.4.3-macos-arm64 signet

# 2. 起一个与内置默认连接串一致的 PostgreSQL（signet/signet@127.0.0.1:5433/signet）；已有可跳过
docker run -d --name signet-db -p 5433:5432 \
  -e POSTGRES_USER=signet -e POSTGRES_PASSWORD=signet -e POSTGRES_DB=signet \
  postgres:16-alpine

# 3. 运行 —— 会从工作目录读取 .env（见下方「配置文件」）
./signet
```

**方式 B：Docker 镜像**

每个 release 同步发布运行时镜像（Docker Hub + ACR）；只拉不建的生产编排见 [`deploy/`](./deploy/)：

```bash
cd deploy
cp ../.env.example .env   # 编辑 SIGNET_*；并设置 SIGNET_IMAGE=<registry>/signet:<tag>
docker compose up -d
```

生产布局（外部 Postgres、密钥卷）详见 [docs/deploy.md](./docs/deploy.md)。

**方式 C：源码构建（开发）**

前提：Rust stable、Node 20+ 与 pnpm、Docker（只为跑一个 Postgres）。

```bash
# 1. 起 Postgres —— 与内置默认连接串一致，无需任何配置
docker compose -f build/docker-compose.yml --profile dev up -d db

# 2. 构建前端产物 —— rust-embed 在编译期嵌入 dashboard/dist，必须先于 cargo run 存在
cd dashboard && pnpm install && pnpm build && cd ..

# 3. 起服务
cargo run -p signet
```

### 配置文件

三种方式读的是同一套环境变量：二进制从工作目录加载 `.env`，compose 注入同名变量。下面两行即可启动；完整带注释的参考见 [.env.example](./.env.example)。

```dotenv
SIGNET_DATABASE_URL=postgres://signet:signet@127.0.0.1:5433/signet
SIGNET_ISSUER=http://localhost:8443
```

| 配置 | 说明 |
|------|------|
| `SIGNET_DATABASE_URL` | PostgreSQL 连接串（上面的值即内置默认值，与本地 dev `db` 容器一致） |
| `SIGNET_ISSUER` | 客户端访问本服务的公开 origin；不能以 `/` 结尾。生产必须设为真实 HTTPS 域名（issuer 为 https 时自动启用 `Secure` Cookie） |
| `SIGNET_HTTP_BIND` | HTTP 监听地址；默认 `0.0.0.0:8443` |
| `SIGNET_TRUSTED_PROXIES` | 仅反向代理后需要：允许断言 `X-Forwarded-For` 的代理 IP/CIDR，逗号分隔 |
| 密钥 | `./data/jwt_private.pem` 与 `./data/encryption.key` 首次启动自动生成——**务必备份**：丢失或轮换会使已签发 token 失效、已存 TOTP 无法解密 |

首位管理员**不**通过配置文件创建：首次启动时 Dashboard 会跳转 `/setup` 创建。

### 首次运行

打开 **http://localhost:8443** —— 首次访问自动跳转 **`/setup`**，创建第一个管理员并登录。

**体验 SSO：** **Dashboard → Clients** 注册一个客户端（secret 只展示一次，弹窗里就是可直接复制给子系统的 `.env` / `config.toml` 片段），然后在列表里点 **Test drive** —— 新标签页走完真实的 authorize → 登录 → consent → 回调，验证整条链路。

**（可选）示例客户端**，五分钟跑通端到端登录：

```bash
cd examples/axum-oidc-client
export OIDC_ISSUER=http://localhost:8443 OIDC_CLIENT_ID=<上面的 id> OIDC_CLIENT_SECRET=<上面的 secret>
cargo run
# 打开 http://127.0.0.1:3000 → Sign in → SSO 登录成功
```

前端热更新开发（`:5173` 代理 `:8443`）见下方[本地开发](#本地开发)。业务系统接入文档见 [docs/client-integration.md](./docs/client-integration.md)。

## 功能概览

- OIDC IdP：authorize / token / PKCE / refresh / userinfo / JWKS / end_session / revoke
- Dashboard：用户、客户端、审计、总览统计（可按 client 过滤）、MFA、Passkey、Webhook、SCIM
- **第三方登录**（身份联邦）：GitHub · Google · 飞书 · 微信开放平台 · 通用 OIDC  
  绑定：上游已验证邮箱匹配本地账号 → 自动绑定；否则按 JIT 策略（全局 Settings 开关 + **每个 provider 可独立覆盖** `jit_mode`，并可单独配置 email 可信级别 `email_trust`）**JIT 创建** `member` 并登录；再否则暂存 15 分钟待密码绑定。本地 MFA / 强制改密策略对第三方登录同样生效。详见 [docs/api-v1.md §12](./docs/api-v1.md#12-第三方登录身份联邦)

![Dashboard 总览](./docs/screenshot_overview.png)

## 文档

| 文档 | 内容 |
|------|------|
| [docs/design.md](./docs/design.md) | 总体设计、角色、安全、路线图 |
| [docs/security.md](./docs/security.md) | **安全设计汇总**（凭证存储、认证、会话、MFA、OIDC、审计、密钥） |
| [docs/client-integration.md](./docs/client-integration.md) | **业务客户端 OIDC 对接**（authorize/token/PKCE/IP 白名单） |
| [docs/integrations.md](./docs/integrations.md) | **集成对接**（RFC 7591 动态注册 · Webhooks/飞书 · SCIM v2） |
| [docs/api-v1.md](./docs/api-v1.md) | **Dashboard HTTP API**（统一 `/api/v1/...`，含第三方登录） |
| [docs/mfa.md](./docs/mfa.md) | TOTP / 恢复码 / 全局与用户强制策略 |
| [docs/dashboard.md](./docs/dashboard.md) | 管理台页面与权限说明 |
| [docs/directory-sync.md](./docs/directory-sync.md) | **目录同步**（LDAP / HTTP JSON 拉取、bind 直通、定时调度、`signet sync` CLI） |
| [docs/directory-mapping-ux.md](./docs/directory-mapping-ux.md) | 目录同步字段映射交互设计（含实现记录） |
| [docs/deploy.md](./docs/deploy.md) | **build/ 与 deploy/**（Dockerfile、本地与生产 compose、`/app/data` 密钥） |

## 本地开发

### 1. 配置

```bash
cp .env.example .env
# 编辑 SIGNET_DATABASE_URL 等
```

首次启动且库中无管理员时，在浏览器打开 Dashboard，会自动跳转到 **`/setup`** 页面，创建首位管理员账户（邮箱、可选显示名）与密码。

### 2. 后端

```bash
cargo run -p signet
```

> 注意：二进制在编译期嵌入 `dashboard/dist`（rust-embed），该目录不存在会编译失败。首次请先构建前端（Quick Start 方式 C 的第 2 步），或直接按 [Quick Start](#quick-start) 顺序操作。

探活：`GET http://localhost:8443/health`

提交 Rust 改动前请执行：

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
```

### 3. Dashboard（Vue）

```bash
cd dashboard
pnpm install
pnpm dev          # http://localhost:5173 ，代理到 :8443
# 或构建并嵌入二进制：
pnpm build
cd .. && cargo build -p signet
```

生产/联调时由 Rust 通过 `rust-embed` 托管 `dashboard/dist`（`cargo build` 前需先有该目录）。

### 4. 账号模型

- **无公开注册**；staff 在 **Dashboard → Users**（前端路由 `/users`，API `/api/v1/admin/users`）开户  
- 角色：`admin` / `manager` / `member`（见设计文档）  
- 首次运行经 **`/setup`** 页面创建首位 `admin`  
- 可选 **MFA**（全局或按用户强制）；账户菜单可自愿绑定  
- 可选在 **Integrations** 配置第三方登录；用户可在账户菜单管理已绑定账号  

### 5. 可观测性

- 所有请求响应带 **`x-request-id`**（透传 / 自动生成 UUIDv4），用于链路关联
- 访问日志由 `crates/signet/src/access_log.rs` 统一输出：单行、结构化字段（`request_id` / `method` / `path` / `query` / `ip` / `status` / `latency_ms`），`2xx/3xx` 为 `INFO`，`4xx` 为 `WARN`，`5xx` 为 `ERROR`
- 日志走 `tracing`，规范见 [.cursor/rules/logging.mdc](./.cursor/rules/logging.mdc)：静态消息 + 结构化字段，错误用 `error` 字段，生产（`APP_ENV=production`）输出单行 JSON
- `GET /metrics` 暴露 Prometheus 指标

## 主要端点

| 路径 | 说明 |
|------|------|
| `GET /health` | 探活 |
| `GET /metrics` | Prometheus 指标（公开） |
| `GET /.well-known/openid-configuration` | OIDC Discovery |
| `GET /oauth/authorize` | 授权（未登录跳转 `/login`，未同意跳转 `/consent`） |
| `POST /oauth/token` | 换票（code + PKCE / refresh） |
| `POST /oauth/consent` | 同意页提交 |
| `GET /oauth/jwks` | JWKS |
| `GET /oauth/userinfo` | UserInfo（含 `groups`） |
| `GET/POST /oauth/end_session` | 统一登出 |
| `POST /oauth/revoke` | RFC 7009 吊销 |
| `POST /oauth/register` | RFC 7591 动态客户端注册 |
| `GET /api/v1/setup/status` | 首次部署探测（`needs_setup`） |
| `POST /api/v1/setup` | 首次运行创建首位 admin |
| `POST /api/v1/password-reset/*` | 密码重置（请求/确认） |
| `GET/POST/DELETE /api/v1/me/passkeys/*` | Passkey（WebAuthn）注册/登录/管理 |
| `GET /api/v1/auth/sso/{provider}/start` | 发起第三方登录 |
| `GET /api/v1/auth/sso/{provider}/callback` | 第三方回调（绑定 / 暂存待绑定 / 签发会话） |
| `GET /api/v1/auth/sso/providers` | 公开：已启用的 SSO provider 列表 |
| `GET/DELETE /api/v1/auth/sso/identities/*` | 已绑定第三方账号列表 / 解绑 |
| `/scim/v2/*` | SCIM v2 用户/组同步（Bearer 认证） |
| `/api/v1/*` | Dashboard / 会话 / 管理 API（**统一前缀**，见 [api-v1.md](./docs/api-v1.md)） |

示例：`POST /api/v1/login`、`GET /api/v1/admin/users`、`GET /api/v1/admin/stats`。

## CI 与发布

| Workflow | 触发 | 作用 |
|----------|------|------|
| **CI** | 源码路径的 Push / PR | Dashboard typecheck + build；Rust `fmt` / `clippy` / `test`（依赖 `dashboard/dist`） |
| **Release Signet Binary** | `v*` tag（或手动） | 多架构二进制 → GitHub Release |
| **Build Signet Image** | 二进制发布成功后 | 用已构建的 `linux-amd64` 打运行时镜像 → **ACR** + **Docker Hub**（`${DOCKERHUB_USERNAME}/signet`），并上传 deploy 配置包到 OSS |

发版示例：`git tag -a v0.4.3 -m v0.4.3 && git push origin v0.4.3`。

构建与部署布局见 [`docs/deploy.md`](./docs/deploy.md)。生产编排在 [`deploy/`](./deploy/)（`docker-compose.yml`、`env.tpl`），本地镜像 / Postgres 见 [`build/docker-compose.yml`](./build/docker-compose.yml)
（`docker compose -f build/docker-compose.yml --profile dev up -d db`）。

## 仓库结构

```text
crates/signet/          Axum OIDC IdP + /api/v1（含 federation/）
dashboard/              Vue 3 + Tailwind CSS v4
migrations/             Postgres 迁移（… audit client_id、身份联邦 …）
examples/               axum-oidc-client：业务系统接入 quickstart（可运行）
build/                  Dockerfile + 本地 compose（镜像构建、可选 Postgres）
.github/workflows/      ci.yml · release-binary.yml · build-signet-image.yml
deploy/                 生产 compose + env 模板（OSS 配置包）
docs/                   design · security · client-integration · integrations · api-v1 · mfa · dashboard · directory-sync
```
