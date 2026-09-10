# Signet

统一身份认证（SSO / OIDC IdP）服务。

> 语言：简体中文 · [English](./README.md)

- **生产入口（未来）**：`https://sso.example.com`
- **开发默认 Issuer**：`http://localhost:8443`（`SIGNET_ISSUER` 可配）
- **首个接入方**：Cella（内网子系统）；客户端统一走通用申请渠道（Dashboard → Clients 或 RFC 7591 动态注册），无内置预置

> 命名说明：本项目为 SSO，**不是**阿里云 Object Storage（OSS）。

## 功能概览

- OIDC IdP：authorize / token / PKCE / refresh / userinfo / JWKS / end_session / revoke
- Dashboard：用户、客户端、审计、总览统计（可按 client 过滤）、MFA、Passkey、Webhook、SCIM
- **第三方登录**（身份联邦）：GitHub · Google · 飞书 · 微信开放平台 · 通用 OIDC  
  绑定策略（防接管）：上游已验证邮箱与本地账号匹配 → 自动绑定；否则暂存待绑定身份（15 分钟），用户接着用密码 / MFA / Passkey 登录本地账号后自动完成绑定。详见 [docs/api-v1.md §12](./docs/api-v1.md#12-第三方登录身份联邦)

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

生产编排见 [`deploy/`](./deploy/)（`docker-compose.yml`、`env.tpl`）。

## 仓库结构

```text
crates/signet/          Axum OIDC IdP + /api/v1（含 federation/）
dashboard/              Vue 3 + Tailwind CSS v4
migrations/             Postgres 迁移（… audit client_id、身份联邦 …）
build/Dockerfile.runtime  运行时镜像（拷贝预编译二进制，不再编译）
.github/workflows/      ci.yml · release-binary.yml · build-signet-image.yml
deploy/                 生产 compose + env 模板
docs/                   design · security · client-integration · integrations · api-v1 · mfa · dashboard
```
