# Signet

统一身份认证（SSO / OIDC IdP）服务。

> 语言：简体中文 · [English](./README.md)

- **生产入口（未来）**：`https://sso.example.com`
- **Issuer**：默认 `http://localhost:8443`；公开值在首次登录后于 **Dashboard → Settings → Server identity** 配置。`SIGNET_ISSUER` 可选：仅作为首次保存前的初始值，保存后以数据库值为准
- **首个接入方**：Cella（内网子系统）；客户端统一走通用申请渠道（Dashboard → Clients、自助 **My apps** 或 RFC 7591 动态注册），无内置预置

> 命名说明：本项目为 SSO，**不是**阿里云 Object Storage（OSS）。

## Quick Start

有三种把服务跑起来的方式。**推荐使用 release 二进制**：每个 [GitHub Release](https://github.com/schiplat/signet/releases) 都提供自包含的 `linux-amd64` / `linux-arm64` / `macos-arm64` 可执行文件，Dashboard 已在编译期嵌入——单个文件加一个 PostgreSQL 即可运行，无需 Rust / Node 工具链；数据库迁移也已内置，启动时自动执行。

**方式 A：release 二进制（推荐）**

从 [Releases 页面](https://github.com/schiplat/signet/releases) 下载对应平台产物（`linux-amd64`、`linux-arm64` 或 `macos-arm64`），然后：

```bash
# 1. 将下载的产物重命名为 `signet`
chmod +x signet-<platform> && mv signet-<platform> signet

# 2. 起一个与内置默认连接串一致的 PostgreSQL（signet/signet@127.0.0.1:5433/signet）；已有可跳过
docker run -d --name signet-db -p 5433:5432 \
  -e POSTGRES_USER=signet -e POSTGRES_PASSWORD=signet -e POSTGRES_DB=signet \
  postgres:16-alpine

# 3. 运行 —— 会从工作目录读取 .env（见下方「配置文件」）
./signet
```

**方式 B：Docker 镜像**

每个 release 同步发布多架构运行时镜像（`linux/amd64`、`linux/arm64`）到 Docker Hub + ACR；只拉不建的生产编排见 [`deploy/`](./deploy/)：

```bash
cd deploy
cp ../.env.example .env   # 编辑 SIGNET_*；并设置 SIGNET_IMAGE=<registry>/signet:<tag>
docker compose up -d
```

生产布局（外部 Postgres、密钥卷）详见 [docs/deploy.md](./docs/zh-CN/deploy.md)。

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

三种方式读的是同一套环境变量：二进制从工作目录加载 `.env`，compose 注入同名变量。只有数据库连接串是启动所需——issuer 可以留空，首次登录后再在 Web 端配置。完整带注释的参考见 [.env.example](./.env.example)。

```dotenv
SIGNET_DATABASE_URL=postgres://signet:signet@127.0.0.1:5433/signet
# 可选覆盖项——留空则在 Dashboard 中配置 issuer：
# SIGNET_ISSUER=https://sso.example.com
```

| 配置 | 说明 |
|------|------|
| `SIGNET_DATABASE_URL` | PostgreSQL 连接串（上面的值即内置默认值，与本地 dev `db` 容器一致） |
| `SIGNET_ISSUER` | **可选。** 客户端访问本服务的公开 origin；不能以 `/` 结尾。优先级为 **数据库 > 环境变量 > 内置默认**：在 **Dashboard → Settings → Server identity** 保存的值优先生效（即时应用、首次保存后锁定），环境变量只在首次保存前作为初始值。同页的 **Reset override**（或 `DELETE /api/v1/admin/settings/server`）会清除已保存值并回退到环境变量。生效 issuer 为 https 时自动启用 `Secure` Cookie |
| `SIGNET_HTTP_BIND` | HTTP 监听地址；默认 `0.0.0.0:8443` |
| `SIGNET_TRUSTED_PROXIES` | 仅反向代理后需要：允许断言 `X-Forwarded-For` 的代理 IP/CIDR，逗号分隔 |
| 密钥 | `./data/jwt_private.pem` 与 `./data/encryption.key` 首次启动自动生成——**务必备份**：丢失或轮换会使已签发 token 失效、已存 TOTP 无法解密 |

运维策略（会话与 token 有效期、登录尝试与锁定、密码长度/历史、审计保留、全局限流）可在 **Dashboard → Settings → Runtime policies** 在线修改，无需重启或改 `.env`；同名 `SIGNET_*` 变量只是"尚未在后台保存过"字段的兜底（界面会标注哪些仍继承自环境）。

首位管理员**不**通过配置文件创建：首次启动时 Dashboard 会跳转 `/setup` 创建。

### 首次运行

打开 **http://localhost:8443** —— 首次访问自动跳转 **`/setup`**，创建第一个管理员并登录。

**体验 SSO：** 在 **Dashboard → Clients**（staff）注册一个客户端（secret 只展示一次，弹窗里就是可直接复制给子系统的 `.env` / `config.toml` 片段；任何登录用户也可在 **Dashboard → My apps** 自助注册）。然后在 Clients 列表里点 **Test drive**：新标签页走完真实的 authorize → 登录 → consent → 回调，验证整条链路。

**（可选）示例客户端**，五分钟跑通端到端登录：

```bash
cd examples/axum-oidc-client
export OIDC_ISSUER=http://localhost:8443 OIDC_CLIENT_ID=<上面的 id> OIDC_CLIENT_SECRET=<上面的 secret>
cargo run
# 打开 http://127.0.0.1:3000 → Sign in → SSO 登录成功
```

前端热更新开发（`:5173` 代理 `:8443`）见 [docs/local-development.md](./docs/zh-CN/local-development.md)。业务系统接入文档见 [docs/client-integration.md](./docs/zh-CN/client-integration.md)。

## 功能概览

- OIDC IdP：authorize / token / PKCE / refresh / userinfo / JWKS / end_session / revoke
- Dashboard：合并的 **Directory**（用户 + 组织树）、客户端、审计、总览统计（可按 client 过滤）、MFA、Passkey、Webhook、SCIM
- **组/部门组织树**：Dashboard → Directory 管理一棵 `department` / `group` 树，含成员、移动、改名与防环校验；OIDC `groups` claim 只下发直接组名。SCIM/目录同步的节点会出现在树里，但名称与成员仍归来源管理
- **客户端自助注册**：任何登录用户可在 Dashboard → My apps 注册并管理自己的应用（应用名 + 回调地址），按 owner 隔离、secret 只显示一次；管理员仍可全局管理（Name / Owner 列）
- **Issuer 可在 Web 端配置**：Dashboard → Settings → Server identity（**DB > `SIGNET_ISSUER`**，审计 + 首次保存后锁定；**Reset override** 回退到环境变量/默认）。**Settings 改为左侧子导航**（General / Access / Operations / Developer），当前分区记录在 `?section=`，刷新与分享链接保持同一分区
- **品牌定制**：产品名 + **Logo 上传**（PNG/JPEG/WebP ≤256 KB，拒绝 SVG），应用于侧栏、登录、初始化、重置与同意页，无需重新部署
- **公开注册（默认关闭）**：Settings → Public sign-up，需先配置 SMTP 与 CAPTCHA 才能开启。提交申请不建号，点击 30 分钟单次邮件链接后才创建普通 `member`（无分组）；只有开启后登录页才显示 **Create account**
- **首次使用引导**：Overview 为管理员展示实时检查面板（issuer 可达性/HTTPS、SMTP 完整性、首个启用客户端），必填步骤未通过前不可关闭
- **运行时策略**（token/会话有效期、登录锁定、密码策略、审计保留、限流）在后台修改，落库即生效，无需重新部署
- **签名密钥轮换**（`signet keys rotate` / `keys prune`），JWKS 同时发布新旧公钥，已签发 token 不受影响
- **第三方登录**（身份联邦）：GitHub · Google · 飞书 · 微信开放平台 · 通用 OIDC  
  绑定：上游已验证邮箱匹配本地账号 → 自动绑定；否则按 JIT 策略（全局 Settings 开关 + **每个 provider 可独立覆盖** `jit_mode`，并可单独配置 email 可信级别 `email_trust`）**JIT 创建** `member` 并登录；再否则暂存 15 分钟待密码绑定。本地 MFA / 强制改密策略对第三方登录同样生效。详见 [docs/api-v1.md §12](./docs/zh-CN/api-v1.md#12-第三方登录身份联邦)

![Dashboard 总览](./docs/screenshot_overview.png)

## 文档

| 文档 | 内容 |
|------|------|
| [docs/zh-CN/README.md](./docs/zh-CN/README.md) | **文档目录**（从这里开始） |
| [docs/design.md](./docs/zh-CN/design.md) | 总体设计、角色、安全、部署拓扑 |
| [docs/security.md](./docs/zh-CN/security.md) | **安全设计汇总**（凭证存储、认证、会话、MFA、OIDC、审计、密钥） |
| [docs/client-integration.md](./docs/zh-CN/client-integration.md) | **业务客户端 OIDC 对接**（authorize/token/PKCE/IP 白名单） |
| [docs/integrations.md](./docs/zh-CN/integrations.md) | **集成对接**（RFC 7591 动态注册 · Webhooks/飞书 · SCIM v2） |
| [docs/api-v1.md](./docs/zh-CN/api-v1.md) | **Dashboard HTTP API**（统一 `/api/v1/...`，含第三方登录） |
| [docs/mfa.md](./docs/zh-CN/mfa.md) | TOTP / 恢复码 / 全局与用户强制策略 |
| [docs/dashboard.md](./docs/zh-CN/dashboard.md) | 管理台页面与权限说明 |
| [docs/groups.md](./docs/zh-CN/groups.md) | **组与部门**（组织树、成员、来源归属、API、claim 语义） |
| [docs/directory-sync.md](./docs/zh-CN/directory-sync.md) | **目录同步**（LDAP / HTTP JSON 拉取、bind 直通、定时调度、`signet sync` CLI） |
| [docs/directory-mapping-ux.md](./docs/directory-mapping-ux.md) | 目录同步字段映射交互设计（含实现记录） |
| [docs/deploy.md](./docs/zh-CN/deploy.md) | **build/ 与 deploy/**（Dockerfile、本地与生产 compose、`/app/data` 密钥） |
| [CHANGELOG.md](./CHANGELOG.md) | 版本变更与破坏性改动 |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | 开发流程、提交规范与本地检查 |
| [SECURITY.md](./SECURITY.md) | 漏洞报告与安全模型 |

英文文档在 [docs/](./docs/)（源版本）；本目录的中文版随版本更新可能滞后。

## 本地开发

完整开发环境说明——配置、后端、Dashboard 热更新、账号模型与可观测性——见
**[docs/local-development.md](./docs/zh-CN/local-development.md)**。

最短流程：启动 Postgres，构建 Dashboard（`cd dashboard && pnpm build`，编译期会嵌入二进制），然后 `cargo run -p signet`，监听 `:8443`。

## 接口

Signet 对外有四个接口面，完整说明见 `docs/`：

| 接口面 | 前缀 | 参考 |
|---|---|---|
| OIDC 协议 | `/oauth/*`、`/.well-known/openid-configuration` | [docs/client-integration.md](./docs/zh-CN/client-integration.md) |
| Dashboard / 管理 API | `/api/v1/*`——会话 Cookie；自动化可用 `Authorization: Bearer` admin API token | [docs/api-v1.md](./docs/zh-CN/api-v1.md) |
| SCIM v2 | `/scim/v2/*`——bearer token | [docs/integrations.md](./docs/zh-CN/integrations.md) |
| 运维 | `GET /health`；`GET /metrics`（独立 loopback 监听） | [docs/security.md](./docs/zh-CN/security.md#63-可观测) |

## CI 与发布

| Workflow | 触发 | 作用 |
|----------|------|------|
| **CI** | 源码路径的 Push / PR | Dashboard typecheck + build + 运行时依赖审计；Rust `fmt` / `clippy`（测试在本地推送前跑） |
| **Release Signet Binary** | `v*` tag（或手动） | 多架构二进制 → GitHub Release |
| **Build Signet Image** | 二进制发布成功后 | 用已构建的二进制打多架构运行时镜像（`linux/amd64`、`linux/arm64`）→ **ACR** + **Docker Hub**（`${DOCKERHUB_USERNAME}/signet`） |

发版示例：`git tag -a v0.6.2 -m v0.6.2 && git push origin v0.6.2`。

构建与部署布局见 [`docs/deploy.md`](./docs/zh-CN/deploy.md)。生产编排在 [`deploy/`](./deploy/)（`docker-compose.yml`），本地镜像 / Postgres 见 [`build/docker-compose.yml`](./build/docker-compose.yml)
（`docker compose -f build/docker-compose.yml --profile dev up -d db`）。


## 贡献

欢迎贡献。前置条件、分支与 PR 流程、提交信息规范以及 CI 会跑的检查见
[CONTRIBUTING.md](./CONTRIBUTING.md)。

- 本地环境搭建见 [docs/local-development.md](./docs/zh-CN/local-development.md)。
- 推送前请在本地跑完检查：`cargo fmt --all -- --check`、
  `cargo clippy --workspace --all-targets -- -D warnings`、`cargo test`；
  `dashboard/` 下执行 `pnpm typecheck && pnpm build`。
- 行为变化时同步更新 `docs/` 下对应页面：英文册是源版本，需与
  `docs/zh-CN/` 中文册保持一致。

## 安全

**请勿为安全漏洞开公开 issue**。按 [SECURITY.md](./SECURITY.md) 私下报告
（邮箱 **info@open.schiplat.com**），我们会在 3 个工作日内确认。安全模型与
实现说明见 [docs/zh-CN/security.md](./docs/zh-CN/security.md)。

## 仓库结构

```text
crates/signet/          Axum OIDC IdP + /api/v1（含 federation/）
dashboard/              Vue 3 + Tailwind CSS v4
migrations/             Postgres 迁移（… audit client_id、身份联邦 …）
examples/               axum-oidc-client：业务系统接入 quickstart（可运行）
build/                  Dockerfile + 本地 compose（镜像构建、可选 Postgres）
.github/workflows/      ci.yml · release-binary.yml · build-signet-image.yml
deploy/                 生产 compose（只拉镜像）
docs/                   design · security · client-integration · integrations · api-v1 · mfa · dashboard · groups · directory-sync（英文源文档）
docs/zh-CN/             上述文档的中文译本
```
