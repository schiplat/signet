# 本地开发

> [English](../local-development.md) · 简体中文

搭建开发环境并从源码运行 Signet。容器方式见 [Quick Start](../../README.zh-CN.md#quick-start)，部署见 [deploy.md](./deploy.md)。

## 1. 配置

```bash
cp .env.example .env
# 编辑 SIGNET_DATABASE_URL 等
```

首次启动且库中无管理员时，在浏览器打开 Dashboard，会自动跳转到 **`/setup`** 页面，创建首位管理员账户（邮箱、可选显示名）与密码。

## 2. 后端

```bash
cargo run -p signet
```

> 注意：二进制在编译期嵌入 `dashboard/dist`（rust-embed），该目录不存在会编译失败。首次请先构建前端（第 3 步），或按 [Quick Start](../../README.zh-CN.md#quick-start) 方式 C 的顺序操作。

探活：`GET http://localhost:8443/health`

提交 Rust 改动前请执行：

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

## 3. Dashboard（Vue）

```bash
cd dashboard
pnpm install
pnpm dev          # http://localhost:5173 ，代理到 :8443
# 或构建并嵌入二进制：
pnpm build
cd .. && cargo build -p signet
```

生产/联调时由 Rust 通过 `rust-embed` 托管 `dashboard/dist`（`cargo build` 前需先有该目录）。

## 4. 账号模型

- **无公开注册**；staff 在 **Dashboard → Directory**（前端路由 `/directory`，API
  `/api/v1/admin/users`）开户
- 角色：`admin` / `manager` / `member`（见 [design.md](./design.md)）
- 首次运行经 **`/setup`** 页面创建首位 `admin`
- 可选 **MFA**（全局或按用户强制）；账户菜单可自愿绑定
- 可选在 **Integrations** 配置第三方登录；用户可在账户菜单管理已绑定账号

## 5. 可观测性

- 所有请求响应带 **`x-request-id`**（透传 / 自动生成 UUIDv4），用于链路关联
- 访问日志由 `crates/signet/src/http/access_log.rs` 统一输出：单行、结构化字段（`request_id` / `method` / `path` / `query` / `ip` / `status` / `latency_ms`），`2xx/3xx` 为 `INFO`，`4xx` 为 `WARN`，`5xx` 为 `ERROR`
- 日志走 `tracing`，规范见 [.cursor/rules/logging.mdc](../../.cursor/rules/logging.mdc)：静态消息 + 结构化字段，错误用 `error` 字段，生产（`APP_ENV=production`）输出单行 JSON
- `GET /metrics` 在**独立监听**上暴露 Prometheus 指标（默认仅回环，`SIGNET_METRICS_BIND` 可改/关），不在公开 API 端口
