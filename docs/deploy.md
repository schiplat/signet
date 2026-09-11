# 构建与部署布局

Signet 把「造镜像」和「跑生产」拆在两个目录，避免根目录堆多个 compose。

| 目录 | 职责 |
|------|------|
| [`build/`](../build/) | Dockerfile + **本地** compose（可选 Postgres） |
| [`deploy/`](../deploy/) | **生产** compose（只拉镜像）+ `env.tpl`（Buz / OSS 配置包） |

日常开发仍以 `cargo run` + `pnpm dev` 为主；下面两套 compose 面向容器化联调与上线。

---

## 1. `build/` — 镜像与本地编排

| 文件 | 作用 |
|------|------|
| `Dockerfile` | 多阶段：构建 Dashboard → 编译 `signet` → 精简运行时镜像 |
| `Dockerfile.runtime` | CI 用：拷贝已发布的二进制，不在镜像里编译 |
| `docker-compose.yml` | 本地：用 `Dockerfile` 构建 `signet`；`--profile dev` 可选起 Postgres |

在**仓库根目录**执行：

```bash
# 仅本地 Postgres（宿主机端口 5433，库/用户/密码均为 signet）
docker compose -f build/docker-compose.yml --profile dev up -d db

# 构建并启动应用镜像（需仓库根目录 .env，含 SIGNET_DATABASE_URL）
docker compose -f build/docker-compose.yml up -d --build
```

`signet` 服务的 build context 是仓库根；`env_file` 指向 `../.env`。数据卷 `signet_data` 挂到容器内 `/app/data`（JWT / 加密密钥，见下）。

发版流水线（`build-signet-image.yml`）使用 `build/Dockerfile.runtime`，把 GitHub Release 里的 `linux-amd64` 二进制打进运行时镜像并推送到 ACR / Docker Hub。

---

## 2. `deploy/` — 生产编排

| 文件 | 作用 |
|------|------|
| `docker-compose.yml` | **只 pull** 镜像，不 build；加入外部网络 `manager-net` |
| `env.tpl` | Buz 渲染成 `deploy/.env` 的模板（`${secrets.*}` / `${vars.*}`） |

生产不在本 stack 内起数据库：连接已有 Postgres（由 `SIGNET_POSTGRES_*` 拼出 URL，主机名为 `manager-net` 上的 `postgres`）。

```bash
cd deploy
# 本地试跑可用 .env.example 拷贝；线上由 Buz 从 OSS 下发 env.tpl 再渲染
cp ../.env.example .env   # 仅临时
docker compose pull
docker compose up -d
```

CI 打包配置：

```text
tar czf configs.tar.gz -C deploy docker-compose.yml env.tpl
→ OSS config_tpl/signet/<tag>/configs.tar.gz
```

因此 **`deploy/docker-compose.yml` 与 `env.tpl` 的路径/文件名不要随意改名**，否则 Buz 解包约定会断。

首次部署：打开 Issuer URL，Dashboard 跳转 `/setup` 创建首位管理员。

---

## 3. 密钥目录 `/app/data`

容器（以及本地默认路径 `./data/`）持久化两份密钥：

| 文件 | 用途 |
|------|------|
| `jwt_private.pem` | RS256，签发 / 校验 OIDC JWT |
| `encryption.key` | AES-256-GCM，加密落库敏感字段（如 TOTP secret） |

- 首次启动若不存在则自动生成。
- 生产挂载 Docker volume `signet_data` → `/app/data`；**丢失或轮换会使已发 token 失效、已存 TOTP 无法解密**。
- 仓库里的 `./data/` 仅本地产物，不随镜像分发。详见 [security.md §7](./security.md#7-密钥与配置)。

---

## 4. 和日常开发的关系

| 场景 | 推荐方式 |
|------|----------|
| 改 Rust / Dashboard 代码 | `cargo run -p signet` + `dashboard/` 下 `pnpm dev` |
| 需要容器化 Postgres | `build/docker-compose.yml` 的 `db` profile |
| 验证完整镜像 | `build/docker-compose.yml` 的 `signet` 服务 `--build` |
| 上线 / gz4 等环境 | `deploy/` + 镜像 tag + 渲染后的 `.env` |
