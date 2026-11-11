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

> **多实例共库必须共享同一把 `encryption.key`**：TOTP secret、webhook secret 都是按该 key 的 AES-GCM 密文落库。两个实例指向同一数据库但各持一把 key 时，会互相写出对方解不开的密文（症状：在实例 A 登记的 TOTP 在实例 B 报 base32 解码失败）。生产 compose 通过共享 `signet_data` volume 天然满足；自行分拆部署时务必让所有实例的 `SIGNET_ENCRYPTION_KEY_PATH` 指向同一份内容。启动时会把 key 指纹写入 `app_settings`（`crypto.encryption_key_fingerprint`）并校验，不一致直接拒绝启动——确属有意重新起 key 时，删除该行可重新武装检查（旧密文仍需自行处理）。`jwt_private.pem` 无此约束：各实例可用各自密钥签发（issuer 不同即可），JWKS 按 issuer 分发。

---

## 4. 容器内执行目录同步 CLI

`signet sync …` 复用与 server 相同的 `build_state`，因此它**不是**一个轻量客户端：启动时会连库、跑迁移、加载（必要时**生成**）`jwt_private.pem` 与 `encryption.key`、重加密 webhook secret，并修剪审计日志。

```bash
# 在目标容器内执行，工作目录与 server 一致，env / 密钥卷完全相同
docker compose -f deploy/docker-compose.yml exec signet \
  signet sync sources

docker compose -f deploy/docker-compose.yml exec signet \
  signet sync run --source corp-ldap --dry-run
```

要点：

- **必须在 server 容器内执行**（或至少保证 `SIGNET_DATABASE_URL` 与 `SIGNET_ENCRYPTION_KEY_PATH` 指向同一份）。在别处用不同密钥路径执行，会在当前目录生成一份**新**密钥文件，然后因解不开已有密文而失败——即使侥幸通过，也会留下与 server 不一致的密钥产物。
- 容器内 cwd 固定为 `/app`、env 由 compose 的 `env_file` 注入（镜像里没有 `.env`），密钥卷挂在 `/app/data`，三点都与 server 一致——所以用 `exec` 即可，不要自己拼环境变量。
- 在宿主机直接跑二进制时，`dotenvy` 会读**当前工作目录**的 `.env`；务必先 `cd` 到放 env 的目录，否则会静默退回内置默认值（例如默认 DB、默认 `./data/` 密钥路径）。
- 日志走 stdout，管道消费需 `RUST_LOG=off`：

```bash
docker compose -f deploy/docker-compose.yml exec -T signet \
  env RUST_LOG=off signet sync sources --json | jq -r '.[].code'
```

- 与调度器/手动触发并发时由迁移 `025` 的单运行唯一索引兜底，后来者报 `another sync run for this source is already in progress`。
- 完整命令、输出、退出码与 `--dry-run` 语义见 [directory-sync.md §9](./directory-sync.md#9-命令行)。

---

## 4.5 签名密钥轮换

`signet keys rotate` 生成新密钥、把旧密钥的**公钥**写入 `SIGNET_JWT_RETIRED_KEY_DIR`（默认 `./data/retired_keys`），并原子替换 `SIGNET_JWT_PRIVATE_KEY_PATH`。重启后：

- 新签发的 access/id token 用新 `kid` 签名；
- 旧密钥签发的 token 仍能验签，直到自然过期（JWKS 同时发布两把公钥，客户端按 `kid` 跟随）；
- 旧私钥不再保留（只写公钥），轮换后的私钥暴露面不增加。

```bash
# 容器内（数据卷 /app/data 持久化两处路径）
docker compose -f deploy/docker-compose.yml exec -T signet signet keys rotate
docker compose -f deploy/docker-compose.yml restart signet
curl -s https://<issuer>/.well-known/jwks.json | jq '.keys[].kid'   # 应看到新旧两把
```

可以重复执行：每次都会把当前密钥退役、生成新密钥；退役目录按 `kid` 命名，重复轮换的旧公钥幂等覆盖。

退役目录不会自动清理（公钥，无泄露风险）。确认旧 token 已过期后可收缩：

```bash
signet keys prune --keep 3   # 只保留最近 3 把退役公钥
```

---

## 4.6 支持的部署拓扑：单活动实例

Signet 当前按**单活动实例**设计与验证：三块进程内状态——限流桶、passkey 挑战存储、
运行时设置快照（后两者中挑战已落库的除外）——不做跨副本共享。多副本负载均衡下
会出现：限流预算按副本数放大、passkey 登录在无粘性会话时必失败、设置变更最长
30 秒才被其他副本读到（其余所有状态——会话、SCIM、审计、同步互斥——都在数据库，
天然多副本安全）。

运行时设置已内置 30 秒后台重读：跨副本传播上限即该间隔；`signet keys rotate`
仍需逐副本重启加载密钥环。需要水平扩展时，先做挑战/限流的共享存储设计再上副本，
不要直接挂 LB。

两处"进程内状态"是有意的取舍，不是疏忽：

- **passkey 仪式状态**留在内存。上游 `webauthn-rs` 把该状态的序列化放在
  `danger-allow-state-serialisation` 特性后并明确警告不要使用——把 CeremonyState
  落库需要开启这个"danger"开关，违背 fail-closed 原则。多副本 passkey 登录需要
  LB 粘性会话，或等上游提供受支持的状态导出。
- **限流桶**留在内存。共享存储（DB 计数/Redis）可用但引入新依赖或每请求写放大，
  单实例下毫无收益。

---

## 5. 和日常开发的关系

| 场景 | 推荐方式 |
|------|----------|
| 改 Rust / Dashboard 代码 | `cargo run -p signet` + `dashboard/` 下 `pnpm dev` |
| 需要容器化 Postgres | `build/docker-compose.yml` 的 `db` profile |
| 验证完整镜像 | `build/docker-compose.yml` 的 `signet` 服务 `--build` |
| 跑目录同步 CLI | 本机 `cargo run -p signet -- sync …`；线上见 [§4](#4-容器内执行目录同步-cli) |
| 上线 / gz4 等环境 | `deploy/` + 镜像 tag + 渲染后的 `.env` |
