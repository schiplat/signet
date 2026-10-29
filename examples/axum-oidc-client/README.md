# Signet quickstart 客户端（Axum）

一个**可运行**的 OIDC 接入参考实现，对应 [client-integration.md](../../docs/client-integration.md) 的全部要求：Discovery、PKCE S256、state/nonce、code 换票、id_token 校验（RS256 + JWKS + iss/aud/exp/nonce）、按 `sub` 本地建用户、自有会话、RP-Initiated 登出。全部代码在一个 `src/main.rs` 里（约 500 行，含注释）。

新子系统接入的最短路径：**复制本目录 → 改 5 个环境变量 → 跑通 → 再按需替换内存存储为你的数据库**。

## 1. 在 Signet 侧注册客户端

管理员在 **Dashboard → Clients** 创建（或走 RFC 7591 动态注册）：

| 项 | 开发值 |
|----|--------|
| redirect_uris | `http://127.0.0.1:3000/auth/callback` |
| post_logout_redirect_uris | `http://127.0.0.1:3000/signed-out` |
| scopes | `openid profile email`（按需加 `groups` / `phone`） |
| Source IP 白名单 | 本机联调可直接关闭；开启则需包含你的出口 IP |

`client_secret` 只展示一次，立即保存。

## 2. 运行

```bash
cd examples/axum-oidc-client

export OIDC_ISSUER=http://localhost:8443
export OIDC_CLIENT_ID=quickstart
export OIDC_CLIENT_SECRET=...          # 第 1 步拿到的一次性 secret

cargo run
# 打开 http://127.0.0.1:3000 ，点 Sign in
```

可选环境变量（均有默认值）：

| 变量 | 默认 | 说明 |
|------|------|------|
| `OIDC_REDIRECT_URI` | `http://127.0.0.1:3000/auth/callback` | 必须与登记值**逐字符一致** |
| `OIDC_SCOPES` | `openid profile email` | 必须是客户端登记 scopes 的子集 |
| `OIDC_POST_LOGOUT_REDIRECT_URI` | `http://127.0.0.1:3000/signed-out` | 必须也在 Signet 白名单内 |
| `BIND` | `127.0.0.1:3000` | 本服务监听地址 |

## 3. 生产化清单（示例未覆盖的部分）

- [ ] `users` 表入库，以 `sub` 为唯一键（示例用内存 map，重启即失）
- [ ] 会话改为签名/加密 cookie 或服务端 session 表
- [ ] `client_secret` 从密钥管理系统读取，不进环境文件仓库
- [ ] 生产 HTTPS（`Secure` cookie 会随 `OIDC_ISSUER` 为 https 自动开启）
- [ ] 服务器时钟同步（id_token 校验依赖 `exp`/`iat`，jsonwebtoken 自带 60s 容忍）
- [ ] 需要用户组做初始授权时：authorize scope 加 `groups`，从 id_token/userinfo 读 `groups` claim

## 4. 非 Rust 子系统

无法复用本示例时，按语言选标准库并对照 `docs/client-integration.md` 的清单走查：

| 语言/框架 | 常用库 |
|-----------|--------|
| Java / Spring | `spring-security-oauth2-client` |
| Python | `authlib`（Flask/Django/FastAPI） |
| Node.js | `openid-client` + `express` |
| Go | `go-oidc`（github.com/coreos/go-oidc） |

要点都一样：只依赖 Issuer + Discovery；PKCE S256；`state` 必填；回调验 `state` → 换票 → 验 `id_token`（含 `nonce`）→ 按 `sub` 建本地会话；登出走 `end_session_endpoint` + 白名单内的 `post_logout_redirect_uri`。
