# Signet MFA（TOTP + 恢复码）

| 项 | 内容 |
|---|---|
| 方式 | TOTP（RFC 6238，SHA1 / 30s / 6 位） |
| 恢复 | 10 个一次性恢复码（argon2 存储） |
| TOTP 密钥 | `totp_secret` 以 AES-256-GCM 应用层加密后落库（明文不再存库）；待确认的种子同样加密 |
| 防重放 | 每个 30 秒时间步只接受一次（`users.totp_last_step` 严格前进）；时钟回跳超过 10 分钟视为校时而非重放 |
| 猜测限制 | 单个 challenge 最多 5 次失败，达上限即作废；失败不写账户锁定计数（密码正确时本就不计） |
| 强制策略 | 全局开关 + 用户级开关（均可关） |
| Settings UI | `/settings`，**仅 admin** |
| API 前缀 | `/api/v1/...`（见 [api-v1.md](./api-v1.md)） |
| UI 说明 | [dashboard.md](./dashboard.md) |

---

## 1. 强制策略

| 开关 | 存储 | 谁改 | 默认 |
|------|------|------|------|
| 全局 `mfa.required_globally` | `app_settings` | admin | `false` |
| 用户 `users.mfa_required` | users | admin / manager | `false` |
| 绑定事实 `users.totp_enabled` | users | 用户绑定 / admin reset | `false` |

登录分支：

```text
if totp_enabled:
    → 始终二次校验（与开关无关）
else if global_required OR user.mfa_required:
    → 强制 enroll
else:
    → 密码直登；可在账户菜单自愿绑定
```

关闭强制开关**不会**自动解绑；解绑途径：

- **用户自主禁用**（`POST /api/v1/me/mfa/disable`）：仅当**全局与用户级强制均未开启**时允许，需验证当前 TOTP 码；
- admin **Reset 2FA**：清空该用户绑定；
- 用户**换绑**（rebind）流程。

若全局强制或该用户 `mfa_required` 开启，用户侧「Disable MFA」不可用（返回 `400 MFA is required by policy and cannot be disabled`）。

---

## 2. 会话模型

需要 MFA 时，密码通过后**不**签发 `signet_session`，只签发短时 `signet_mfa` challenge（约 10 分钟）。  
verify / enroll confirm 成功后签发正式会话并清除 challenge。

OIDC `/oauth/authorize` 仅接受正式会话。

---

## 3. 权限

| 能力 | admin | manager | member |
|------|-------|---------|--------|
| Settings 全局 MFA 开关 | 读写 | 无 | 无 |
| 用户 `mfa_required` | 读写 | 读写 | 无 |
| Reset 他人 2FA | 是 | 否 | 否 |
| 本人绑定 / 换绑 / 恢复码 | 是 | 是 | 是 |

---

## 4. API（摘要）

| 端点 | 说明 |
|------|------|
| `GET/PATCH /api/v1/admin/settings/mfa` | admin：全局开关 |
| `POST /api/v1/login` | `ok` / `mfa_required` / `enroll_required` |
| `POST /api/v1/mfa/verify` | TOTP 或恢复码 |
| `POST /api/v1/mfa/enroll/start\|confirm` | 强制 enroll（challenge） |
| `GET /api/v1/me/mfa` | 状态与剩余恢复码 |
| `POST /api/v1/me/mfa/enroll/start\|confirm` | 已登录自愿绑定 |
| `POST /api/v1/me/mfa/recovery/regenerate` | 轮换恢复码（需 TOTP） |
| `POST /api/v1/me/mfa/rebind/start\|confirm` | 换绑 |
| `POST /api/v1/me/mfa/disable` | 用户自主禁用（需当前 TOTP；强制时禁止，body `{ code }`） |
| `POST /api/v1/admin/users/:id/mfa/reset` | admin 清绑定 |

---

## 5. 审计动作

`mfa.verify`、`mfa.enroll`、`mfa.recovery_use`、`mfa.recovery_regen`、`mfa.rebind`、`mfa.reset`、`mfa.disable`、`settings.mfa_update`  
（`mfa.reset` / `settings.mfa_update` 仅 admin 审计列表可见。）

---

## 6. UI

- Login：密码 → 验码 / 强制绑定 + 一次性恢复码展示  
- 恢复码一次性展示页提供 **Copy** 与 **Download**（`signet-recovery-codes.txt`），重绑/轮换后同样可下载  
- TopNav：Two-factor auth（全角色），含状态、剩余恢复码，以及**禁用 MFA**（仅非强制时可见）  
- Users：Require MFA；**MFA 状态列**（Enabled / Required / Off）；Reset 2FA（admin）  
- Settings：全局 Require MFA（admin only）  
