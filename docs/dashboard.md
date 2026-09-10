# Signet Dashboard（管理台）

Vue 3 + Vite + Tailwind CSS v4，构建产物嵌入 Rust（`rust-embed`）。  
开发：`dashboard/` 下 `pnpm dev`（代理 `/api` → `:8443`）。

相关：[api-v1.md](./api-v1.md) · [mfa.md](./mfa.md) · [client-integration.md](./client-integration.md)

---

## 1. 角色与导航

| 角色 | 可见区域 |
|------|----------|
| `admin` | Activity、Overview、Users、Clients、Audit logs、**Settings** |
| `manager` | Activity、Overview、Users、Clients、Audit logs（无 Settings；审计不含删除类） |
| `member` | Activity；账户菜单（资料 / 密码 / 2FA / 会话） |

`Activity` 对所有角色可见（`/activity`）：非 staff 登录后默认落到该页，展示个人安全摘要 + 当前用户自己的登录与账号/安全操作记录。

路由守卫：`meta.staff` / `meta.admin`。

---

## 2. 页面能力

### Activity（通用）

- 顶部**个人安全摘要卡**：上次登录（时间 + 浏览器/系统）、活跃会话数、2FA 状态 + passkey 数量、已授权应用数
- 下方为当前用户自己的登录与账号/安全操作记录（`GET /api/v1/me/activity`，按 `actor_user_id` 过滤，所有角色可用，响应含 `summary`）
- 分页浏览，含 IP / 浏览器 / 系统与时间；空状态给出提示
- 定位为「个人视角」，与 Overview 的「全局运营视角」区分

### Overview

- 用户 / 角色 / 客户端汇总（全局统计卡）
- **应用筛选器**：右上角可选全部应用 / 某个接入应用 / `Signet (direct)`（无应用归属的直登）；选中后登录合计、趋势图、最近登录与下方分布图均切换为该应用视角
- **登录趋势**：近 30 日一张图叠加 **当日 / 7 日滚动 / 30 日滚动** 登录次数；右上角仍显示当前 24h·7d·30d 合计
- **Logins by app**：近 30 天各应用登录次数对比图（Top 10 横向条形；`(direct)` 归并展示）
- **Browsers / OS**：近 30 天登录事件的浏览器与操作系统分布图
- 登录明细统一在 **Audit logs** 查看（Overview 不再内嵌最近登录列表，避免与 Audit logs / Activity 重复）

### Users

- 列表排序、搜索、分页  
- 冻结行视觉标注（Frozen）  
- 列表含 **Phone** 列（新建/编辑可填联系电话，选填；当前仅作联系信息，未做短信验证绑定）  
- 列表含 **MFA 状态列**：`Enabled`（已绑定 TOTP）/ `Required`（策略强制、尚未绑定）/ `Off`  
- 列表含 **SSO 列**：`SSO origin`（`provisioned_via=sso_jit`，第三方 JIT 开户）+ 已绑定 provider 名称徽章；无密码且已绑定时附带 `SSO-only`  
- 操作：Edit / Freeze·Unfreeze / **Revoke sessions**；**Delete**、**Reset 2FA** 仅 admin  
- Edit：角色、状态、**Require MFA**、**Groups**、**Phone**、密码等  
- 新建/编辑时邮箱与手机均实时查重，命中重复时提示并禁用提交  
- 批量 Freeze selected  

### Clients

- 注册 / Edit / Enable·Disable / Rotate secret；Delete 仅 admin  
- Disabled 行视觉标注  
- **Source IP**：默认新建开启白名单；可关闭为 Unrestricted；Edit 可改 CIDR 列表  

### Audit logs

- 搜索（含 IP）、action / 应用（App）/ 浏览器 / OS 过滤、列排序（含 **Login IP**）  
- 展示 actor、IP、应用（`client_id` 徽标）、浏览器/OS（**Device** 列）、action、resource  
- **点击任意行**查看事件详情（含应用、完整 detail JSON 与 User-Agent）  
- **Export CSV**：导出当前过滤结果的 CSV（含 `client_id` 列）  

### Settings（admin only）

- Security：全局 **Require MFA for all users**
- SSO / federation：**JIT provision on SSO**（首次第三方登录且已验证邮箱无本地用户时是否自动开户）

### Integrations（admin only）

- Webhooks：列出 / 新建 / 删除，类型可选 **飞书（Feishu）** 或 **Generic**，可查看最近投递状态
- **Third-party sign-in**：GitHub / Google / 飞书 / 微信开放平台 / 通用 OIDC 连接器的增删改查与启用禁用；展示各 provider 需注册的 **Callback URL** 与绑定账号数；编辑时 secret 留空表示保持不变（不回显）
- SCIM v2：展示启用状态与端点，并支持 **生成 / 轮换 / 吊销** Bearer token（明文仅展示一次，库中只存哈希）
- WebAuthn：展示 RP ID / RP Origin

### 账户菜单（右上角，全角色）

- Edit profile / Change password / **Two-factor auth** / **Active sessions** / **Passkeys** / **Linked accounts** / Log out  
- Two-factor auth：绑定 / 换绑 / 轮换恢复码；非强制时可 **Disable MFA**（强制时显示策略提示且不可禁用）  
- Edit profile：可改显示名与**联系电话**（手机实时查重、排除自身）  
- Active sessions：查看当前会话（IP、设备、时间），撤销单个或「除当前外全部」  
- Passkeys：列出 / 注册（WebAuthn） / 删除 passkey  
- **Linked accounts**：查看已绑定的第三方账号，可 **Unlink**；下方 **Link a provider** 列出所有已启用且尚未绑定的 provider（GitHub / Google / 飞书 / 微信 / OIDC），点击后跳转上游授权，回调绑到**当前登录用户**。也可在登录页先点第三方 → 未匹配时 15 分钟内用密码登录自动完成绑定（适用于任意已启用 provider）。  
- 恢复码一次性展示页提供 **Copy** 与 **Download**（含 enroll 与 regenerate 两种入口）

---

## 3. 登录 UX

1. 密码（或 **Passkey**，输入邮箱后一键登录）  
2. **第三方登录**：若管理员启用了 provider，密码表单下方出现 "or continue with" 分隔线与按钮（GitHub / Google / 飞书 / 微信 / 自定义 OIDC），点击后跳转上游授权  
3. **绑定结果**（回调后）：  
   - 已绑定或邮箱自动匹配 → 直接签发会话进入系统  
   - 尚无匹配本地账号 → 若开启 JIT 且上游有已验证邮箱，自动开户并登录；否则回登录页 `?sso_error=no_matching_account`（可 15 分钟内密码登录完成绑定）  
   - 已登录状态下走 SSO 回调 → 把该上游身份绑到当前用户  
4. 若 `mfa_required` → TOTP 或恢复码  
5. 若 `enroll_required` → 扫码绑定 → 一次性展示恢复码  
6. OIDC `return_to`（`/oauth/...`）完成后回跳授权  
7. 其他第三方失败同样回登录页并显示 `?sso_error=` 对应文案（`unknown_provider` / `provider_disabled` / `state_mismatch` / `upstream_error` / `missing_code` 等）  
8. 忘记密码：登录页链接 → `/reset-password` 两步重置（请求 → 确认）

详情与防接管规则见 [api-v1.md §12](./api-v1.md#12-第三方登录身份联邦)。

---

## 4. API 前缀

Dashboard 只调用 **`/api/v1/...`**。详见 [api-v1.md](./api-v1.md)。
