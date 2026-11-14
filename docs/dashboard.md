# Signet Dashboard（管理台）

Vue 3 + Vite + Tailwind CSS v4，构建产物嵌入 Rust（`rust-embed`）。  
开发：`dashboard/` 下 `pnpm dev`（代理 `/api` → `:8443`）。

相关：[api-v1.md](./api-v1.md) · [mfa.md](./mfa.md) · [client-integration.md](./client-integration.md)

---

## 1. 角色与导航

| 角色 | 可见区域 |
|------|----------|
| `admin` | Activity、My apps、Overview、**Directory**、Clients、Audit logs、**Settings**、Directory sync |
| `manager` | Activity、My apps、Overview、**Directory**、Clients、Audit logs（无 Settings / Directory sync；审计不含删除类） |
| `member` | Activity、My apps；账户菜单（资料 / 密码 / 2FA / 会话） |

`Activity` 对所有角色可见（`/activity`）：非 staff 登录后默认落到该页，展示个人安全摘要 + 当前用户自己的登录与账号/安全操作记录。

路由守卫：`meta.staff` / `meta.admin`。

---

## 2. 页面能力

### Activity（通用）

- 顶部**个人安全摘要卡**：上次登录（时间 + 浏览器/系统）、活跃会话数、2FA 状态 + passkey 数量、已授权应用数
- 下方为当前用户自己的登录与账号/安全操作记录（`GET /api/v1/me/activity`，按 `actor_user_id` 过滤，所有角色可用，响应含 `summary`）
- 分页浏览，含 IP / 浏览器 / 系统与时间；空状态给出提示
- 定位为「个人视角」，与 Overview 的「全局运营视角」区分

### My apps（通用，`/my-apps`）

GitHub「Developer settings」式自助注册：**任何登录用户**都可申请 OAuth 客户端并成为其 owner，无需管理员审批。

- **Register an application**：填应用名（必填，展示在 consent 页）+ 回调地址（必填，http(s)、无 fragment）+ 可选 scopes（缺省 `openid profile email`）；提交即得 `client_id`，`client_secret` 只展示一次（附 `.env` / `config.toml` 对接片段）
- 默认形态与 RFC 7591 动态注册一致：`authorization_code` + `refresh_token`、PKCE、无 IP 白名单
- Owner 可自助：**Edit**（改名称 / 回调地址，行内按钮）、**Rotate**（轮换 secret，旧 secret 立即失效）、**Delete**（连带删除该 client 的授权记录与 token）——后两者在行尾 `⋮` 菜单
- 只能看到并操作自己创建的 client；管理员仍在 **Clients** 页全局管理（可看到 **Name** 与 **Owner** 列）
- 后端：`/api/v1/me/clients*`，审计沿用 `client.create / client.update / client.rotate_secret / client.delete`，`detail.via="self_service"`

### Overview

- **Get started 引导（admin 首次登录默认展示，醒目卡片）**：4 项**带校验**的检查 —— 管理员账号、Issuer（是否为默认值 / 是否与当前访问 origin 一致 / 非 localhost 是否用了 https）、邮件中继（host 与 From 是否齐全，而不只是"已配置"）、首个应用（至少一个启用且 redirect URI 合法）。状态分为 **Done / Needs attention / To do**，分段进度条 + 警告计数；支持 **Re-check** 重新读取服务端状态（面板只读，不修改任何配置）。**必填项（Issuer、首个应用；管理员账号隐含完成）未通过前禁止 Dismiss**（X 与按钮均禁用，并提示原因）；SMTP 标记为 optional，不阻塞关闭。关闭后通过页头 `Setup guide · n/4` 重新打开
- 用户 / 角色 / 客户端汇总（全局统计卡）
- **应用筛选器**：右上角可选全部应用 / 某个接入应用 / `Signet (direct)`（无应用归属的直登）；选中后登录合计、趋势图、最近登录与下方分布图均切换为该应用视角
- **登录趋势**：近 30 日一张图叠加 **当日 / 7 日滚动 / 30 日滚动** 登录次数；右上角仍显示当前 24h·7d·30d 合计
- **Logins by app**：近 30 天各应用登录次数对比图（Top 10 横向条形；`(direct)` 归并展示）
- **Browsers / OS**：近 30 天登录事件的浏览器与操作系统分布图
- 登录明细统一在 **Audit logs** 查看（Overview 不再内嵌最近登录列表，避免与 Audit logs / Activity 重复）

### Directory（staff）

Users 与组织树合并为一页（`/directory`），左侧组织、右侧当前节点的用户表：

- **左侧树**：`All users` / `Ungrouped` 两个虚拟节点 + 部门/组树（`kind = department | group`，来源徽章与直接成员数）；顶部 `+` 新建组/部门，支持改名、移动（拒环）、删除（仅 admin，子节点上移）
- **右侧完整用户表**：沿用原有 Users 能力 —— 搜索、排序、分页、Import JSON / Export CSV（均带当前组过滤）、New User（默认加入当前选中组）、批量 Freeze、行操作 Edit / Freeze·Unfreeze / Revoke sessions / Reset 2FA / Delete；选中本地组时行菜单额外提供 **Remove from this group**
- **过滤**：选中组/部门只显示其直接成员；有子节点时出现 **Include sub-groups** 开关，开启后递归包含后代（仅影响列表，不改变 OIDC claim）
- **来源归属**：`scim` / `directory` 节点可移动，但名称、成员与删除归来源；选中时提供 **Add members**（仅 local）
- 用户字段与操作细节：MFA / SSO 列、实时查重、Edit 角色/状态/Require MFA/Groups/Phone/密码等；Phone 仍可新建/编辑并出现在 CSV 导出中，但列表不再单列展示；`/users`、`/groups` 重定向到 `/directory`

### Clients

- 注册 / Edit / Enable·Disable / Rotate secret；Delete 仅 admin
- **Register Client 只保留必填**：Client ID、Redirect URIs；其余（Post-logout URIs、Scopes、IP 白名单）收进 **Advanced options** 折叠。**IP 白名单默认关闭**（与 RFC 7591 动态注册一致），需要时再开，避免试用被 CIDR 拦住
- 行内直接展示 **Test drive**、**Edit**；**Rotate secret / Disable·Enable / Delete** 收进行尾 `⋮` 菜单（菜单渲染到 body 并跟随滚动，避免被表格 overflow 裁切）
- Disabled 行视觉标注  
- **Name / Owner 列**：Name 为应用显示名（旧数据为空显示 `—`）；Owner 为自助注册者邮箱（管理员创建或无主显示 `—`），Edit 弹窗内也会提示该归属人可在 My apps 页自行管理
- **Source IP**：默认新建开启白名单；可关闭为 Unrestricted；Edit 可改 CIDR 列表
- 授权码流程始终要求 PKCE S256（无开关）  

### Audit logs

- 搜索（含 IP）、action / 应用（App）/ 浏览器 / OS 过滤、列排序（含 **Login IP**）  
- 展示 actor、IP、应用（`client_id` 徽标）、浏览器/OS（**Device** 列）、action、resource  
- **点击任意行**查看事件详情（含应用、完整 detail JSON 与 User-Agent）  
- **Export CSV**：导出当前过滤结果的 CSV（含 `client_id` 列）  

### Settings（admin only）

- Security：全局 **Require MFA for all users**
- **Server identity**：issuer（默认值 / 环境变量 / 本页保存 三种来源会标注）。环境变量存在时只读；首次保存后锁定，需显式 **Unlock to change** 才能再次修改（风险确认 + 审计）。保存即时生效；旧 token 失效、客户端与第三方 SSO 回调需同步更新
- **Runtime policies**：会话/token 有效期、登录尝试与锁定、密码长度/历史、审计保留、全局限流；保存即生效，未保存的字段沿用环境变量
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
7. 其他第三方失败同样回登录页并显示 `?sso_error=` 对应文案（`unknown_provider` / `provider_disabled` / `state_mismatch` / `upstream_error` / `access_denied` / `missing_code` / `email_required` 等）。用户在飞书等授权页拒绝时为 `access_denied`（友好提示，非系统故障）。`email_required`：飞书等未返回邮箱时拒绝首次绑定/登录，并提示开通邮箱权限（微信除外；已绑定身份可继续登录）。  
8. 忘记密码：登录页链接 → `/reset-password` 两步重置（请求 → 确认）

详情与防接管规则见 [api-v1.md §12](./api-v1.md#12-第三方登录身份联邦)。

---

## 4. API 前缀

Dashboard 只调用 **`/api/v1/...`**。详见 [api-v1.md](./api-v1.md)。
