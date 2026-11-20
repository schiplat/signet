# Signet 文档目录

> [English](../README.md) · 简体中文

Signet 是面向内部系统的统一身份认证服务（OIDC IdP）。本页按"你想做什么"组织文档。

英文文档是源版本（[docs/](../)）；中文译本随版本更新可能滞后。

## 从这里开始

| 文档 | 内容 |
|---|---|
| [本地开发](../local-development.md) | 源码搭建、Dashboard 热更新、账号模型、可观测性 |
| [设计总览](../design.md) | 目标与非目标、部署拓扑、协议与端点、数据模型、核心流程 |
| [客户端对接](../client-integration.md) | 业务系统接入：Discovery、authorize、token、id_token 校验、userinfo、登出、M2M、排错 |
| [部署布局](../deploy.md) | `build/` 与 `deploy/`、Dockerfile 与 compose、`/app/data` 密钥、密钥轮换、单活动实例拓扑 |

## 日常运维

| 文档 | 内容 |
|---|---|
| [管理台](../dashboard.md) | 页面与权限、Settings、My apps、Clients、Directory、键盘与无障碍 |
| [MFA](../mfa.md) | TOTP + 恢复码、强制策略、会话模型、API 与审计动作 |
| [目录同步](../directory-sync.md) | LDAP / HTTP JSON 拉取、bind 直通登录、定时调度、`signet sync` CLI、SCIM push 加固 |
| [目录映射交互](../directory-mapping-ux.md) | 两种 pull 源共用的字段映射交互规范（英文） |

## 集成

| 文档 | 内容 |
|---|---|
| [集成对接](../integrations.md) | RFC 7591 动态客户端注册、Webhook 投递（含飞书）、SCIM v2 |
| [HTTP API（`/api/v1`）](../api-v1.md) | Dashboard、会话与管理接口，含自助客户端与第三方登录联邦 |

## 安全与组

| 文档 | 内容 |
|---|---|
| [安全设计](../security.md) | 凭证存储、认证、会话、MFA、OIDC 加固、审计、密钥与配置 |
| [组与部门](../groups.md) | 组织树、按来源归属、`groups` claim、API 与权限 |

## 尚未实现

文档描述的是已发布行为；下列功能尚未实现，集中列在这里，避免各页出现"已支持"的误解：

| 项目 | 说明 |
|---|---|
| 手机号短信验证绑定 | `phone` 目前是未验证的联系信息；绑定需要短信网关与发送限流/防重放 |
| Alertmanager 告警对接 | 指标已在 `/metrics` 暴露，尚未接入 Alertmanager |
| SCIM `PATCH /Users` 写 `userName` / `emails` | 需先定义唯一冲突对推送客户端的语义（409 还是合并）；目前已支持 `active` 与 `displayName` |
| SCIM `filter` | 带 `filter` 的请求返回 400，而不是静默返回整个目录 |
| SCIM 组写入 `directory_groups` | SCIM 的组成员关系目前仍写本地 `users.groups` 列 |
| 从上游拉取样例（probe） | 映射预览依赖手工粘贴样例；从目录抓取样例（使 LDAP 组列变精确）尚未实现 |

有意不做：SAML、钉钉/企微连接器、多活动实例水平扩展、部门层级前缀匹配。

## 文档约定

- `$ISSUER`（或 `{issuer}`）是部署的公开 origin，例如 `https://sso.example.com`；
  开发默认值为 `http://localhost:8443`。
- 环境变量使用 `SIGNET_*`；后台保存的设置优先于环境变量，除非章节另有说明。
- `/api/v1` 开头的是管理台/管理 API；`/oauth/*` 是标准 OIDC 协议面。
