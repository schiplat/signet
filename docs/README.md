# Signet documentation

> English · [简体中文](./zh-CN/README.md)

Signet is a unified identity service (OIDC IdP) for internal systems. This page
indexes the documentation by what you are trying to do.

These English documents are the source of truth. Chinese translations live in
[`docs/zh-CN/`](./zh-CN/) and may lag behind a release.

## Start here

| Document | What it covers |
|---|---|
| [Local development](./local-development.md) | Source setup, dashboard hot-reload, account model, observability |
| [Design overview](./design.md) | Goals and non-goals, deployment topology, protocol and endpoints, data model, flows |
| [Client integration](./client-integration.md) | Connecting a business system: discovery, authorize, token, id_token validation, userinfo, logout, M2M, troubleshooting |
| [Deploy layout](./deploy.md) | `build/` vs `deploy/`, Dockerfiles and compose, `/app/data` keys, key rotation, the single-active-instance topology |

## Operate it

| Document | What it covers |
|---|---|
| [Dashboard](./dashboard.md) | Pages, roles and permissions, Settings, My apps, Clients, Directory |
| [MFA](./mfa.md) | TOTP + recovery codes, enforcement policy, session model, API and audit actions |
| [Directory sync](./directory-sync.md) | LDAP / HTTP JSON pull, bind-through sign-in, scheduling, `signet sync` CLI, SCIM push hardening |
| [Directory mapping UX](./directory-mapping-ux.md) | The field-mapping interaction spec shared by both pull kinds (English only) |

## Integrate it

| Document | What it covers |
|---|---|
| [Integrations](./integrations.md) | RFC 7591 dynamic client registration, webhook delivery (including Feishu), SCIM v2 |
| [HTTP API (`/api/v1`)](./api-v1.md) | Dashboard, session and admin endpoints, including self-service clients and SSO federation |

## Security and groups

| Document | What it covers |
|---|---|
| [Security design](./security.md) | Credential storage, authentication, sessions, MFA, OIDC hardening, audit, keys and configuration |
| [Groups and departments](./groups.md) | The organisation tree, ownership by source, the `groups` claim, API and permissions |

## Not implemented yet

The documents describe the shipped behaviour; these items are not implemented
yet and are listed here so no page promises them:

| Item | Detail |
|---|---|
| SMS-verified phone binding | `phone` is unverified contact information; binding needs an SMS gateway plus sending rate limits and replay protection |
| Alertmanager integration | Metrics are exposed on `/metrics`; feeding them into Alertmanager is not built |
| SCIM `PATCH /Users` writing `userName` / `emails` | Requires deciding what a uniqueness conflict means for a pushing client (409 or merge); `active` and `displayName` are supported |
| SCIM `filter` | Requests carrying `filter` are rejected with 400 rather than silently returning the whole directory |
| SCIM groups in `directory_groups` | SCIM group membership still writes the local `users.groups` column |
| Upstream sample probe | The mapping preview takes a pasted sample; fetching one from the directory (which would make the LDAP group column exact) is not built |

Deliberately out of scope: SAML, DingTalk/WeCom connectors, horizontal scaling
with multiple active instances, and hierarchical department-prefix matching.

## Conventions in these documents

- `$ISSUER` (or `{issuer}`) is the public origin of the deployment, e.g.
  `https://sso.example.com`; the development default is `http://localhost:8443`.
- Environment variables are `SIGNET_*`; settings saved in the dashboard win over
  the environment unless a section says otherwise.
- Paths starting with `/api/v1` are dashboard/admin APIs; `/oauth/*` is the
  standard OIDC surface.
