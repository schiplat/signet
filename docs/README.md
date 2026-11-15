# Signet documentation

> English · [简体中文](./zh-CN/README.md)

Signet is a unified identity service (OIDC IdP) for internal systems. This page
indexes the documentation by what you are trying to do.

These English documents are the source of truth. Chinese translations live in
[`docs/zh-CN/`](./zh-CN/) and may lag behind a release.

## Start here

| Document | What it covers |
|---|---|
| [Design overview](./design.md) | Goals and non-goals, deployment topology, protocol and endpoints, data model, flows, roadmap |
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

## Conventions in these documents

- `$ISSUER` (or `{issuer}`) is the public origin of the deployment, e.g.
  `https://sso.example.com`; the development default is `http://localhost:8443`.
- Environment variables are `SIGNET_*`; settings saved in the dashboard win over
  the environment unless a section says otherwise.
- Paths starting with `/api/v1` are dashboard/admin APIs; `/oauth/*` is the
  standard OIDC surface.
