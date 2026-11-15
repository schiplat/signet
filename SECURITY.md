# Security Policy

Signet is an OIDC identity provider (SSO). Security issues are taken seriously, and
we appreciate responsible disclosure.

## Reporting a vulnerability

**Please do not open a public issue** for security vulnerabilities.

Report vulnerabilities privately by emailing **info@open.schiplat.com**. Include:

- A clear description of the vulnerability and its impact.
- Steps to reproduce, or a proof-of-concept if available.
- Affected version(s) / commit.
- Any suggested remediation.

We will acknowledge receipt within **3 business days** and aim to provide a fix or
a concrete plan within **14 days**. You will be credited in the release notes
unless you ask to remain anonymous.

## Scope

| In scope | Out of scope |
|----------|--------------|
| Authentication & authorization flows (OIDC/OAuth, MFA, passkeys, sessions) | Social engineering / phishing |
| Token & credential handling (JWT, refresh, authorization codes, TOTP) | Vulnerabilities in third-party dependencies not caused by our usage |
| Consent, logout, password reset, SCIM, webhooks | DoS from unlimited public traffic (covered by rate limiting) |
| Dashboard admin API | Physical attacks, compromised operator machines |
| Sensitive data exposure (PII, secrets) | Previously disclosed/known issues |

## Security model

Signet's security design is documented in [docs/security.md](./docs/security.md).
Key points:

- Passwords, recovery codes, client secrets, and tokens are stored only as
  hashes (Argon2 / SHA-256). TOTP secrets are encrypted at rest with
  AES-256-GCM.
- Authorization Code flow requires PKCE (S256), an exact `redirect_uri`
  allowlist, mandatory `state`, and scope allowlisting.
- Sessions use HttpOnly, SameSite=Lax cookies (Secure configurable via
  `SIGNET_COOKIE_SECURE`).
- Rate limiting, login lockout, and audit logging are enabled by default.

## Supported versions

| Version | Supported |
|---------|-----------|
| `0.x` (master) | ✅ |

Only the latest commit on `master` receives security fixes. There is no
long-term-support branch at this time.

## Disclosure process

1. Confirmation and triage within 3 business days.
2. Fix developed on a private branch and tested.
3. Coordinated release with a security advisory; reporter credited (unless
   anonymous).
