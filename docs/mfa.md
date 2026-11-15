# Signet MFA (TOTP + recovery codes)

> English · [简体中文](./zh-CN/mfa.md)

| Item | Detail |
|---|---|
| Method | TOTP (RFC 6238, SHA1 / 30s / 6 digits) |
| Recovery | 10 single-use recovery codes (stored with argon2) |
| TOTP secret | `totp_secret` is encrypted at rest with AES-256-GCM at the application layer (no plaintext in the database); pending seeds are encrypted the same way |
| Replay protection | Each 30-second time step is accepted once (`users.totp_last_step` must advance strictly); a clock going back more than 10 minutes is treated as a resync, not a replay |
| Guess limiting | A single challenge allows at most 5 failures and is then invalidated; failures do not count towards account lockout (the password was already correct) |
| Enforcement | Global switch + per-user switch (both may be off) |
| Settings UI | `/settings`, **admin only** |
| API prefix | `/api/v1/...` (see [api-v1.md](./api-v1.md)) |
| UI guide | [dashboard.md](./dashboard.md) |

---

## 1. Enforcement policy

| Switch | Stored in | Who changes it | Default |
|------|------|------|------|
| Global `mfa.required_globally` | `app_settings` | admin | `false` |
| Per-user `users.mfa_required` | users | admin / manager | `false` |
| Enrollment fact `users.totp_enabled` | users | user enrollment / admin reset | `false` |

Sign-in branches:

```text
if totp_enabled:
    → always a second check (independent of the switches)
else if global_required OR user.mfa_required:
    → forced enrollment
else:
    → the password signs in directly; enrollment stays optional in the account menu
```

Turning the enforcement switches **off** does not unbind anyone. The unbind paths are:

- **Self-service disable** (`POST /api/v1/me/mfa/disable`): allowed only when **neither the global nor the per-user requirement is on**, and it takes the current TOTP code;
- admin **Reset 2FA**: clears that user's binding;
- the user's own **rebind** flow.

While the global requirement or that user's `mfa_required` is on, "Disable MFA" is unavailable on the user side (it returns `400 MFA is required by policy and cannot be disabled`).

---

## 2. Session model

When MFA is needed, a correct password does **not** issue `signet_session`; it issues only a short-lived `signet_mfa` challenge (about 10 minutes).
A successful verify / enroll confirm issues the real session and clears the challenge.

OIDC `/oauth/authorize` accepts a real session only.

---

## 3. Permissions

| Capability | admin | manager | member |
|------|-------|---------|--------|
| Global MFA switch in Settings | read/write | none | none |
| Per-user `mfa_required` | read/write | read/write | none |
| Reset another user's 2FA | yes | no | no |
| Own enrollment / rebind / recovery codes | yes | yes | yes |

---

## 4. API (summary)

| Endpoint | Notes |
|------|------|
| `GET/PATCH /api/v1/admin/settings/mfa` | admin: the global switch |
| `POST /api/v1/login` | `ok` / `mfa_required` / `enroll_required` |
| `POST /api/v1/mfa/verify` | TOTP code or recovery code |
| `POST /api/v1/mfa/enroll/start\|confirm` | forced enrollment (challenge) |
| `GET /api/v1/me/mfa` | status and remaining recovery codes |
| `POST /api/v1/me/mfa/enroll/start\|confirm` | optional enrollment while signed in |
| `POST /api/v1/me/mfa/recovery/regenerate` | rotate recovery codes (needs TOTP) |
| `POST /api/v1/me/mfa/rebind/start\|confirm` | rebind |
| `POST /api/v1/me/mfa/disable` | self-service disable (needs the current TOTP; refused while enforced; body `{ code }`) |
| `POST /api/v1/admin/users/:id/mfa/reset` | admin clears the binding |

---

## 5. Audit actions

`mfa.verify`, `mfa.enroll`, `mfa.recovery_use`, `mfa.recovery_regen`, `mfa.rebind`, `mfa.reset`, `mfa.disable`, `settings.mfa_update`
(`mfa.reset` / `settings.mfa_update` are visible in the audit list to admins only.)

---

## 6. UI

- Login: password → code, or forced enrollment + one-time display of recovery codes
- The one-time recovery-code page offers **Copy** and **Download** (`signet-recovery-codes.txt`); the same applies after a rebind or rotation
- TopNav: Two-factor auth (all roles) — status, remaining recovery codes, and **Disable MFA** (shown only while not enforced)
- Users: Require MFA; the **MFA status column** (Enabled / Required / Off); Reset 2FA (admin)
- Settings: the global Require MFA switch (admin only)
