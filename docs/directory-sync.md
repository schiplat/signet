# Signet directory sync design

> English · [简体中文](./zh-CN/directory-sync.md)

| Item | Detail |
|---|---|
| Role | Sync an external directory into the local Signet user store as a **read-only data source**; LDAP users may sign in with their directory password |
| First target | LDAP (pull) |
| Related | [Design overview](./design.md) · [Security design](./security.md) · [Integrations](./integrations.md) · [Dashboard API](./api-v1.md) · [MFA](./mfa.md) |

---

## 1. Goals and non-goals

### 1.1 Goals

1. Treat an external directory as a **read-only data source** and sync users (and
   groups) into the local `users` table;
2. Support three source kinds: **LDAP**, **SCIM** and **generic HTTP JSON**;
3. Support two trigger modes: **CLI/API manual** and **background scheduling**,
   both manageable, auditable and observable;
4. Let LDAP directory users sign in with their directory password (**bind
   through**);
5. Support upstream **push** integrations.

### 1.2 Non-goals (explicitly out of scope for v1)

| Not doing | Why |
|---|---|
| Write-back to the upstream (bidirectional sync) | One-way meets the need; write-back introduces write conflicts and widened upstream permissions |
| Syncing password hashes | `users.password_hash` is argon2-only; supporting multiple hashes is costly and risky |
| Mapping upstream groups to Signet `role` | **Privilege-escalation risk**: a single upstream change would grant admin. `role` stays locally managed |
| Replacing SSO federation | `upstream_providers`/`user_identities` federate **at authentication time**; this design syncs **at provisioning time**. They complement each other |
| AD Deleted Objects deletion detection | Requires extra tombstone permissions and varies widely across environments |
| Nested group expansion | Needs special capabilities such as AD's `LDAP_MATCHING_RULE_IN_CHAIN` |

---

## 2. Settled decisions

| # | Decision | Choice | Impact |
|---|---|---|---|
| D1 | Push semantics | **Upstream → Signet** (reuse and harden the existing `/scim/v2` server) | Push exists only on the SCIM line; LDAP is pull-only |
| D2 | Password policy | **LDAP bind-through** | Passwords stay in LDAP; the sign-in path must branch |
| D3 | Upstream deletes a user | **Disable by default, never delete** | Preserves audit actor attribution (`audit_logs.actor_user_id` is `ON DELETE SET NULL`) |
| D4 | LDAP TLS | **LDAPS (636) mandatory + certificate verification enforced**; a self-signed CA can be imported | Plaintext bind is unacceptable; TLS configuration is required |
| D5 | Edit rights on directory users | **Fully read-only**: admins cannot change email/name/groups; only local MFA, `role` and a direct disable | Needs managed semantics and an attribute-ownership matrix |
| D6 | LDAP unavailable | **Fail closed** | Sign-in fails; no local-password fallback |

---

## 3. Sources and integration modes

| Source | Mode | Direction | Trigger | Notes |
|---|---|---|---|---|
| **LDAP** | pull | Signet → directory | CLI / schedule | LDAPS + service-account search; bind-through for sign-in |
| **Generic HTTP JSON** | pull | Signet → upstream | CLI / schedule | Most flexible; needs SSRF protection |
| **SCIM** | push | Upstream → Signet | Upstream-driven | The existing `/scim/v2`, needs hardening (§14) |

> ⚠️ **LDAP has no push semantics.** Documentation and requirements must say
> "three source kinds × two integration modes (pull / push)" to avoid the
> impression that LDAP should also support push.

---

## 4. Data model

### 4.1 New tables (migration `024_directory_sync.sql`)

```sql
-- Source configuration
CREATE TABLE directory_sources (
    id UUID PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,          -- CLI / URL identifier, e.g. "corp-ldap"
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('ldap', 'scim', 'http_json')),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    priority INT NOT NULL DEFAULT 100,  -- conflict priority across sources (lower wins)
    config JSONB NOT NULL DEFAULT '{}', -- kind-specific configuration (plaintext, no secrets)
    credential_enc TEXT,                -- service-account password / bearer token, AES-256-GCM
    ca_cert_pem TEXT,                   -- LDAPS self-signed CA (public key, no encryption)
    sync_groups BOOLEAN NOT NULL DEFAULT TRUE,
    interval_minutes INT,               -- NULL = manual trigger only
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One row per sync run (history for the UI/audit)
CREATE TABLE directory_sync_runs (
    id UUID PRIMARY KEY,
    source_id UUID NOT NULL REFERENCES directory_sources(id) ON DELETE CASCADE,
    trigger TEXT NOT NULL CHECK (trigger IN ('manual', 'schedule', 'cli', 'push')),
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'partial', 'failed')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    scanned INT NOT NULL DEFAULT 0,
    created_count INT NOT NULL DEFAULT 0,
    updated_count INT NOT NULL DEFAULT 0,
    disabled_count INT NOT NULL DEFAULT 0,
    skipped_count INT NOT NULL DEFAULT 0,
    conflict_count INT NOT NULL DEFAULT 0,
    error_count INT NOT NULL DEFAULT 0,
    error TEXT,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,  -- manual trigger actor
    stats JSONB NOT NULL DEFAULT '{}'   -- extended metrics such as group counts
);
CREATE INDEX directory_sync_runs_source_started_idx
    ON directory_sync_runs (source_id, started_at DESC);

-- External entry ↔ local user links
CREATE TABLE directory_entries (
    id UUID PRIMARY KEY,
    source_id UUID NOT NULL REFERENCES directory_sources(id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,          -- LDAP: entryUUID/objectGUID; SCIM: id
    external_dn TEXT,                   -- needed for LDAP bind-through
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_hash TEXT,                   -- managed-field fingerprint, avoids needless UPDATEs
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_synced_at TIMESTAMPTZ,
    UNIQUE (source_id, external_id)
);
CREATE INDEX directory_entries_user_idx ON directory_entries (user_id);
```

> `users.external_id` (migration `012`) is **globally unique** and SCIM-facing; it
> **cannot** serve as a per-source external id. Hence `directory_entries`.
> One external identity may link to exactly one local user; one local user may be
> linked by several sources (multi-source, see §17).

### 4.2 `users` changes

```sql
-- Three "disable intent" bits: each authority owns one, none overwrites another
ALTER TABLE users ADD COLUMN local_disabled     BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN directory_disabled BOOLEAN NOT NULL DEFAULT FALSE;  -- migration 026
ALTER TABLE users ADD COLUMN scim_disabled      BOOLEAN NOT NULL DEFAULT FALSE;  -- migration 026
-- The SCIM client manages this account's attributes (migration 027)
ALTER TABLE users ADD COLUMN scim_managed       BOOLEAN NOT NULL DEFAULT FALSE;
-- Directory-sourced groups, kept apart from local manual groups (§6.5)
ALTER TABLE users ADD COLUMN directory_groups TEXT[] NOT NULL DEFAULT '{}';
-- Since migration 043 both columns are UUID[]: ids, resolved through signet_group_names()
```

The effective status is the **OR** of the three bits, locked down by a database
constraint:

```sql
status = CASE WHEN local_disabled OR directory_disabled OR scim_disabled
              THEN 'disabled' ELSE 'active' END      -- constraint users_status_matches_flags
```

**Why one bit is not enough** (the original single `local_disabled` column
lacked this): `status` has only active/disabled, while disablement can come from
**several distinct sources**. If every party writes `status`, the same column
carries both "who disabled it" and "is it disabled", so they inevitably overwrite
each other:

| Scenario | Result with a single column |
|---|---|
| SCIM disables → a later directory sync sees the user in the directory | The sync writes `status = active`, **erasing SCIM's disable** |
| Directory disables (user disappeared) → SCIM pushes `active: true` | SCIM writes `status = active`, **erasing the directory disable** |
| A local admin enables an upstream-disabled account | The admin thinks it worked; the next sync disables it again |

The three bits mean "each records its own intent; `status` is their
conclusion":

- An upstream disable ⇒ locally disabled; enabling locally has no effect — the
  strictest policy, now guaranteed by a **database constraint** that no write path
  can bypass;
- Each authority can release only **its own** bit (sync clears only
  `directory_disabled`, SCIM only `scim_disabled`, an admin only
  `local_disabled`);
- "Whose write overwrites whose" becomes inexpressible at the data-model level.

Clearing rules for `directory_disabled` / `scim_disabled` are in §6.3; **when an
authority dies its intent must be released** (otherwise the account is locked
forever with no way out) — see §4.3.

> Sync checklist: `USER_COLS` in `models.rs`, the `User` struct, the admin
> list/detail responses, and every `SELECT {USER_COLS}` call site. **Implemented
> accordingly** — no writer declares `status` directly any more; everything
> derives it from the bits (`status_from_flags` / the constraint).

### 4.3 Authority liveness and release of its intent

An intent holds only while its owner is alive. Each authority has a liveness
test, and any failure must call `authority::release_dead_authority_claims`:

| Intent / ownership | Liveness test | Released when |
|---|---|---|
| `directory_disabled` | An **enabled** source links this user | The source is disabled or deleted |
| `scim_disabled` / `scim_managed` | The SCIM config has a token (rotation keeps it alive; **only revocation kills it**) | `DELETE /admin/scim/token` |

Both tests scan **by liveness**, not by owner, deliberately: a link can be deleted
by hand (`DELETE /directory/sources/{code}` says so), and scanning by owner would
then find nobody to release, locking the account permanently. Scanning by
liveness makes the system self-heal.

> A real lock-up bug lived here: after the SCIM token was revoked nothing released
> `scim_disabled`, and an SCIM-disabled account could not be enabled by an admin
> (the constraint forbids it), so **no path** recovered it. `tests/disable_flags.rs`
> now pins the difference between rotation and revocation.

### 4.4 Upstream-managed markers: origin and ownership are separate

| Column | Question it answers | When written |
|---|---|---|
| `provisioned_via` | How this account **first** came to exist (`sso_jit` / `scim` / …) | Creation only. Taking over an existing local account does **not** rewrite it |
| `directory_entries` (a link exists) | Whether the directory owns its attributes | During sync |
| `scim_managed` | Whether the SCIM client owns its attributes | Any SCIM write (`create` / `put` / `patch`) |

`provisioned_via` and `scim_managed` must stay separate: when an IdP takes over an
existing local account it **is not** that account's creator, and writing
`created by scim` would mislead operators. Both feed
`authority::managing_authority`, which answers "who owns this account" for the
write/delete refusals in §5 (directory outranks SCIM: links carry a priority, and
the directory is the source of truth for attributes).

---

## 5. Attribute ownership and read-only semantics (D5)

| Field | Owner | Directory may write | Local may change |
|---|---|---|---|
| `email` | Directory | ✅ | ❌ |
| `username` | Directory | ✅ | ❌ |
| `display_name` | Directory | ✅ | ❌ |
| `groups` (local groups) | Local | ❌ | ✅ |
| `directory_groups` | Directory | ✅ | ❌ |
| `status` | Directory + local override | ✅ (upstream value) | ✅ (only through `local_disabled`) |
| `external_id` | Directory | ✅ | ❌ |
| `password_hash` | Local | ❌ | ✅ (always empty for directory users) |
| `mfa_required` / `totp_enabled` / `totp_secret` | Local | ❌ | ✅ |
| `role` | **Local** | ❌ | ✅ |
| `phone` | Local | ❌ (v1) | ✅ |
| `must_change_password` | Local | ❌ (always `false` for directory users) | ✅ |

**Determining "who manages"**: `authority::managing_authority(pool, user_id) -> Option<Authority>`,
where `Authority` is `Directory(code)` or `Scim`. The directory takes the
**highest-priority** source code (`ORDER BY priority ASC, code ASC`; `code` gives a
deterministic result at equal priority), and directory outranks SCIM.

**Why one query rather than two functions**: the originally planned
`is_managed(pool, user_id) -> bool` and `managing_source(..) -> Option<String>`
are two projections of the same query, and every enforcement point needs the code
to build its error and audit detail ("managed by directory source corp" and
"managed by SCIM" are different sentences); a boolean projection would only add a
second truth source that drifts.

> `Authority` is an enum rather than `Option<String>` because SCIM has no code —
> directory codes are operator-chosen, and `"scim"` is even a legal **kind**
> value, so a string is genuinely ambiguous exactly where it would be used to
> refuse a write.

A refusal returns `403`; both the message and the **owned-field list** are pure
functions/constants on `Authority` (`write_error(field)` / `delete_error()` /
`managed_fields()`, see §5.1). `tests/directory_policy.rs` pins them to the table
above.

`Authority::managed_fields()` has one deliberate difference: the directory owns
`directory_groups`, **SCIM does not**. SCIM groups still write the local
`users.groups` column; claiming ownership here would make local group edits
collide with a value SCIM overwrites. Moving SCIM groups to `directory_groups` is
separate work (§6.5, §14).

**Implemented (P0)**:

| Entry point | Behaviour |
|---|---|
| `update_user` | Refuses only when the **normalised new value** of `email`/`username`/`display_name` differs from the current one; changes to local fields (`role`/`groups`/`phone`/`mfa_required`/`status`, …) pass through |
| `delete_user` | Always refused, suggesting disable instead (consistent with D3: upstream deletion only disables, and local should not hard-delete either) |
| `disable_user` / `enable_user` / `batch_disable_users` | **Allowed**, writing/clearing `users.local_disabled` (below) |

> **One correction to the wording above**: §5 originally listed `disable_user`
> among the entries that must refuse. But the same D5 table says `status` is
> "directory + local override, locally changeable (only through
> `local_disabled`)" — refusing disable would make the promised local override
> unusable. The implementation therefore **allows it and writes
> `local_disabled`**. `set_status` now requires the caller to pass
> `local_disabled`, so any local disable that bypasses that intent is caught at
> compile time.

> A refused write audits `directory.managed_write_blocked` (`detail = { source,
> field }`). The sync engine's own `directory.sync.*` / `directory.user.*` events
> belong to P1, since there was no sync to audit yet.

### 5.1 Testability of the refusal policy

`Authority::write_error` / `delete_error` / `managed_fields` are pure
functions/constants (`crates/signet/src/authority.rs`), so the ownership table can
be pinned by ordinary unit tests without a database. `tests/directory_policy.rs`
covers: managed fields refused, local fields allowed, and unknown fields
**allowed by default** (a caller's typo must not lock an admin out of unrelated
attributes).

### 5.2 How the dashboard presents "why disabled" and "can it be enabled"

`PublicUser` exposes three fields so the dashboard need not infer disable
semantics:

| Field | Meaning |
|---|---|
| `disabled_by: string[]` | The authorities currently holding the account: `local` / `directory` / `scim` (several may coexist) |
| `can_enable: bool` | Whether an admin's Unfreeze would **actually** work (computed server-side, below) |
| `local_disabled: bool` | The local bit itself (the edit dialog needs it separately) |

**Why an array rather than a single `reason`**: an account may be held by two
authorities at once, and an admin's Unfreeze can release only the **local** bit. A
single value would have to pick a winner and hide the other authority still
holding the account — which is exactly the answer to "why did nothing happen".

**Why `can_enable` is server-computed**: it is **policy**, not a rendering
choice. The old button appeared for every disabled account, returned `200`,
cleared the local intent, and left the account **still frozen** — reporting
success while nothing happened. Policy belongs on the server so the view's copy
cannot drift from what the write path actually enforces.

Dashboard (`UsersView.vue`): the status column lists `disabled_by` entries; when
Unfreeze cannot take effect it is replaced by `Held upstream` explaining which
authority must let go; the edit dialog warns that choosing active clears only the
local freeze, and the account stays frozen.

---

## 6. Sync algorithm

### 6.1 Main flow (full reconciliation)

```text
1. Create a run (status=running, recording trigger and actor)
2. Page through the upstream's full entries
3. Process each entry (6.2)
4. Reconciliation tail (6.3)
5. Group sync (6.5, when enabled)
6. Close the run with counts; on failure status=failed + error
```

Paging and batching:

- LDAP: RFC 2696 Simple Paged Results, configurable page size (default 500); AD
  also needs the paging control OID `1.2.840.113556.1.4.319`.
- Commit a transaction every N entries (default 200) to avoid long transactions
  and memory growth.

### 6.2 Per-entry processing

```text
Look up directory_entries by (source_id, external_id)
├─ link found
│   ├─ managed-field fingerprint equals source_hash → update last_seen_at only (skipped)
│   └─ differs → UPDATE managed fields + source_hash + last_seen_at (updated)
└─ no link
    ├─ match a local user by email / username
    │   ├─ match → conflict: skip + count conflict + audit directory.conflict (6.4)
    │   └─ no match → INSERT a new user (role='member', password_hash='',
    │                  provisioned_via=<kind>, local_disabled=FALSE)
    │               + write the link (created)
    └─ write the link
```

New-user fields: `sub` is a generated UUIDv4; a missing `display_name` falls back
to the email's local part (the same rule as the JIT path in
`federation/link.rs:203`).

### 6.3 Reconciliation tail (missing means disable)

```sql
UPDATE users SET directory_disabled = TRUE,
                 status = CASE WHEN local_disabled OR scim_disabled
                               THEN 'disabled' ELSE 'disabled' END   -- see §4.2
WHERE id IN (SELECT user_id FROM directory_entries
             WHERE source_id = $1 AND last_seen_at < <this run's start>)
```

(`status` derives from the three bits; the sync writes **its own bit** and never
touches `local_disabled` / `scim_disabled`.)

- It does **not** delete users, delete links or clear `local_disabled`;
- It audits `directory.user.disabled`; `detail.reason` has two values:

| reason | When |
|---|---|
| `absent_upstream` | The directory no longer lists this entry |
| `out_of_scope` | The directory still lists it, but it no longer belongs to this source's **scope** (§7.2.1: transfer, domain change) |

`apply_disables` carries the planner's reason per entry instead of hard-coding
one — an operator reading "account disabled" at 3 a.m. must be able to tell
"left the company" from "changed department";
- Two scope-related boundaries: scope can disable only users **linked by this
  source** (the absence sweep walks links, so unlinked users are untouched), and
  a `--limit` trial skips reconciliation, so scope **never** disables anyone in a
  trial;
- When an entry reappears, the sync **clears its own** `directory_disabled` (other
  authorities' bits still apply, §4.2) and audits `directory.user.enabled` —
  but **only when the account actually becomes active**: if local or SCIM still
  holds it, nothing visible changed, and an "enabled" event would send operators
  looking for an account that still cannot sign in;
- The "reappearance releases" rule is required: for a user whose attributes are
  unchanged but whose `directory_disabled` is still true, the planner must emit
  `Update` in addition to `Unchanged`, or the returning user stays disabled
  forever;
- Keeping the link makes "disappear then reappear" avoid duplicate accounts.

### 6.4 Conflict handling

| Conflict | Handling |
|---|---|
| The upstream email/username collides with an existing local user with no link | **Skip + report a conflict**; never take over automatically. Audit `directory.conflict`; an admin confirms explicitly and links it by hand |
| The colliding user is **already linked by another source** | **Skip, no conflict**. Ownership follows `priority` (§4.1); the higher-priority source keeps the attributes, and `reason` names the owning source (below) |
| The same email appears several times upstream | Take the first, skip the rest with a warning |
| An upstream email change collides with another user | The UPDATE fails → that entry skips with a conflict, the rest continue, the run becomes `partial` |
| An upstream entry is gone but locally linked | 6.3 disable |

> **Multi-source overlap**: when the same person exists in two directories, both
> sources link to them (`external_id` is per-source). The planning phase checks
> `managing_source` first — if the owning source is not this run's source, it
> **neither writes attributes nor disables on "upstream disappearance"**, records
> a skip, and puts the owning source in `reason`.
>
> A skip rather than a conflict: a conflict means "collided with a local account
> that **nobody manages**", which is the takeover risk needing human judgement.
> Two sources listing one person is normal multi-source operation; counting it as
> a conflict would leave every run `partial`, and operators would soon learn to
> ignore the status. The owning source's attributes win — that is what `priority`
> means.
>
> The cost is that groups contributed by a lower-priority source are dropped. v1
> accepts that (Q5 is still open); when ownership changes, the next run replans.

> **Security**: v1 **does not** auto-claim an existing account by email.
> Otherwise a malicious or misconfigured directory entry (say
> `admin@corp.com`) could take over a local admin account. Surfacing the conflict
> beats silent takeover. If claiming is ever supported it must require: the source
> explicitly opts in, the target user `role='member'`, and the target has no local
> password.

### 6.5 Group mapping

`users.groups` is published as the OIDC `groups` claim (`oidc/token.rs`,
`oidc/userinfo.rs`), so writing directory groups straight into `groups` would
clobber local manual groups. The split-column approach:

- `users.groups` = local groups (administrator-maintained)
- `users.directory_groups` = directory groups (fully replaced by sync)
- The OIDC `groups` claim = the **union** of both (deduplicated, stably sorted so
  the claim is repeatable)

On sync, the groups this source contributes are replaced wholesale (since
migration 043 stored as ids; unknown names create `source='directory'` rows):

```sql
UPDATE users SET directory_groups = signet_group_ids($2, 'directory') WHERE id = $1
```

> This needs changes in the OIDC claim assembly and the dashboard user list — a
> manageable cost that leaves room for multi-source and local coexistence.

v1 group boundaries:

- Sync **direct members only**; no nested expansion;
- On the LDAP side, resolve via `member` (OpenLDAP group objects) or `memberOf`
  (AD reverse lookup), selectable in the source config;
- SCIM groups are tagged `source='scim'` in `scim_groups`, and `/scim/v2/Groups`
  sees only its own; directory and local groups never appear in the IdP's list;
- Directory groups appear in Dashboard → **Directory**'s tree (with a Directory
  badge) and can be moved under a department; name, membership and existence
  still belong to the sync source.

**Implemented (P1/P2)**: sync fully replaces `users.directory_groups` (`update_user`
keeps the existing value when `$5 IS NULL`, so a source with `sync_groups` off
does not wipe it; a non-null value goes through `signet_group_ids($5,'directory')`);
on a successful run with `sync_groups` enabled, `source='directory'` groups with
no members and no children are tombstoned (groups deleted upstream leave nothing
behind); the OIDC `groups` claim comes from `models::effective_groups`, the
deduplicated, sorted union of both columns (so one user always sees the same
claim). Tests: `tests/oidc_groups_claim.rs`.

---

## 7. LDAP specifics

### 7.1 Dependency and TLS

`ldap3` is required, and default features **must** be disabled (the default `tls`
uses native-tls):

```toml
ldap3 = { version = "0.12", default-features = false, features = ["tls-rustls-ring"] }
```

Points (verified against the crate docs):

- `tls-rustls` alone **does not work**; a crypto provider must be selected
  (`tls-rustls-ring` or `tls-rustls-aws-lc-rs`);
- `tls` and `tls-rustls` are **mutually exclusive**; enabling both fails to
  compile;
- A self-signed CA is injected through `RootCertStore` +
  `LdapConnSettings::set_config(Arc<ClientConfig>)`;
- `no_tls_verify` (skip verification) is forbidden — it contradicts D4 and the
  code exposes no such option.

### 7.2 Connection config (`config JSONB`)

```json
{
  "url": "ldaps://ldap.corp.example:636",
  "bind_dn": "cn=signet-sync,ou=svc,dc=corp,dc=example",
  "base_dn": "ou=people,dc=corp,dc=example",
  "user_filter": "(&(objectClass=person)(mail=*))",
  "email_domains": ["corp.example", "partner.example"],
  "department_attribute": "department",
  "department_values": ["Engineering", "Platform"],
  "username_attribute": "uid",
  "email_attribute": "mail",
  "display_name_attribute": "displayName",
  "external_id_attribute": "entryUUID",
  "group_base_dn": "ou=groups,dc=corp,dc=example",
  "group_filter": "(objectClass=groupOfNames)",
  "group_membership": "member",
  "page_size": 500
}
```

- `credential_enc` stores the service-account password (read-only permission is
  enough);
- **Grant the directory the least privilege**: read access to the `base_dn` and
  `group_base_dn` subtrees only;
- `user_filter` runs on the server and is a **coarse filter**: it saves traffic
  but the preview cannot validate it (§13.1.3). When writing domain patterns,
  note that `(mail=*corp.example)` also matches `bob@evilcorp.example`; write
  `(mail=*@corp.example)`;
- `email_domains` / `department_values` are **fine filters**, evaluated locally on
  normalised entries, so the preview can report "0/N matched". They are additive
  (all must pass), not alternatives;
- **Filters must be escaped; never interpolate user input into a filter (filter
  injection).** The predicates (`email_domains`, …) use local comparison and are
  never interpolated, so `ldap.rs`'s "no interpolation, no escaping needed"
  argument holds — any new field that interpolates config values into a filter
  must first add RFC 4515 escaping and tests.

### 7.2.1 Scope is "ownership", not a "query condition"

This is the single most important point in this section. `email_domains` and
`department_values` define **who this source owns**, not **who to query now**. The
direct consequence (§6.3's "missing means disable"):

- Narrowing the scope ⇒ people falling outside are **disabled** (and their
  sessions revoked), the same path as upstream deletion;
- So **changing the scope is destructive**: run `--dry-run` first to see the
  `disabled` count, or read the disable list in the run history;
- "0 matched" does not mean "synced 0 people" but **disables everyone this source
  already manages at once**. The preview's `scope` row fails such a config with
  `ok: false` (§13.1.3), and saving rejects empty entries, wildcards, and
  `department_values` without a `department_attribute` — configurations that
  would match nothing;
- **Domains are stable, departments are volatile**: dropping out under a domain
  filter basically only happens on departure or a domain change; under a
  department filter **every internal transfer drops out**. Disable reasons are
  therefore deliberately split:

| reason | Meaning |
|---|---|
| `absent_upstream` | The directory no longer lists this person (departure/deletion) |
| `out_of_scope` | The directory still lists them, but they no longer belong to this source's scope (transfer, domain change) |
| `email_domain_not_allowed` | The directory still lists them, still in scope, but the domain is excluded by the **global sign-in allowlist**. This is a `skip` and **never** appears in disable (below) |

The first two appear in the run history's `changes[].reason` and the audit
`reason`, so operators can tell "left" from "transferred"; the third is a skip
reason explaining "why was this person not synced".

**Scope vs allowlist: ownership vs admission.** Two different `email_domains`
exist; mixing them turns one policy change into a mass disable:

| | Scope `ScopeFilter` (this section) | Global sign-in allowlist `admission` (§7.2.2) |
|---|---|---|
| Question | Who does this source **own** | Who may **come in** |
| Falling outside | Linked users are **disabled** (`out_of_scope`) | Nothing happens: account and data stay, they just cannot sign in |
| Coverage | Only **this source** | Sign-in, SSO JIT, admin provisioning, SCIM push, sync |
| Where configured | `email_domains` in the source config | Dashboard → Settings / `SIGNET_ALLOWED_EMAIL_DOMAINS` |
| Who gets hurt | Narrowing disables | Narrowing refuses new sign-ins, disables nobody |

The rule is simple: **"we no longer manage this person" belongs in scope; "this
person may not come in" belongs in the allowlist**. Swapping them is
asymmetric — "may not come in" in scope disables people still employed, while
"no longer managed" in the allowlist leaves departed people enabled (just unable
to sign in).

Domain matching is deliberately narrow: it compares **whole label boundaries**,
so `corp.example` matches `corp.example` and `mail.corp.example` but **not**
`evilcorp.example`; case-insensitive; **no wildcards and no regex** — a pattern
language expressive enough for anything is also something the preview cannot
validate and a typo can silently narrow or empty the scope. Department values are
compared exactly (trimmed, case-insensitive), with no prefix matching. That gap is
Q7 in §17: AD often writes departments as a path like `Engineering / Platform`,
in which case `department_attribute` / `department_path` must point at exactly
that level — a parent name will not match, **and because scope is ownership, a
mistake disables (`out_of_scope`) rather than merely syncing fewer rows**. Always
check the `--dry-run` `disabled` count before and after changing a department
filter.

### 7.2.2 Global sign-in allowlist (admission): skips, never disables

The global allowlist (`docs/api-v1.md` §14) affects sync in one way: **entries
whose domain is not listed are skipped**, `changes[].reason = email_domain_not_allowed`,
and:

- They are **not created** and **not updated** (attributes are not written);
- If the upstream entry corresponds to an already-linked user, it is **not
  disabled** — the planner records that `external_id` in the "seen this run" set
  before deciding the skip, so §6.3's absence sweep does not read it as "no
  longer listed". This detail is the crux: the allowlist says "may not come in",
  not "has left"; if it fell into absence reconciliation, narrowing the allowlist
  would become a mass disable, contradicting the admission-vs-ownership split;
- A linked user left enabled for this reason is refused at session issuance on
  sign-in (`docs/api-v1.md` §14) — "the account exists but cannot come in";
- The entry does **not** produce `out_of_scope` (scope is a different predicate,
  decided before the allowlist), so an operator can tell "fell out of scope (will
  be disabled)" from "blocked by the allowlist (will not be disabled)" in the run
  history;
- The order is deliberate: email readability check → scope → duplicate check
  (claim external_id) → allowlist. Moving the allowlist before the claim would
  silently lose the second guarantee above.

### 7.3 Choosing the external id

| Directory | Stable id | Notes |
|---|---|---|
| OpenLDAP | `entryUUID` | Stable |
| AD | `objectGUID` | Binary; convert to a UUID string |

Never use the DN as `external_id`: an OU change changes the DN and creates a
duplicate account. The DN lives only in `external_dn`, for bind.

### 7.4 Incremental sync (optimisation only)

| Directory | Incremental field | Pitfall |
|---|---|---|
| AD | `uSNChanged` | Monotonic per DC, not global; changing DC corrupts it |
| AD | `whenChanged` | Second precision; several changes in one second are missed |
| OpenLDAP | `modifyTimestamp` | Second precision; needs a look-back of several minutes (kludge) |

**Conclusion**: incremental sync is only an optimisation to reduce cost, and a
periodic full reconciliation (especially for deletion detection) **must** remain.
Defaults: hourly incremental + daily full; v1 may start with full only and add
incremental after it works.

---

## 8. LDAP bind-through authentication (D2)

### 8.1 Sign-in path branching

Today `auth/routes.rs:90` calls local verification unconditionally:

```text
if !verify_password(&body.password, &user.password_hash)? { ... }
```

Branch by **managing source** instead:

```text
1. Load the user (unchanged)
2. Status and lock checks (unchanged)
3. Check whether the user is managed by an enabled LDAP source
   ├─ yes → validate with an LDAP bind (8.2)
   └─ no  → local argon2 verification (unchanged)
4. On success continue to begin_login_mfa_flow (unchanged; MFA needs no changes)
```

This also fixes the empty-password defect in §15: only unmanaged users reach the
argon2 branch, and an empty hash must return `401`, not `500`.

**Implemented (P2)**:

| Component | Location | Behaviour |
|---|---|---|
| Path selection | `directory::auth::resolve` | One SQL query picks the **lowest-`priority` enabled LDAP source** (the same ownership rule as `managing_source` and the planner). No link / source disabled / source not `ldap` / `external_dn` missing or blank → `Local` |
| Bind verification | `directory::auth::verify` → `ldap::bind_as` | One bind with the stored `external_dn`; connect 5s / operation 10s; always unbind |
| Three-state result | `directory::auth::Credential` | `Valid` / `Invalid { counts_toward_lockout }` / `Unavailable { source_code, detail }` |
| Unavailable | 503 `directory unavailable` | Writes `auth.directory_unavailable` (with source and error) before returning; **no** local-password fallback |
| Metrics | `metrics.rs` | `signet_directory_login_failures_total`, `signet_directory_unavailable_total`, counted apart from local failures |

> **Corrupt configuration**: a source whose config fails to parse makes `resolve`
> return an error (→500) rather than silently falling back to local. Directory
> users have no local password, and pretending "wrong password" would send them
> to reset a password that does not exist. Configs are validated on save, so this
> state means the database was edited externally.

> **Local password writes are blocked in `password::set_user_password`**: that
> function is now the single choke point, so all four callers (self-service
> change, admin reset, email reset, forced change) are stopped there. The reason
> is not that a directory user's local password is meaningless but that it is
> **harmful**: bind-through means it is never used, while disabling or deleting
> the source turns it into a usable credential. The check uses
> `directory::enabled_managing_source` (enabled sources only), deliberately a
> different semantic from `managing_source`: **disabling a source must hand the
> account back to local management**, otherwise retiring a directory would
> permanently lock its users out. `/password-reset/request` likewise skips
> sending for managed accounts while staying 200 to prevent enumeration.

### 8.2 Bind verification

- Bind directly with the **`directory_entries.external_dn` stored at sync time**,
  avoiding a "service-account search + bind" pair per sign-in (lower latency, and
  the sign-in path needs no search permission);
- Use the configured `ldaps://` URL; LDAPS is mandatory;
- The password is never stored, logged or cached;
- On success reset local `failed_login_attempts` / `locked_until`, then continue
  into the existing MFA flow.

**An empty password is refused locally without opening a connection.**
`simple_bind(dn, "")` is an *unauthenticated bind* per RFC 4513 §5.1.2 (asking the
server to treat it as anonymous), and servers that accept it (e.g. OpenLDAP with
`allow bind_anon_cred`) return `success` — `verify` would read that as "valid
credentials" and **grant a session for the DN's user on an empty password**, with
the DN coming from our own link table. An empty password says "I have no
password", not "I want to be anonymous", so a zero length returns
`Credential::Invalid { counts_toward_lockout: true }` and 401: **our** decision
(not the directory's), so §8.4 books it locally like the local password path.
Only zero length is blocked — pure whitespace is "trying a real password" and
belongs to the directory. The same shape in `LdapConnector::connect` for the
service-account bind (`password.unwrap_or("")`) now errors instead of degrading
into an anonymous search (`requires_credential` already made "LDAP sources need a
credential" the rule, because anonymous binds silently return a reduced view).

### 8.3 Failure and outage semantics (D6 fail closed)

| Case | Behaviour |
|---|---|
| bind returns invalid credentials | `401 invalid email or password`; audit and metric increments |
| LDAP unreachable / timed out | `503 {"error":"directory unavailable"}` + `tracing::error!`; **no** local fallback |
| DN missing (never synced to `external_dn`) | Treated as unmanaged → local verification; with no local password → `401` |

Timeouts: connect 5s, operation 10s (configurable); timeouts are **mandatory**, or
a hung LDAP server exhausts the login thread pool.

### 8.4 Lockout policy (to confirm, §17)

Local `failed_login_attempts` and AD's own lockout policy **stack**, potentially
locking a user out with the causes masking each other. v1 recommendation:

- LDAP authentication **failures do not count** towards local lockout (the
  directory's own policy governs);
- But `auth.login.failed` audits and Prometheus metrics are **still recorded**,
  preserving brute-force visibility.

**Implemented that way**: `Credential::Invalid { counts_toward_lockout: false }`
expresses the decision, and the handler skips the `failed_login_attempts`
increment and the local lockout branch while still writing audits and metrics
(`signet_directory_login_failures_total`, separate from local). The decision lives
in the return type rather than the call site so "should this failure count
locally?" must be answered explicitly.

---

## 9. Command line

Implemented in `directory/cli.rs`. Adding a CLI is a behaviour change for
`main.rs` (which previously parsed no argv and was env-only), so **no subcommand
keeps the old behaviour** (read env → serve), leaving container commands and
deploy scripts untouched.

### 9.1 Commands

```bash
signet sync run     --source <code> [--dry-run] [--json] [--limit <n>]
signet sync ldap    --source <code> [--dry-run] [--json] [--limit <n>]   # alias of run
signet sync runs    --source <code> [--json] [--limit <n>]               # default 20
signet sync sources [--json]
signet serve                                                             # same as no subcommand
```

`run`'s connector comes from the source's `kind` (`ldap` / `http_json`); one
command drives both. The subcommand was renamed from `ldap` to `run` in P4, with
`ldap` kept as `#[command(visible_alias = "ldap")]` so existing scripts work
unchanged.

`--limit` is not just "run fewer": **it also skips the "missing upstream means
disable" reconciliation** — a truncated snapshot cannot distinguish "deleted"
from "beyond the limit". A limited run therefore reports `reconciled: false` with
an explicit warning, and never disables users because of truncation.

### 9.2 Typical usage

```bash
# First connection: compute the diff only, see who would be created/updated/disabled
signet sync run --source corp-ldap --dry-run

# Commit the run once it looks right
signet sync run --source corp-ldap

# Sample-check the attribute mapping (note: no absence reconciliation)
signet sync run --source corp-ldap --limit 50

# Troubleshooting: recent run history / configured sources
signet sync runs --source corp-ldap
signet sync sources
```

### 9.3 `--dry-run` boundaries

`--dry-run` is the seatbelt for the first LDAP rollout: it computes expected
created/updated/disabled/conflict counts and prints the diff, **writing nothing**.
It also **opens no run record** (the `status` CHECK has no `dry_run`, and
recording a run that wrote nothing would make the history lie), so dry runs never
appear in `runs`.

### 9.4 Output

```bash
$ signet sync sources
code                 kind       enabled  priority interval   credential
corp-ldap            ldap       true          100 30m        set
```

```bash
$ signet sync runs --source corp-ldap
id                                     started (UTC)        status    created updated disabled conflicts
3f6c1e2a-…                             2026-09-20 15:40:02  succeeded       2       1        0         0
```

`run`'s text report contains `source / mode / status / scanned + counts`, then
the noteworthy changes with a `reason` each; beyond 50 entries it truncates and
suggests `--json` (`--json` always returns the full list).

A `disable` `reason` has two values (§6.3): `absent_upstream` (no longer listed)
and `out_of_scope` (still listed but outside the source's scope — transfer or
domain change). They are the only way to tell "left" from "transferred", so they
are printed as raw tokens for `grep`/alerting rules.

The `runs` text table shows only 7 columns; `--json` returns all `RunRow` fields
(including `trigger`, `scanned`, `skipped_count`, `error_count`, `stats`) — use
`--json` to distinguish `cli` / `schedule` / `manual` triggers.

`status` values: `running` / `succeeded` / `partial` (finished with conflicts or
entry errors) / `failed`.

### 9.5 Exit codes and failure semantics

- Success `0`; any error `1` (`main` returns `anyhow::Result`), with an `Error: …`
  summary on the output so CI can decide.
- Missing source / config parse failure: `load_source` runs **before**
  `open_run`, so `Error: directory source not found: <code>` merely terminates the
  process — **no run record, no audit** (`source::get_by_code` →
  `SourceConfig::parse`).
- Connection failures and other planning errors happen **after** `open_run`, so
  the run closes as `failed` + `error` and a `directory.sync.failed` audit is
  written (a dry run has `run_id = null`). Leaving the failure record is
  deliberate — otherwise a killed process would hold "running" forever.
- **Concurrency**: migration `025`'s single-run unique index allows one `running`
  row per source. Racing the dashboard trigger or the scheduler, the later caller
  gets `another sync run for this source is already in progress` (HTTP 409)
  instead of two interleaved syncs. A running run heartbeats every 60 seconds;
  only a `running` row whose heartbeat is older than `STALE_RUN_MINUTES` (120
  minutes) is marked `abandoned by a previous process` before a new run starts —
  long tasks are not misjudged for running long, and a killed process never wedges
  the source. Run history is kept for 90 days by default.

### 9.6 Prerequisites (important)

The CLI is **not** a lightweight client: it reuses `build_state` and therefore
performs the same initialisation as the server:

- Connects to `SIGNET_DATABASE_URL` and **runs migrations**;
- Loads or **auto-generates** `jwt_private.pem` and `encryption.key`;
- Re-encrypts webhook secrets once (failure is fatal, never silently downgrading
  to unsigned);
- Prunes expired audit logs, seeds the SCIM token when needed, and builds the
  WebAuthn relying party.

Two operational requirements follow:

1. **The database, key paths and `SIGNET_WEBAUTHN_RP_ID` / `RP_ORIGIN` must match
   the server.** Running the CLI with a different `SIGNET_ENCRYPTION_KEY_PATH`
   generates a **new** key file in place and then fails to decrypt existing
   ciphertext; even if it happens to work, it leaves a key artifact inconsistent
   with the server. Use the same env (or the same cwd inside the container).
2. `dotenvy` reads `.env` from the **current working directory**. When running by
   hand outside the container, always `cd` to the directory holding the env file,
   or it silently falls back to built-in defaults.

Production execution (container `exec`) is in
[deploy.md §4](./deploy.md#4-running-the-directory-sync-cli-inside-the-container).

### 9.7 Logs and pipelines

Logs go to **stdout** (the same stream as the report), so a bare `| jq` is
polluted by INFO lines. Disable logs when consuming a pipe:

```bash
RUST_LOG=off signet sync sources --json | jq -r '.[].code'
```

Logs follow the [logging rules](../.cursor/rules/logging.mdc): static messages +
structured fields. `APP_ENV=production` switches to single-line JSON.

---

## 10. Scheduling and run history

Today there is **no** background/scheduled-task facility; the only request-scoped
`tokio::spawn`s are two in `webhooks.rs`.

Design:

- Spawn a scheduler loop in `build_app`, ticking every minute with
  `tokio::time::interval`;
- Each tick finds sources with `enabled = TRUE AND interval_minutes IS NOT NULL`
  that are due;
- **Replica safety**: take a source-level `pg_try_advisory_lock` (key derived from
  `source_id`) before running and skip when it is held; otherwise every replica
  runs the sync;
- v1 uses `interval_minutes` (integer) rather than cron expressions, avoiding a
  cron-parsing dependency; upgrade later if needed;
- Run history is written to `directory_sync_runs` and exposed through:

```text
GET  /api/v1/admin/directory/sources                        # list
POST /api/v1/admin/directory/sources                        # create (credential encrypted)
PUT  /api/v1/admin/directory/sources/{code}                 # update
POST /api/v1/admin/directory/sources/{code}/enabled         # enable/disable
POST /api/v1/admin/directory/sources/{code}/sync            # manual trigger (async, returns a run id)
GET  /api/v1/admin/directory/sources/{code}/runs            # run history
GET  /api/v1/admin/directory/sources/{code}/runs/{id}       # one run's detail
```

Permissions: all require `require_admin_role` (credentials are sensitive).

**Implemented (P3)**: `directory::scheduler` (60-second tick /
`MissedTickBehavior::Delay` / skipping the first immediate tick) plus
`model::due_sources`. "Due" is decided in one SQL statement: `enabled`,
`interval_minutes IS NOT NULL`, no **live** running run, and at least the
interval elapsed since the most recent `started_at`.

> **One deviation from §10: no `pg_try_advisory_lock`.** A session-level advisory
> lock belongs to the **connection that took it**, and this repository's
> connections come from a pool, borrowed and returned per query — "lock → spawn a
> task → unlock" spans connections, so the lock does not lock anything, and a lock
> that does not lock is worse than none because readers assume protection.
>
> The real mutex is migration `025`'s partial unique index
> (`directory_sync_runs (source_id) WHERE status = 'running'`): `begin_run` can
> insert exactly one row across **all replicas and all trigger modes**
> (schedule/manual/cli), and the insert happens **before** connecting to the
> directory. The losing replica gets `Conflict` and writes nothing. A database
> constraint cannot be forgotten.
>
> **Another deviation, and a bug fix**: `due_sources` defines "live" as
> `started_at` within `STALE_RUN_MINUTES`. Treating any `running` row as blocking
> would let one crashed run stop the source **forever** — the recovery path
> `fail_stale_runs` only runs inside `open_run`, and `open_run` is only reached
> when something calls it. Both constants therefore share
> `engine::STALE_RUN_MINUTES`: if they drift, the source either wedges forever or
> collides with a live sync. `tests/directory_scheduler.rs` pins this with
> `a_crashed_run_is_recovered_instead_of_wedging_the_source_forever`.

---

## 11. Audit and observability

### 11.1 Audit events

| Event | Granularity |
|---|---|
| `directory.source.created` / `.updated` / `.deleted` / `.enabled` / `.disabled` | Per operation |
| `directory.sync.started` / `.finished` / `.failed` | Per run (with trigger, counts, elapsed) |
| `directory.user.created` | **Per entry** |
| `directory.user.disabled` | **Per entry** (`detail.reason = absent_upstream` / `out_of_scope`) |
| `directory.user.enabled` | **Per entry**, and **only when the account really becomes active** (§6.3) |
| `directory.user.updated` | **Summary only** (counts), not per entry |
| `directory.conflict` | **Per entry** |
| `directory.managed_write_blocked` | Per refused local write (`detail = { source, field }`) |

On the SCIM push side (§14) the granularity is **one event per request**, not per
affected row — an IdP replacing a 500-person group is **one** action, and 500
events would bury it:

| Event | Trigger |
|---|---|
| `scim.user.create` | `POST /Users` |
| `scim.user.update` | `PUT`/`PATCH` **that actually changed managed attributes** (`detail.changed` lists them; `detail.via` = `put` / `replace active` / `remove active`) |
| `scim.user.enabled` / `scim.user.disabled` | When `active` **transitions** (`detail.via` says which spelling) |
| `scim.user.delete` | `DELETE /Users` (actually a disable, §14.1) |
| `scim.group.create` / `.update` / `.delete` | The three group writes (`update`'s `detail.outcome` reports member add/remove counts) |

> **Idempotent pushes are not audited.** A compliant client resends the whole
> resource on every poll; recording one event per request would drown the few
> timestamps an operator looks for in the polling period — and a client resending
> `active: false` has not made a new decision. So `update` is recorded only when
> `changed` is non-empty, and enable/disable only on **transitions** — the same
> rule as `directory.user.enabled` above.

> ⚠️ **Webhook fan-out must be handled**: `audit.rs:107` unconditionally calls
> `webhooks::dispatch` for **every** audit event, with **no retry**. A full sync of
> 100k users audited per entry means 100k audit rows + 100k webhook deliveries.
> Therefore:
> - `updated` is summarised, not per entry;
> - add fan-out suppression for sync events (e.g.
>   `directory_sources.config.webhook_events = "summary"`), or aggregate per run
>   into a single `directory.sync.finished` push.

### 11.2 Metrics

- `directory_sync_runs_total{source,status}`
- `directory_sync_duration_seconds{source}`
- `directory_sync_entries_total{source,action}`
- `directory_sync_conflicts_total{source}`
- `directory_bind_total{result}` (sign-in bind success/failure/unreachable)

### 11.3 Logs

Follow the [logging rules](../.cursor/rules/logging.mdc): static messages +
structured fields (`source_code`, `run_id`, `scanned`, `created`, `updated`,
`disabled`, `conflicts`, `elapsed_ms`); errors in an `error` field. **Never** log
passwords, service-account credentials or bind passwords.

---

## 12. Security

| Item | Requirement |
|---|---|
| LDAP TLS | LDAPS + certificate verification enforced (D4); the code exposes no skip-verification switch |
| Credential storage | Service-account passwords / bearer tokens always go through `Encryptor` (AES-256-GCM) into `credential_enc`; **never** plaintext |
| Outbound SSRF | A new unified outbound module: http(s) only, no redirect following, connect/total timeouts, response-size cap, **private/loopback/link-local addresses blocked (including a second check after DNS resolution, against rebinding)**. LDAP is not HTTP, but the HTTP JSON source (P4) needs it, so it is built in P0 and `webhooks.rs:80` plus federation's `issuer_url` validation switch to it |
| Directory account permissions | Read-only, least privilege (read the user and group subtrees only) |
| Privilege escalation | Directory data **never** writes `users.role`; groups write only `directory_groups` |
| Read-only enforcement | Admin endpoints refuse managed-field edits per §5 with `403` and a clear reason |
| Conflicts do not take over | Auto-claiming an existing account (especially admin/manager) by email is explicitly forbidden in v1 |
| Passwords | Never stored, logged or cached; bind-through uses only the submitted password |
| Incidental fix | `webhooks.secret` was **plaintext** while SSO client secrets and TOTP secrets were already encrypted — unify on `Encryptor` |

---

## 13. Generic HTTP JSON source (P4)

Configuration (`kind = 'http_json'`; `config` uses explicit dotted paths and
`deny_unknown_fields`):

```json
{
  "url": "https://directory.corp.example.com/api/users",
  "method": "GET",
  "auth": "bearer",
  "users_path": "data.users",
  "external_id_path": "id",
  "email_path": "email",
  "email_domains": ["corp.example"],
  "department_path": "dept",
  "department_values": ["Engineering"],
  "username_path": "login",
  "display_name_path": "name",
  "groups_path": "groups",
  "pagination": { "mode": "cursor", "param": "cursor", "next_path": "paging.next", "max_pages": 10 }
}
```

- **Authentication**: `auth` is `"none"` / `"bearer"` / `{"basic": {"username": "..."}}`;
  the secret itself lives in `credential_enc` (`Encryptor`, AES-256-GCM) and is
  **never in `config`**; `auth: none` drops the credential requirement
  (`SourceConfig::requires_credential`, the same decision on create and update);
- **Field mapping**: dotted paths of the form `a.b[0].c` (supporting
  `["keys.with.dots"]` and an optional `$.` root marker). Path syntax errors
  (empty segments, unclosed brackets/quotes) must not be treated as "no value" —
  otherwise a typo silently becomes an empty directory, and an empty directory
  disables every user the source manages (D3);
- **Failures that must error**: a missing or non-array `users_path` → error naming
  the path and the JSON type actually found, **never an empty list**; a non-2xx
  upstream → status code plus the URL without its query, never the response body
  (it may be an HTML error page);
- **Pagination**: `none` / `page` (`?page=N&page_size=M`, first page and parameter
  names configurable) / `cursor` (next cursor from `next_path`, absent means
  done). All are hard-capped by `max_pages` (config max 1000): an upstream that
  always has another page would loop forever while holding the service token;
- **Outbound validation**: every page re-runs `outbound::ensure_allowed` (DNS
  rebinding means the save-time check is stale by fetch time), no redirects are
  followed, and the response-size cap plus connect/total timeouts reuse P0's
  `outbound` module. Saving also checks once
  (`source::ensure_destination_allowed`), same layer as webhooks: a literal
  private address may only be saved with `SIGNET_OUTBOUND_ALLOW_PRIVATE` on;
- **Reuses P1's mapping and reconciliation layer**: the connector only fetches
  data, producing `Vec<UpstreamUser>` into the same planner / apply / run history
  / audit chain; `engine::fetch_and_plan` is the only place dispatching by kind;
- **Explicitly not done (v1)**: `method` supports only `GET` (a POST body has no
  configuration surface, so it errors rather than silently downgrading), no
  wildcard/filter general JSONPath, and no parsing of "group object arrays"
  (`{id,name}` cannot be guessed; report "no groups" rather than inventing names);
- **Scope**: `email_domains` / `department_path` + `department_values` match the
  LDAP semantics exactly (§7.2.1), including "out of scope means disable" and the
  `out_of_scope` reason. The only difference is where values come from: a
  department is a JSON path, not a directory attribute. Upstream filtering
  embedded in the URL (`?dept=eng`) belongs to the upstream and is invisible to
  Signet, so it **does not replace** the predicates here;
- **Incremental**: still unimplemented; full reconciliation only (as with LDAP,
  §7.4).

Dashboard: creating a source lets you choose the kind (immutable afterwards,
matching the API); the HTTP JSON form covers URL / auth / pagination; **the
mapping part is now shared by both pull kinds** (§13.1).

---

## 13.1 Mapping UI and preview endpoint (shared by both pull kinds)

### 13.1.1 Why not six input boxes

The old mapping was a set of isolated text inputs (`data.users` / `id` / `mail` /
`entryUUID`…), offloading three things at once onto the operator: remembering what
the upstream looks like, memorising path syntax, and waiting until **the next
sync** to discover a mistake. A fourth is worse: the normalisation (lowercased
emails, display-name fallback to the email prefix, group sorting/dedup) is
invisible in the form, so nobody knows what the database will contain.

The shared shape is therefore: **one mapping table + a kind-specific "sample
pane"**. Both pull kinds answer the same questions with different syntax:

| Mapping row (`ROW_*`) | LDAP | HTTP JSON |
|---|---|---|
| `scope` | `base_dn` + `user_filter` | `users_path` |
| `external_id` | `external_id_attribute` | `external_id_path` |
| `email` | `email_attribute` | `email_path` |
| `username` | `username_attribute` | `username_path` |
| `display_name` | `display_name_attribute` | `display_name_path` |
| `groups` | `group_base_dn` + `group_filter` + `group_member_attribute` + `group_name_attribute` | `groups_path` |

The row definitions live in one frontend place (`dashboard/src/lib/directoryMapping.ts`);
adding a kind changes data rather than writing another form. `scim` is **not** in
that table: it is the push direction (§3), its mapping is fixed by the SCIM
schema, and the UI says so explicitly instead of offering a fake pull mapping.

### 13.1.2 Sample: paste once, then click

"Fetch a sample from the upstream" is not in the first batch, so both kinds take a
**paste**, shaped to their data:

- **JSON is nested → two trees.** The first is "where is the list" (only array
  nodes are clickable; others are greyed with a reason); after choosing, the second
  is "what does one record look like", **re-rooted at the entry**, so the paths it
  yields are entry-relative (`id`, not `data.users[0].id` — the latter only holds
  for the first row of the first page).
- **LDIF is flat → an attribute list.** `ldapsearch -LLL` output is LDIF, exactly
  the authoritative source for the LDAP settings most often wrong (`uid` vs
  `sAMAccountName`, `entryUUID` vs `objectGUID`). Parsing is **server-side**
  (`directory::ldif`); the frontend renders the returned `targets`, avoiding a
  second LDIF implementation.

`targets` carry occurrence counts and provenance (`user` / `group` / `both`), and
multi-valued attributes are tagged `N values`. The JSON side's "how many of 12
entries have this key" is computed in the frontend per entry and shown as a
`12/12` / `3/12` badge — keys present in only a few entries get highlighted, which
"look only at the first record" can never reveal.

**Click target**: clicking a field in the sample fills the **currently focused
input**; with no focus it does nothing and shows a hint. No modal-inside-a-modal
picker.

### 13.1.3 `POST /admin/directory/sources/preview-mapping` (admin-only, pure)

```
{ kind, config, sample?, sync_groups?, offset? }
→ { fields: [{ row, ok, error, resolved, total, fixed }],
    targets: [{ key, count, multi, source, sample_value, user_entries, group_entries }],
    rows: [{ external_id, external_dn, email, username, display_name, groups }],
    warnings: [...], entry_count, offset, page_size, truncated }
```

- **Touches no database and makes no network request**: `sample` is used in memory
  only, never stored or logged (it is real directory data);
- **Shares the same code as sync**, so the preview cannot diverge from a real run:
  LDAP goes through `ldap::upstream_from_entry` (also used by `fetch_users`), HTTP
  JSON through `http_json::to_upstream`, normalisation through
  `plan::ManagedFields::from_upstream` + `plan::normalize_groups`;
- **Per-row errors instead of one "invalid configuration"**: `ok/resolved/total`
  let the UI pin the conclusion to the offending row. The `scope` row checks two
  things for LDAP: whether the sample DN falls under `base_dn` (`user_filter` runs
  server-side and cannot be judged locally — the response says so), and whether
  §7.2.1's scope predicate **admits at least one** entry — the predicate is
  evaluated locally, so this is decidable, and "0 matched" fails the row with
  `ok: false` (the `error` explains that a real run would disable everyone the
  source manages). With no scope configured the row keeps its original meaning
  (`resolved` = entries under `base_dn`), so old configurations render unchanged;
- **Things not done are stated too**: no sample → empty `fields` plus a warning,
  **never a pretended validation**; no group entries → the group column is
  explicitly unverified; `group_base_dn` set with `sync_groups` off → an explicit
  "groups will not be written" warning;
- **Sample cap 1 MiB** (the route raises the body limit to 4 MiB so the framework's
  413 does not win first);
- **Validate everything, page the output**: `fields`' `resolved/total` and
  `targets`' counts are computed over **all** sample entries (`total ==
  entry_count`); only `rows` are paged by `offset`, 25 per page. They deliberately
  do not share a number: an earlier version truncated validation to the first 50
  entries, so one panel showed two denominators, "120 entries" and "10/50", and the
  smaller one made rare attributes look more common than they are (8% rendered as
  20%) — exactly the misjudgement the count exists to prevent. Analysis is one
  in-memory pass and `MAX_SAMPLE_BYTES` caps it, so the cost is negligible;
- An out-of-range `offset` **falls back to the last page** instead of returning an
  empty table (the sample may shrink between two debounced calls, and an empty
  table reads as "this source has no users"). `page_size` is always the page width
  (capacity); **never step by `rows.len()`**, because entries without an external
  id produce no row and the last page is shorter than the width, so stepping by
  row count would overlap windows;
- `deny_unknown_fields`: a misspelled request field (e.g. `sample_json`) returns
  400 instead of silently becoming "no sample, validation passed";
- **No audit**: it writes nothing, reads no database, holds no credential, and is
  called repeatedly while editing the mapping; what deserves auditing is the
  saved configuration (`directory.source.*`). Samples are **not persisted**
  either.

### 13.1.4 One deliberate approximation

In a real sync, LDAP groups come from the **group side** (`fetch_group_membership`
runs a server-side search on `group_base_dn` with `group_filter`). A pasted LDIF
has no server to query, so membership is inferred from "the DN falls under
`group_base_dn` and carries `group_member_attribute`".

The group column is therefore marked **best effort** in LDIF mode (`warnings`);
the other five columns are exact. Exactness awaits "fetch the sample from the
upstream" (no probe, no exact promise).

### 13.1.5 Preview and save consistency

The preview's `config` comes directly from **the form's current values**, not the
save-time `buildBody()`, so it shows exactly what is typed and reacts to edits.

That works because **the backend relaxed validation**: unfilled mapping keys are
reported as "not set yet" (that row `ok = false`, `error = "… is not set yet"`),
not as "invalid configuration". The earlier strict validation required optional
keys such as `display_name_attribute`, so previewing the raw form 400'd on an
empty string — which would have pushed the frontend to preview
`buildBody()` instead.

Consistency rests on this: preview and save read the same form values, and "save
omits empty optional keys" is interpreted by the backend as "empty means unset",
so neither "preview passes but save fails" nor the reverse can occur.

---

## 14. SCIM inbound push (P5 outline)

The existing `/scim/v2` is a SCIM **server**, on the right track, but needs
hardening to really take Okta / Entra pushes:

| Problem | Location | Fix |
|---|---|---|
| `role = 'user'` violates the CHECK (only admin/manager/member), so **user creation always 500s** | `scim.rs` create_user | Use `'member'` |
| The PATCH body's operation list is named `operations`, while RFC 7644 and IdPs send `Operations`; serde is case-sensitive + `#[serde(default)]` ⇒ an empty list, **the whole body discarded**, yet 200 with an unchanged resource | `scim.rs` `PatchUserBody` / `PatchGroupBody` | Accept both spellings |
| Operations ignored `op`/`path` and treated everything as a write ⇒ on the group route `remove` **added** members; `{"op":"remove","path":"active"}` without `value` ⇒ silently ineffective; Entra's `{"op":"Replace","path":"active","value":false}` (scalar) ⇒ accepted and ignored | `scim.rs` `patch_user` / `patch_group` | Parse `op`/`path` per RFC 7644 §3.5.2, supporting `active`/`displayName`/`members` |
| `PATCH /Groups` could only add, never remove | `scim.rs` `patch_group` | Support add/remove/replace |
| `delete_group` bound an unused `$1` | `scim.rs` `delete_group` | Fix the binding |
| DELETE returned 200 + an Error schema | `scim.rs` `delete_user` / `delete_group` | Return `204` |
| Missing audits (no `scim.group.*`) | — | Add them |

Not implemented today: `PATCH /Users` writing `userName` / `emails` (a
uniqueness conflict needs a defined policy for pushing clients), SCIM `filter`
support, and moving SCIM group storage onto `directory_groups`. The
[documentation index](./README.md#not-implemented-yet) keeps the canonical list.

> **The `Operations` item deserves its own note**: it made every PATCH defect above
> unobservable — a real client's body became an empty list during
> deserialisation, and the route "successfully" did nothing. The earlier defect
> analysis ("op/path semantics completely ignored") only held for lowercase
> bodies; against a real IdP the symptom is "PATCH always returns 200 and nothing
> changes". Regression tests therefore go through the **body** layer
> (`user_attrs_from_body` / `group_member_changes_from_body`) rather than calling
> the interpreter directly — otherwise the bug stays untestable.

The push write path should reuse the sync mapping and conflict logic, and write
`directory_sync_runs` (`trigger = 'push'`) for a unified run history and audit.

### 14.1 Upstream deletes only disable, never remove data (D3 in practice)

The same principle as directory sync: an upstream delete is **an intent**, not a
deletion. Landing points:

| Entry | Behaviour | Why |
|---|---|---|
| `DELETE /scim/v2/Users/{id}` | Set `scim_disabled = TRUE` (`status` derives per §4.2) and `scim_managed = TRUE`; **never delete the row** | `directory_entries.user_id` and the IdP's `externalId` both point at this id. Deleting it would make the next push **open a new account** for the same person, and the old account's sessions, audits and group history would lose their owner — and a mistaken delete is unrecoverable |
| `DELETE /scim/v2/Groups/{id}` | Set `deleted_at = NOW()`, snapshot members into `members_at_delete` (migration `028`), and remove the group name from every user's `groups` | Both directions must hold: membership **must stop authorising** (`groups` feeds the claim), and a recoverable record **must remain**. Deleting the row would destroy "this group existed and who was in it" |
| An admin deletes a managed account | `403`, suggesting disable | Deletion rights for managed accounts belong upstream (§5) |

**Recreating a same-named group**: `scim_groups.display_name`'s unique constraint
becomes a partial index over live rows only
(`scim_groups_live_display_name_key`); otherwise the tombstone would hold the name
forever and block an IdP recreating it.

### 14.2 Mixed deployments: SCIM and directory sync no longer overwrite each other

When one account is both directory-linked and SCIM-pushed (the three intent bits
in §4.2 exist for this):

- A SCIM disable writes only `scim_disabled`, **not** `local_disabled` — "the
  upstream's intent" and "the local intent" are two things, and merging them
  leaves operators unable to tell "the IdP disabled it" from "I disabled it";
- Directory sync writes only `directory_disabled`, so it cannot see SCIM's
  disable and therefore cannot erase it;
- Attribute ownership favours the directory (§4.4), but **disable intents never
  overwrite each other**: each authority holds its own bit, and `status` is their
  OR.

---

## 15. P0 defect list (prerequisite for every phase)

These were **already broken** in the code and sit on the paths this design
reuses:

| # | Location | Problem | Fix |
|---|---|---|---|
| 1 | `scim.rs:228` | Inserts `role = 'user'`, violating `CHECK (role IN ('admin','manager','member'))` → `POST /scim/v2/Users` always 500s | Use `'member'` |
| 2 | `mfa/mod.rs:341` | `mfa_challenges.purpose = 'change_password'` violates `CHECK (purpose IN ('login','enroll'))` → forced password change broken | Extend the CHECK or reuse an existing value |
| 3 | `auth/routes.rs:90` | Users with `password_hash = ''` (SSO JIT / SCIM) make `PasswordHash::new("")` fail, turning into **500** rather than 401 | Branch per §8.1; unmanaged users with an empty hash return 401 |
| 4 | `scim.rs:684` | `delete_group`'s UPDATE references only `$2` but binds `group.id` first | Fix the binding |
| 5 | `webhooks.rs:80` | Outbound URLs only checked for an `http(s)://` prefix; no SSRF protection | Adopt §12's unified outbound validation |
| 6 | `webhooks.rs:87` | `webhooks.secret` stored in plaintext, inconsistent with other secrets | Encrypt with `Encryptor` |
| 7 | `federation/provider.rs` | Outbound HTTP had no timeout (only webhooks had 10s) | Unify on the outbound module |

> **Where item 6 landed**: `audit::record(pool, event)` became
> `audit::record(state, event)`, and `webhooks::dispatch` / `deliver_one` take
> `&AppState` as well, so the delivery path can reach the `Encryptor` to decrypt
> `secret_enc`. `login_alert::track_login` changed signature too. Existing
> plaintext is migrated by `bootstrap::encrypt_webhook_secrets` at startup, and
> that step is **deliberately fatal**: a silent failure would leave `secret_enc`
> empty and downgrade deliveries to unsigned.

> **Outbound validation compatibility note**: `outbound` rejects targets resolving
> to private/loopback/link-local addresses by default, so **existing webhooks
> pointing at intranet addresses start failing** (a `success = false` delivery is
> recorded). If an intranet receiver must stay, set
> `SIGNET_OUTBOUND_ALLOW_PRIVATE=true` (deployment-level, off by default; turning
> it on logs a WARN at startup, and it only relaxes the **address** policy — non
> http(s) schemes and embedded credentials are still refused). Also: all outbound
> requests disable redirects, so a provider whose endpoint relies on redirects is
> affected. `issuer_url` and OIDC discovery use a strict mode (literal address
> check only, no DNS resolution), so an intranet IdP works fine by hostname.

---

## 16. Phasing and acceptance

| Phase | Content | Acceptance |
|---|---|---|
| **P0 foundation** | All §15 defects; `is_managed`/read-only semantics; the three tables + `users` changes in §4; audit events; unified outbound module; credential encryption | Existing tests pass; SCIM user creation no longer 500s; forced password change works; empty-password users return 401; an admin editing a directory user is refused |
| **P1 LDAP sync engine** | Connect/LDAPS; full paged pull; fingerprint comparison; create/update; missing means disable; groups into `directory_groups`; CLI (`--dry-run`, `--json`); manual trigger API; run history | `--dry-run` diff matches a real run; a full run against the target directory succeeds; an upstream deletion disables the user with an audit trail; a second run reports `updated = 0` |
| **P2 LDAP bind-through** | Branch sign-in per §8; LDAPS bind; fail closed; metrics | Directory users sign in with their directory password and pass MFA normally; a changed password takes effect; LDAP down returns 503 with no fallback |
| **P3 scheduling** | §10 scheduler + advisory lock; run-history UI entry | Runs on time; two replicas starting together run once; failures audited and metered |
| **P4 HTTP JSON source** | §13 | One full sync; SSRF cases (private address, redirect, oversized response) all refused |
| **P4.5 Shared mapping UI** | §13.1 | Paste a sample once and click mappings; preview matches real writes after normalisation; the sample is never stored or logged |
| **P4.7 Source scope: email domains / departments** | §7.2.1 | Sync only the configured domains/departments; a misconfiguration (0 matches) fails the preview instead of silently emptying; run history distinguishes "left" from "transferred" |
| **P5 SCIM push hardening** | §14 | Real Okta/Entra pushes can create/update/delete; group add/remove correct; audits complete |

Not implemented today: the upstream sample probe (P4.6). The mapping
preview takes a pasted sample, so the LDAP group column stays best effort.

> **P1 and P2 must ship together**: syncing users without bind-through means
> directory users are imported but cannot sign in — the feature is not delivered.

---

## 17. Open questions

| # | Open | Impact |
|---|---|---|
| Q1 | Is the first integration target **AD** or **OpenLDAP**? | Decides the `external_id` field, member resolution and incremental fields. Lock down **one** first; do not support both at once |
| Q2 | User count and expected sync frequency? | Decides `page_size`, batch-transaction size and whether incremental is needed (the full-reconciliation window at 100k users) |
| Q3 | Should LDAP auth failures increment local lockout? (§8.4 recommends **no**) | Double-lockout risk |
| Q4 | Adopt the split-column `directory_groups` approach? (§6.5 recommends it) | Affects OIDC claim assembly and dashboard display |
| Q5 | Must multiple sources co-manage one user? | Affects conflict arbitration (`priority`) and whether `directory_entries` may hold several rows per user |
| Q6 | Should this document be listed in the README documentation index? | Discoverability |
| Q7 | Should `department_values` support **hierarchy/prefix** semantics (e.g. "everything under Engineering")? | Today it compares exact values (§7.2.1); if AD writes departments as paths like `Engineering / Platform`, `department_attribute` / `department_path` must point at **exactly that level**, otherwise a configured filter matches nothing. Prefix semantics would loosen the scope test and change the "out of scope means disabled" boundary, requiring follow-up decisions: whether the preview's `scope` row distinguishes "prefix hit" from "exact hit", and whether prefixes split only on `/`. **Not implemented for now** — recorded only |
