-- 024 Directory sync foundation.
--
-- Introduces the tables and `users` columns the directory sync feature builds
-- on (see docs/directory-sync.md §4). This migration is pure DDL: no sync
-- engine, CLI or LDAP connector exists yet, so the tables start empty.
--
-- No data migration is needed for the two new `users` columns: their defaults
-- describe every existing row correctly (nothing is directory-managed yet, and
-- no user has directory-sourced groups).

-- ── Data source configuration ───────────────────────────────────────────
CREATE TABLE directory_sources (
    id UUID PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,          -- CLI / URL identifier, e.g. "corp-ldap"
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('ldap', 'scim', 'http_json')),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    priority INT NOT NULL DEFAULT 100,  -- attribute precedence on conflict (lower wins, §6.4)
    config JSONB NOT NULL DEFAULT '{}', -- kind-specific settings; MUST NOT contain secrets
    credential_enc TEXT,                -- service-account password / bearer token, AES-256-GCM
    ca_cert_pem TEXT,                   -- LDAPS self-signed CA (public key, no need to encrypt)
    sync_groups BOOLEAN NOT NULL DEFAULT TRUE,
    interval_minutes INT,               -- NULL = manual trigger only
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Run history (queried by the UI and by audit) ────────────────────────
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
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL, -- who triggered a manual run
    stats JSONB NOT NULL DEFAULT '{}'   -- extension metrics, e.g. group counts
);

CREATE INDEX directory_sync_runs_source_started_idx
    ON directory_sync_runs (source_id, started_at DESC);

-- ── External entry ↔ local user links ───────────────────────────────────
--
-- `users.external_id` (migration 012) is globally UNIQUE and SCIM-facing, so it
-- cannot serve as a per-source external id: with two sources it would collide.
CREATE TABLE directory_entries (
    id UUID PRIMARY KEY,
    source_id UUID NOT NULL REFERENCES directory_sources(id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,          -- LDAP: entryUUID/objectGUID; SCIM: id
    external_dn TEXT,                   -- needed for LDAP bind-through auth (§8)
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_hash TEXT,                   -- fingerprint of managed fields, avoids needless UPDATEs
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_synced_at TIMESTAMPTZ,
    UNIQUE (source_id, external_id)     -- one external identity links to one local user
);

CREATE INDEX directory_entries_user_idx ON directory_entries (user_id);

-- ── users: local intent + directory-sourced groups ──────────────────────
--
-- `local_disabled` is a *local* disable intent kept separate from the upstream
-- status, so the next sync cannot silently re-enable a user an admin disabled.
-- Only an explicit admin enable clears it; sync never writes it (§4.2).
--
-- `directory_groups` is kept apart from the locally-managed `groups` column so
-- sync can replace directory-sourced membership without clobbering local ones.
ALTER TABLE users
    ADD COLUMN local_disabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN directory_groups TEXT[] NOT NULL DEFAULT '{}';
