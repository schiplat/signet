-- Federated identity phase 1: upstream providers + local account linking.
--
-- upstream_providers: admin-configured upstream identity providers (GitHub,
-- Google, Feishu, WeChat Open Platform, or any generic OIDC issuer).
-- client_secret is encrypted at rest with the application Encryptor
-- (AES-256-GCM), same scheme as TOTP secrets.
--
-- user_identities: links a local user to one identity at one upstream
-- provider. (provider_code, subject) is globally unique: one upstream
-- identity maps to exactly one local user; one user may link many providers.

CREATE TABLE upstream_providers (
    code TEXT PRIMARY KEY,              -- short slug used in URLs, e.g. 'github'
    provider_type TEXT NOT NULL,        -- 'github' | 'google' | 'feishu' | 'wechat' | 'oidc'
    display_name TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret_enc TEXT NOT NULL,    -- Encryptor-encrypted client secret
    issuer_url TEXT,                    -- oidc only: discovery root
    scopes TEXT NOT NULL DEFAULT '',    -- space-separated, provider default when empty
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE user_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_code TEXT NOT NULL REFERENCES upstream_providers(code) ON DELETE CASCADE,
    subject TEXT NOT NULL,              -- stable upstream id (github id, google sub, unionid...)
    email TEXT,                         -- upstream email at link time (informational)
    raw JSONB NOT NULL DEFAULT '{}',    -- last-seen upstream profile (debug/support)
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    UNIQUE (provider_code, subject)
);

CREATE INDEX user_identities_user_idx ON user_identities(user_id);

CREATE TABLE identity_link_challenges (
    id UUID PRIMARY KEY,                -- also used as the signed-in handshake state
    state TEXT NOT NULL UNIQUE,         -- CSRF state stored in an HttpOnly cookie
    code_hash TEXT NOT NULL,            -- SHA-256 of the upstream authorization code
    email TEXT,                         -- verified email from the upstream profile
    display_name TEXT,
    provider_code TEXT NOT NULL,
    subject TEXT NOT NULL,
    raw JSONB NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX identity_link_challenges_expiry_idx ON identity_link_challenges(expires_at);
