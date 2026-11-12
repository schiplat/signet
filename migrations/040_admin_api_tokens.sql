-- Admin API machine credentials ("PAT"): bearer tokens that let automation
-- (CI, cron, scripts) call the admin API without a browser session.
--
-- A token is bound to its creator and carries no authority of its own: every
-- call resolves the owning user and applies their *current* role, status and
-- must_change_password gate, so demoting or disabling an admin retires their
-- tokens' power on the next request. The plaintext is shown once at creation;
-- only the SHA-256 digest is stored.
CREATE TABLE admin_api_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_admin_api_tokens_user ON admin_api_tokens(user_id);
