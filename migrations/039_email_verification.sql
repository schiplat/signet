-- Verified-email infrastructure, consumed by self-service email change.
--
-- `users.email_verified`: grandfathered true — existing accounts were created
-- by an admin (or SCIM/JIT with a verified upstream email), so there is no
-- address to verify retroactively. New addresses become verified only through
-- the change-request flow (or by an admin / a verified upstream).
--
-- `email_change_tokens`: one live change request per user; the token is
-- single-use and hashed like the password-reset flow it mirrors.
ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE email_change_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    new_email TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX email_change_tokens_user_idx ON email_change_tokens (user_id);
