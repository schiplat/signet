-- Public self-registration, off by default.
--
-- A sign-up request is not an account: the email, display name and already
-- hashed password sit here until the address is proven by clicking the link
-- sent to it. Only then is a `users` row created. This is what makes claiming
-- somebody else's address impossible without access to their mailbox, and it
-- keeps every abandoned attempt out of the directory (and out of the admin
-- statistics).
--
-- The link token is stored as its SHA-256 digest, is single-use (the row is
-- deleted on confirmation) and expires after 30 minutes. One row per address:
-- requesting again replaces the token, so an older link stops working instead
-- of staying live for its full window.
CREATE TABLE signup_requests (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    ip TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Always stored lowercased by the handler; the constraint is the last line of
-- defence against a second live request for the same mailbox.
CREATE UNIQUE INDEX signup_requests_email_key ON signup_requests (email);
CREATE INDEX signup_requests_expires_idx ON signup_requests (expires_at);

-- Append-only throttle counters.
--
-- Deliberately separate from signup_requests: a repeat request replaces its
-- pending row, so counting those rows would let one address hide repeated
-- attempts. These rows are counted only, never joined to an identity, and are
-- swept after a day.
CREATE TABLE signup_attempts (
    id BIGSERIAL PRIMARY KEY,
    ip TEXT,
    email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX signup_attempts_ip_idx ON signup_attempts (ip, created_at);
CREATE INDEX signup_attempts_email_idx ON signup_attempts (email, created_at);
