-- Durable delivery queue for outbound notifications (webhooks and email).
--
-- Both used to be fire-and-forget: webhooks spawned a task with one attempt
-- (a process restart lost in-flight dispatches; a receiver blip lost the
-- event for good) and the reset email was awaited inline, so a slow relay
-- stalled the request that most needed to be fast. An outbox fixes both:
-- enqueue synchronously, deliver from a background worker with backoff.
--
-- The email body can carry a one-time reset link, so it is stored under the
-- application's AES-GCM key (same policy as TOTP seeds), not plaintext.
CREATE TABLE outbox (
    id UUID PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('webhook', 'email')),
    -- webhook delivery
    webhook_id UUID REFERENCES webhooks(id) ON DELETE CASCADE,
    event_id UUID,
    payload JSONB,
    -- email delivery
    email_to TEXT,
    email_subject TEXT,
    email_body_enc TEXT,
    email_log_body BOOLEAN,
    -- delivery bookkeeping
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX outbox_due_idx ON outbox (next_attempt_at) WHERE attempts < 5;
