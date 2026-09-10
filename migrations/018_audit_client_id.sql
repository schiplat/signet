-- 018: per-client audit attribution
--
-- audit_logs.client_id stores the OAuth client identifier (TEXT snapshot,
-- intentionally NOT a UUID FK to client_apps so attribution survives
-- client deletion). Historical rows keep NULL and surface as
-- "Signet (direct)" in dashboards.

ALTER TABLE audit_logs
    ADD COLUMN client_id TEXT;

-- Filter: audit list by app.
CREATE INDEX audit_logs_client_id_idx ON audit_logs(client_id);

-- Covers the global login-trend queries (action + time range).
CREATE INDEX audit_logs_action_created_idx
    ON audit_logs(action, created_at DESC);

-- Per-app trend / stats (partial: only attributable rows).
CREATE INDEX audit_logs_client_created_idx
    ON audit_logs(client_id, created_at DESC)
    WHERE client_id IS NOT NULL;
