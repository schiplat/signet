-- Retire the duplicate audit index.
--
-- `005_login_ip_client_allowlist.sql` created
-- `audit_logs_action_created_at_idx` on (action, created_at DESC);
-- `018_audit_client_id.sql` created `audit_logs_action_created_idx` with the
-- identical definition. Postgres maintains both, so every audit insert writes
-- two copies of the same index — pure write amplification on the hottest
-- insert table. The earlier one stays; the duplicate goes.
DROP INDEX IF EXISTS audit_logs_action_created_idx;

-- Note for future readers of `025_directory_sync_single_run.sql`: its comment
-- says the scheduler "additionally takes a pg_try_advisory_lock". It does not —
-- the single-run invariant is enforced by the partial unique index that
-- migration creates, and `directory/scheduler.rs` explains why a pool-owned
-- advisory lock was rejected. The comment cannot be edited in place: sqlx
-- verifies migration checksums, so changing an applied file breaks every
-- existing deployment. This note is the correction.
