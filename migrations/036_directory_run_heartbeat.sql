-- Liveness for a running sync.
--
-- `directory_sync_runs.status = 'running'` was aged out by `started_at` alone:
-- a legitimate sync longer than two hours (a large LDAP tree over a slow WAN)
-- was marked failed while still running, which released the one-run-per-source
-- index and let a second run start against the same source — exactly the
-- interleaving migration 025 exists to prevent. The sweep now ages on a
-- heartbeat the engine refreshes, so "no progress" is the signal instead of
-- "long-running". NULL means a row from before this column existed (or one
-- that has not ticked yet); the queries fall back to `started_at` for those.
ALTER TABLE directory_sync_runs
    ADD COLUMN heartbeat_at TIMESTAMPTZ;

UPDATE directory_sync_runs SET heartbeat_at = started_at WHERE status = 'running';
