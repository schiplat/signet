-- 025 Directory sync: at most one running run per source.
--
-- Two concurrent runs of the same source would each plan from the same snapshot,
-- so both would try to create the same users (colliding on unique constraints)
-- and both would apply a "user absent upstream" list computed before the other
-- run's writes. Serializing runs per source makes that state unreachable.
--
-- The scheduler (P3) additionally takes a `pg_advisory_lock` so that a second
-- replica does not even attempt the work; this index is the last line of defence
-- and also covers the manual-trigger and CLI paths, which have no lock.
CREATE UNIQUE INDEX directory_sync_runs_one_running_idx
    ON directory_sync_runs (source_id)
    WHERE status = 'running';
