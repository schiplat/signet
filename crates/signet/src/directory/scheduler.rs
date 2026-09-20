//! Background scheduling (§10).
//!
//! One loop, one minute per tick, and every tick asks the database which sources
//! are due. The scheduling decision lives entirely in that query
//! ([`model::due_sources`]) rather than in the process: a replica that restarts
//! does not lose its place, and two replicas reading the same table cannot
//! disagree about what is due.
//!
//! **On cross-replica exclusivity.** §10 prescribes a `pg_try_advisory_lock`
//! per source. That is not implemented, and the reason is worth recording.
//! Session-level advisory locks belong to the *connection* that took them, while
//! this code acquires and releases connections per query from a pool — so
//! "lock, spawn a task, unlock" would silently fail to hold anything, and a lock
//! that does not hold is worse than no lock because it reads as protection.
//!
//! The protection itself is already in place by a stronger mechanism: migration
//! `025` puts a partial unique index on `directory_sync_runs (source_id) WHERE
//! status = 'running'`, so `model::begin_run` can only insert one live run per
//! source, across every replica and every trigger (schedule, manual, CLI). A
//! losing replica gets a `Conflict` before it touches the directory, and nothing
//! is written twice. You cannot forget a database constraint.

use crate::directory::engine::{self, Trigger};
use crate::directory::model;
use crate::directory::source::SourceRow;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use std::time::Duration;

/// How often the loop looks for due sources.
///
/// One minute bounds the scheduling error independently of `interval_minutes`:
/// an interval of 5 minutes runs at 5–6 minutes, never at 10. Ticking faster
/// would only add queries; the per-source interval still decides what runs.
const TICK: Duration = Duration::from_secs(60);

/// Starts the scheduler. Called once from [`crate::build_app`].
///
/// Not started by [`crate::build_state`], so the CLI and the test harness never
/// get a background loop they did not ask for.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(TICK);
        // The first tick of a `tokio` interval is immediate. Consuming it would
        // mean every process start fires a round of syncs, so skip it: a restart
        // loop must not become a sync loop.
        ticker.tick().await;
        // If a tick is missed (a long-running `run_due`, or the process was
        // starved), delay rather than burst: catching up is not worth a
        // thundering herd of directory connections.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            match run_due(&state).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(started = n, "started scheduled directory syncs"),
                // A failure here is a database problem, not a sync problem: the
                // loop must survive it and try again next tick, so it is logged
                // and swallowed rather than propagated.
                Err(e) => tracing::error!(error = %e, "directory sync scheduler tick failed"),
            }
        }
    });
}

/// Starts a run for every source that is due, and returns how many were started.
///
/// Public because it is the seam the DB-backed tests drive: the loop around it
/// only decides *when* to call this.
pub async fn run_due(state: &AppState) -> AppResult<usize> {
    let due: Vec<SourceRow> = model::due_sources(&state.pool, engine::STALE_RUN_MINUTES).await?;
    let mut started = 0;
    for row in due {
        match engine::spawn_source(state, &row.code, Trigger::Schedule, None).await {
            Ok(run_id) => {
                started += 1;
                tracing::info!(source = %row.code, %run_id, "scheduled directory sync started");
            }
            // Another replica (or a manual trigger) holds this source. That is
            // the expected outcome of a correct race, so it is not a warning:
            // logging it loudly would train operators to ignore the level.
            Err(AppError::Conflict(_)) => {
                tracing::debug!(source = %row.code, "directory source is already syncing, skipping");
            }
            // A misconfigured source fails to even open a run row. Skip it and
            // let the rest of the round proceed — one broken source must not
            // stop every other directory from syncing.
            Err(e) => {
                tracing::error!(error = %e, source = %row.code, "cannot start scheduled directory sync");
            }
        }
    }
    Ok(started)
}
