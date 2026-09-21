//! Database access for the sync engine: snapshot loaders and run bookkeeping.
//!
//! The loaders exist to hand [`crate::directory::plan`] a consistent picture of
//! the local side. They deliberately snapshot *before* any write: the planner
//! reasons about one point in time, and the apply step then executes the plan
//! without re-reading, so a concurrent local edit cannot make the plan
//! self-contradictory halfway through.

use crate::directory::plan::{LinkSnapshot, LocalState, UserIndexEntry, UserSnapshot};
use crate::directory::source::SourceRow;
use crate::directory::source::SOURCE_ROW_COLS;
use crate::error::{AppError, AppResult};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

pub const RUN_COLS: &str = "id, source_id, trigger, status, started_at, finished_at, scanned, \
    created_count, updated_count, disabled_count, skipped_count, conflict_count, error_count, \
    error, actor_user_id, stats";

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct RunRow {
    pub id: Uuid,
    pub source_id: Uuid,
    pub trigger: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub scanned: i32,
    pub created_count: i32,
    pub updated_count: i32,
    pub disabled_count: i32,
    pub skipped_count: i32,
    pub conflict_count: i32,
    pub error_count: i32,
    pub error: Option<String>,
    pub actor_user_id: Option<Uuid>,
    pub stats: Value,
}

/// Links this source owns.
pub async fn load_links(pool: &PgPool, source_id: Uuid) -> AppResult<Vec<LinkSnapshot>> {
    let rows = sqlx::query_as::<_, (String, Uuid, Option<String>)>(
        "SELECT external_id, user_id, source_hash FROM directory_entries WHERE source_id = $1",
    )
    .bind(source_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(external_id, user_id, source_hash)| LinkSnapshot {
            external_id,
            user_id,
            source_hash,
        })
        .collect())
}

/// Managed attributes of the linked users, needed to diff against the directory.
pub async fn load_linked_users(
    pool: &PgPool,
    links: &[LinkSnapshot],
) -> AppResult<Vec<UserSnapshot>> {
    let ids: Vec<Uuid> = links.iter().map(|l| l.user_id).collect();
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            Option<String>,
            String,
            String,
            Vec<String>,
            bool,
        ),
    >(
        "SELECT id, email, username, display_name, status, directory_groups, directory_disabled \
         FROM users WHERE id = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, email, username, display_name, status, directory_groups, directory_disabled)| {
                UserSnapshot {
                    id,
                    email,
                    username,
                    display_name,
                    status,
                    directory_groups,
                    directory_disabled,
                }
            },
        )
        .collect())
}

/// Identity of every local user, for collision detection.
///
/// The whole table is read rather than looking entries up one at a time: an
/// upstream entry can collide with *any* local account, so there is no smaller
/// complete answer, and three columns per user is far cheaper than one query per
/// directory entry.
pub async fn load_user_index(pool: &PgPool) -> AppResult<Vec<UserIndexEntry>> {
    let rows = sqlx::query_as::<_, (Uuid, String, Option<String>)>(
        "SELECT id, email, username FROM users",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, email, username)| UserIndexEntry {
            id,
            email,
            username,
        })
        .collect())
}

/// `user_id` → code of the highest-precedence source linking it, across all
/// sources (matching [`crate::directory::managing_source`]).
///
/// Deliberately **not** scoped to the run's own links, even though that would
/// make it far cheaper. Two of the three callers ask about a user the source
/// does not link: `collision_change` asks after finding an account by *email*,
/// which can be a user any other source provisioned, and answering "nobody
/// outranks them" there flips a skip into a conflict — the account-takeover
/// case. The planner is a pure function over this snapshot, so it cannot ask
/// for one more row when it discovers it needs one; the snapshot has to be
/// complete. A narrower query here is a silent behaviour change, not an
/// optimization.
pub async fn load_managing_sources(pool: &PgPool) -> AppResult<HashMap<Uuid, String>> {
    let rows = sqlx::query_as::<_, (Uuid, String)>(
        r#"
        SELECT DISTINCT ON (e.user_id) e.user_id, s.code
        FROM directory_entries e
        JOIN directory_sources s ON s.id = e.source_id
        ORDER BY e.user_id, s.priority ASC, s.code ASC
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().collect())
}

/// Assembles the complete local picture for one source.
pub async fn load_local_state(
    pool: &PgPool,
    source_id: Uuid,
    source_code: &str,
) -> AppResult<LocalState> {
    // Two rounds rather than four sequential queries. The sync is a background
    // job, but its snapshot is on the critical path of every run, and the
    // identity read is the largest query in the engine — there is no reason for
    // it to wait behind the link read, or for the two queries that need the
    // links to wait for each other.
    let (links, index) = tokio::try_join!(load_links(pool, source_id), load_user_index(pool))?;
    let (linked_users, managing) =
        tokio::try_join!(load_linked_users(pool, &links), load_managing_sources(pool),)?;
    Ok(LocalState {
        source_code: source_code.to_string(),
        links,
        linked_users,
        index,
        managing,
    })
}

/// Opens a run row so the history exists even if the process dies mid-sync.
///
/// The partial unique index from migration `025` allows only one `running` row
/// per source, so losing the race to another trigger surfaces as a conflict
/// rather than as two interleaved syncs.
pub async fn begin_run(
    pool: &PgPool,
    source_id: Uuid,
    trigger: &str,
    actor_user_id: Option<Uuid>,
) -> AppResult<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO directory_sync_runs (id, source_id, trigger, status, actor_user_id)
        VALUES ($1, $2, $3, 'running', $4)
        "#,
    )
    .bind(id)
    .bind(source_id)
    .bind(trigger)
    .bind(actor_user_id)
    .execute(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db)
            if db.constraint() == Some("directory_sync_runs_one_running_idx") =>
        {
            AppError::conflict("another sync run for this source is already in progress")
        }
        other => AppError::from(other),
    })?;
    Ok(id)
}

/// Closes a run with its final counters.
#[allow(clippy::too_many_arguments)]
pub async fn finish_run(
    pool: &PgPool,
    run_id: Uuid,
    status: &str,
    scanned: i64,
    counts: crate::directory::plan::Counts,
    error: Option<&str>,
    stats: &Value,
) -> AppResult<()> {
    sqlx::query(
        r#"
        UPDATE directory_sync_runs
        SET status = $2, finished_at = NOW(), scanned = $3, created_count = $4,
            updated_count = $5, disabled_count = $6, skipped_count = $7,
            conflict_count = $8, error_count = $9, error = $10, stats = $11
        WHERE id = $1
        "#,
    )
    .bind(run_id)
    .bind(status)
    .bind(scanned as i32)
    .bind(counts.created as i32)
    .bind(counts.updated as i32)
    .bind(counts.disabled as i32)
    .bind(counts.skipped as i32)
    .bind(counts.conflicts as i32)
    .bind(counts.errors as i32)
    .bind(error)
    .bind(stats)
    .execute(pool)
    .await?;
    Ok(())
}

/// Closes runs abandoned by a crash, so the history never shows a perpetually
/// "running" entry and the source is not wedged forever.
///
/// Only runs older than `older_than_minutes` are touched: a run that is genuinely
/// in flight must stay `running`, otherwise a second trigger would start
/// alongside it.
pub async fn fail_stale_runs(
    pool: &PgPool,
    source_id: Uuid,
    older_than_minutes: i64,
    reason: &str,
) -> AppResult<u64> {
    let res = sqlx::query(
        r#"
        UPDATE directory_sync_runs
        SET status = 'failed', finished_at = NOW(), error = $2
        WHERE source_id = $1
          AND status = 'running'
          AND started_at < NOW() - ($3 || ' minutes')::interval
        "#,
    )
    .bind(source_id)
    .bind(reason)
    .bind(older_than_minutes.to_string())
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Sources the scheduler should run now (§10).
///
/// "Due" means all four of:
///
/// * `enabled` — an admin switched it off;
/// * `interval_minutes IS NOT NULL` — `NULL` means manual-trigger-only, which is
///   how a source is configured for a first cautious rollout;
/// * no *live* run — a source already syncing is not due, whatever the clock
///   says. This is what makes a slow sync (longer than its own interval) not pile
///   up behind itself;
/// * the last run *started* at least `interval_minutes` ago.
///
/// Two subtleties worth stating. First, absence of any run counts as due, so a
/// newly configured source syncs on the next tick rather than after a full
/// interval of silence. Second, the comparison is against the last `started_at`,
/// not `finished_at`: measuring from the finish would stretch the effective
/// period by the runtime, and a source that always fails would still be retried
/// every interval rather than hammered.
///
/// `stale_minutes` is the caller's [`crate::directory::engine::STALE_RUN_MINUTES`]
/// and it is load-bearing: a run left `running` by a crash must not count as
/// live, or that source would never sync again. The recovery itself is
/// [`fail_stale_runs`], which `begin_run`'s caller runs before inserting — so
/// reporting a stale source as due is what un-wedges it.
pub async fn due_sources(pool: &PgPool, stale_minutes: i64) -> AppResult<Vec<SourceRow>> {
    let rows = sqlx::query_as::<_, SourceRow>(&format!(
        r#"
        SELECT {SOURCE_ROW_COLS}
        FROM directory_sources s
        WHERE s.enabled
          AND s.interval_minutes IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM directory_sync_runs r
              WHERE r.source_id = s.id
                AND r.status = 'running'
                AND r.started_at >= NOW() - ($1 || ' minutes')::interval
          )
          AND COALESCE(
                  (SELECT MAX(r.started_at) FROM directory_sync_runs r WHERE r.source_id = s.id),
                  TIMESTAMPTZ '-infinity'
              ) <= NOW() - (s.interval_minutes || ' minutes')::interval
        ORDER BY s.priority ASC, s.code ASC
        "#
    ))
    .bind(stale_minutes.to_string())
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn list_runs(pool: &PgPool, source_id: Uuid, limit: i64) -> AppResult<Vec<RunRow>> {
    let rows = sqlx::query_as::<_, RunRow>(&format!(
        "SELECT {RUN_COLS} FROM directory_sync_runs \
         WHERE source_id = $1 ORDER BY started_at DESC LIMIT $2"
    ))
    .bind(source_id)
    .bind(limit.clamp(1, 200))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_run(pool: &PgPool, source_id: Uuid, run_id: Uuid) -> AppResult<Option<RunRow>> {
    let row = sqlx::query_as::<_, RunRow>(&format!(
        "SELECT {RUN_COLS} FROM directory_sync_runs WHERE source_id = $1 AND id = $2"
    ))
    .bind(source_id)
    .bind(run_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}
