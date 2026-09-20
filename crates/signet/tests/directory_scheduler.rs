//! Scheduler contracts (docs/directory-sync.md §10).
//!
//! "Which sources run now?" is a single SQL predicate, and every clause in it
//! guards a distinct failure mode: an admin's off switch, cautious manual-only
//! rollout, a slow sync overlapping itself, and a crash wedging a source forever.
//! Each of those gets a test here, because each is one `AND` away from silently
//! running something it should not — or from never running something again.
//!
//! The clock is controlled by writing `directory_sync_runs` rows with explicit
//! `started_at` values rather than by sleeping, so the tests are deterministic.
//! Every test runs through [`common::scoped`], so a failing assertion still
//! removes its source — otherwise the next run would see leftover scheduled
//! sources in the same database.

mod common;

use signet::directory::engine::STALE_RUN_MINUTES;
use signet::directory::model::due_sources;
use signet::directory::scheduler::run_due;
use signet::directory::source::SourceRow;
use signet::state::AppState;
use sqlx::PgPool;
use uuid::Uuid;

/// Serializes the tests in this file.
///
/// [`run_due`] is deliberately global — it is the scheduler's entry point, so it
/// starts a run for *every* due source in the database, not just one. Two tests
/// calling it while a sibling asserts "this source is due" would therefore race on
/// shared state: the sibling's source gets a fresh run row and stops being due.
/// A file-local lock is enough because this is the only test binary that calls
/// `run_due`.
static HARNESS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Sets the source's schedule. `None` means manual-trigger-only.
async fn set_interval(pool: &PgPool, source_id: Uuid, minutes: Option<i32>) {
    sqlx::query("UPDATE directory_sources SET interval_minutes = $2 WHERE id = $1")
        .bind(source_id)
        .bind(minutes)
        .execute(pool)
        .await
        .expect("set the schedule interval");
}

/// Seeds a run row with an explicit start time and status.
///
/// `minutes_ago` is relative to the database's clock, not the test process's, so
/// the comparison in `due_sources` is exercised against the same clock it uses.
async fn seed_run(pool: &PgPool, source_id: Uuid, status: &str, minutes_ago: i64) {
    sqlx::query(
        r#"
        INSERT INTO directory_sync_runs (id, source_id, trigger, status, started_at)
        VALUES ($1, $2, 'schedule', $3, NOW() - ($4 || ' minutes')::interval)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(source_id)
    .bind(status)
    .bind(minutes_ago.to_string())
    .execute(pool)
    .await
    .expect("seed a run row");
}

/// Removes the source's run history, so a test can assert on a fresh interval
/// without carving out a second source.
async fn clear_runs(pool: &PgPool, source_id: Uuid) {
    sqlx::query("DELETE FROM directory_sync_runs WHERE source_id = $1")
        .bind(source_id)
        .execute(pool)
        .await
        .expect("clear the run history");
}

/// `due_sources` is global, so every assertion has to look at one source rather
/// than at the whole list — other tests' sources are in the same database.
async fn is_due(state: &AppState, source: &SourceRow) -> bool {
    due_sources(&state.pool, STALE_RUN_MINUTES)
        .await
        .expect("query due sources")
        .iter()
        .any(|row| row.id == source.id)
}

async fn count_runs(pool: &PgPool, source_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM directory_sync_runs WHERE source_id = $1")
        .bind(source_id)
        .fetch_one(pool)
        .await
        .expect("count the runs")
}

#[tokio::test]
async fn a_never_run_source_is_due_on_the_next_tick() {
    let Some(state) = common::state().await else {
        return;
    };
    // See `HARNESS`: `run_due` is global, so these tests cannot overlap.
    let _guard = HARNESS.lock().await;
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        set_interval(&state.pool, source.id, Some(60)).await;

        // Waiting a full interval before the first sync would make a newly
        // configured source look broken for an hour.
        assert!(is_due(&state, &source).await);
    })
    .await;
}

#[tokio::test]
async fn a_manual_only_source_is_never_due() {
    let Some(state) = common::state().await else {
        return;
    };
    // See `HARNESS`: `run_due` is global, so these tests cannot overlap.
    let _guard = HARNESS.lock().await;
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        set_interval(&state.pool, source.id, None).await;
        seed_run(&state.pool, source.id, "succeeded", 10_000).await;

        assert!(
            !is_due(&state, &source).await,
            "NULL interval_minutes means an admin must trigger this source by hand"
        );
    })
    .await;
}

#[tokio::test]
async fn a_disabled_source_is_never_due() {
    let Some(state) = common::state().await else {
        return;
    };
    // See `HARNESS`: `run_due` is global, so these tests cannot overlap.
    let _guard = HARNESS.lock().await;
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        set_interval(&state.pool, source.id, Some(60)).await;
        sqlx::query("UPDATE directory_sources SET enabled = FALSE WHERE id = $1")
            .bind(source.id)
            .execute(&state.pool)
            .await
            .expect("disable the source");

        assert!(
            !is_due(&state, &source).await,
            "switching a source off must stop the clock too"
        );
    })
    .await;
}

#[tokio::test]
async fn the_interval_decides_when_a_source_is_due_again() {
    let Some(state) = common::state().await else {
        return;
    };
    // See `HARNESS`: `run_due` is global, so these tests cannot overlap.
    let _guard = HARNESS.lock().await;
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        set_interval(&state.pool, source.id, Some(60)).await;

        seed_run(&state.pool, source.id, "succeeded", 5).await;
        assert!(
            !is_due(&state, &source).await,
            "a run five minutes into a sixty-minute interval must not be repeated"
        );

        clear_runs(&state.pool, source.id).await;
        seed_run(&state.pool, source.id, "succeeded", 120).await;
        assert!(
            is_due(&state, &source).await,
            "the interval has elapsed since the most recent start"
        );
    })
    .await;
}

/// A failed run must not stop the next attempt: the interval is measured from the
/// start, so a source that keeps failing is retried once per interval rather than
/// hammered or abandoned.
#[tokio::test]
async fn a_failed_run_still_counts_towards_the_interval() {
    let Some(state) = common::state().await else {
        return;
    };
    // See `HARNESS`: `run_due` is global, so these tests cannot overlap.
    let _guard = HARNESS.lock().await;
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        set_interval(&state.pool, source.id, Some(60)).await;

        seed_run(&state.pool, source.id, "failed", 5).await;
        assert!(!is_due(&state, &source).await, "no retry storm");

        clear_runs(&state.pool, source.id).await;
        seed_run(&state.pool, source.id, "failed", 90).await;
        assert!(is_due(&state, &source).await, "but it does try again");
    })
    .await;
}

/// A live run blocks the source, even if its own interval has long elapsed. This
/// is the property that stops a slow directory from being synced twice at once.
#[tokio::test]
async fn a_live_run_blocks_the_source_regardless_of_the_interval() {
    let Some(state) = common::state().await else {
        return;
    };
    // See `HARNESS`: `run_due` is global, so these tests cannot overlap.
    let _guard = HARNESS.lock().await;
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        set_interval(&state.pool, source.id, Some(1)).await;
        seed_run(&state.pool, source.id, "running", 5).await;

        assert!(
            !is_due(&state, &source).await,
            "a run in flight must not be duplicated just because the interval is short"
        );
    })
    .await;
}

/// The counterpart to the previous test, and the reason `STALE_RUN_MINUTES` is
/// shared: a run left `running` by a crash must eventually stop blocking, or that
/// source would never sync again and the outage would only be visible as silence.
///
/// It is the *scheduler* recovering here, with no manual trigger involved: the
/// source is reported due, and [`run_due`] then closes the abandoned row before
/// opening a fresh one.
#[tokio::test]
async fn a_crashed_run_is_recovered_instead_of_wedging_the_source_forever() {
    let Some(state) = common::state().await else {
        return;
    };
    // See `HARNESS`: `run_due` is global, so these tests cannot overlap.
    let _guard = HARNESS.lock().await;
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        set_interval(&state.pool, source.id, Some(60)).await;
        seed_run(&state.pool, source.id, "running", STALE_RUN_MINUTES + 60).await;

        assert!(
            is_due(&state, &source).await,
            "an abandoned run must not make a source permanently ineligible"
        );

        run_due(&state).await.expect("run the scheduler once");

        // Exactly one run row may be live, and it must be the new one. Asserting
        // the count also pins the partial unique index from migration 025: if the
        // stale row were still `running`, inserting the new one would have failed
        // and there would be no second row at all.
        let (running, failed): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*) FILTER (WHERE status = 'running'), \
                    COUNT(*) FILTER (WHERE status = 'failed') \
             FROM directory_sync_runs WHERE source_id = $1",
        )
        .bind(source.id)
        .fetch_one(&state.pool)
        .await
        .expect("count the runs");
        assert_eq!(running, 1, "the replacement run must be live");
        assert_eq!(failed, 1, "the abandoned run must have been closed");
    })
    .await;
}

/// A second tick immediately after the first must start nothing: the run opened
/// by the first tick is live, so the source is no longer due. This is the
/// in-process half of multi-replica safety; the cross-replica half is the partial
/// unique index, pinned above and in `directory_engine.rs`.
#[tokio::test]
async fn a_second_tick_does_not_start_a_second_run() {
    let Some(state) = common::state().await else {
        return;
    };
    // See `HARNESS`: `run_due` is global, so these tests cannot overlap.
    let _guard = HARNESS.lock().await;
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        set_interval(&state.pool, source.id, Some(60)).await;

        // `run_due` is global, so the assertions count *this* source's run rows
        // rather than trusting the returned total, which includes every source in
        // the database.
        run_due(&state).await.expect("run the scheduler once");
        let after_first = count_runs(&state.pool, source.id).await;
        assert_eq!(
            after_first, 1,
            "the new source must start on the first tick"
        );

        run_due(&state).await.expect("run the scheduler again");
        assert_eq!(
            count_runs(&state.pool, source.id).await,
            after_first,
            "the run opened by the first tick must make the source ineligible"
        );
    })
    .await;
}
