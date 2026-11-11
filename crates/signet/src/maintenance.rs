//! Periodic housekeeping: audit retention and expired-credential sweeps.
//!
//! Audit pruning used to run exactly once, at boot — a long-lived instance
//! accumulated past its `SIGNET_AUDIT_RETENTION_DAYS` until the next restart.
//! The same boot-only gap applied to every table that mints expiring rows:
//! sessions, authorization codes, MFA challenges, password-reset tokens,
//! registration tokens and pending SSO links are all filtered on `expires_at`
//! by their readers, so stale rows are harmless but unbounded — and for an IdP
//! that mints a session per sign-in, that growth is the slow kind of outage.
//!
//! One hourly task covers both. Deletions are bounded per tick (the tables are
//! indexed on their expiry columns and the sweeps run off-peak relative to
//! nothing in particular), and every failure is logged, never fatal: a failed
//! sweep retries in an hour, while a panicked task would silence the sweep
//! for the life of the process.

use crate::state::AppState;
use std::time::Duration;

/// How often the sweeper runs.
const TICK: Duration = Duration::from_secs(60 * 60);

/// Rows deleted per table per tick. A backlog (first boot after months, or a
/// retention change) drains over several ticks instead of one long-running
/// DELETE that holds locks across the hottest tables.
const BATCH: i64 = 5_000;

/// Spawns the background sweeper. Startup only — tests and the CLI drive
/// [`sweep_once`] directly when they want it.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TICK).await;
            let days = state.rt().audit_retention_days;
            if let Err(e) = sweep_once(&state, days).await {
                tracing::warn!(error = %e, "maintenance sweep failed; retrying next tick");
            }
        }
    });
}

/// One pass of the sweeper: audit retention plus the expired-token tables.
///
/// Public for tests and for a future CLI entry point (`signet sweep`).
pub async fn sweep_once(state: &AppState, retention_days: i64) -> anyhow::Result<()> {
    let pool = &state.pool;
    let pruned = crate::audit::prune_audit_logs(pool, retention_days).await?;
    if pruned > 0 {
        tracing::info!(pruned, retention_days, "pruned audit logs");
    }

    for (table, column) in EXPIRING_TABLES {
        // Postgres has no `DELETE ... LIMIT`; the bounded form deletes by the
        // primary keys of one batch of expired rows.
        let deleted = sqlx::query(&format!(
            "DELETE FROM {table} WHERE id IN \
             (SELECT id FROM {table} WHERE {column} < NOW() LIMIT {BATCH})"
        ))
        .execute(pool)
        .await?
        .rows_affected();
        if deleted > 0 {
            tracing::debug!(table, deleted, "swept expired rows");
        }
    }

    // Age-based retention for the two append-only tables with no expiry column.
    // `login_devices` is a "have I seen this IP before" memo, not an audit
    // record: after 90 days an address counts as new again, which re-arms the
    // new-device alert rather than leaking anything. Delivery history is
    // diagnostic only.
    for (table, column, days) in RETENTION_TABLES {
        let deleted = sqlx::query(&format!(
            "DELETE FROM {table} WHERE id IN \
             (SELECT id FROM {table} \
              WHERE {column} < NOW() - ($1::int * INTERVAL '1 day') LIMIT {BATCH})"
        ))
        .bind(days)
        .execute(pool)
        .await?
        .rows_affected();
        if deleted > 0 {
            tracing::debug!(table, deleted, days, "swept rows past retention");
        }
    }
    Ok(())
}

/// `(table, age column, retention days)` for tables swept by age rather than by
/// an `expires_at` timestamp.
const RETENTION_TABLES: &[(&str, &str, i32)] = &[
    ("login_devices", "last_seen_at", 90),
    ("webhook_deliveries", "created_at", 30),
    // Sync history is diagnostic, not an audit record (the audit log carries
    // the durable account). A five-minute schedule writes ~105k rows a year.
    ("directory_sync_runs", "started_at", 90),
];

/// `(table, expiry column)` pairs swept every tick.
///
/// `sessions` uses the same column its reader filters on; `mfa_challenges`'
/// pending TOTP secrets are the reason its expiry is enforced as a deletion and
/// not just a read filter.
const EXPIRING_TABLES: &[(&str, &str)] = &[
    ("sessions", "expires_at"),
    ("auth_codes", "expires_at"),
    ("mfa_challenges", "expires_at"),
    ("password_reset_tokens", "expires_at"),
    ("registration_access_tokens", "expires_at"),
    ("identity_link_challenges", "expires_at"),
];
