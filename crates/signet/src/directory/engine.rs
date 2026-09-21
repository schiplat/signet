//! Sync orchestration: counters, run history, audit, and the writes (§6.1, §11).
//!
//! The shape is always the same: fetch the whole upstream set, snapshot the local
//! side, plan (pure), then apply. Because the plan is computed before anything is
//! written, a connector failure aborts without touching the database, and
//! `--dry-run` produces exactly the report a real run would.

use crate::audit::AuditEvent;
use crate::directory::http_json;
use crate::directory::ldap::LdapConnector;
use crate::directory::model::{self, RunRow};
use crate::directory::plan::{self, Change, Counts, Outcome, PlanOptions, SyncPlan};
use crate::directory::source::{self, SourceConfig, SourceRow};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

/// Audit actions written by the engine (§11.1).
pub const AUDIT_SYNC_STARTED: &str = "directory.sync.started";
pub const AUDIT_SYNC_FINISHED: &str = "directory.sync.finished";
pub const AUDIT_SYNC_FAILED: &str = "directory.sync.failed";
pub const AUDIT_USER_CREATED: &str = "directory.user.created";
pub const AUDIT_USER_DISABLED: &str = "directory.user.disabled";
pub const AUDIT_CONFLICT: &str = "directory.conflict";

/// Entries per transaction. Small enough that a failure mid-run does not discard
/// much work, large enough that a 100k-user sync is not 100k round trips.
const CHUNK: usize = 200;

/// A run still marked `running` after this long is assumed to be a crash
/// leftover (no sync legitimately takes two hours) and is closed so the source
/// is not wedged permanently.
///
/// Published because the scheduler needs the same number: see
/// [`crate::directory::model::due_sources`], where a run older than this must not
/// be treated as blocking. Two constants drifting apart would either wedge a
/// source forever or start a second run alongside a live one.
pub const STALE_RUN_MINUTES: i64 = 120;

/// Why a run happened. Mirrors the `directory_sync_runs.trigger` CHECK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    Manual,
    Schedule,
    Cli,
    Push,
}

impl Trigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Schedule => "schedule",
            Self::Cli => "cli",
            Self::Push => "push",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SyncOptions {
    /// Compute the plan and report it without writing anything, and without
    /// opening a run row (there is no `dry_run` status to record it under).
    pub dry_run: bool,
    /// Stop after this many upstream entries. Implies no reconciliation.
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub source: String,
    pub run_id: Option<Uuid>,
    pub dry_run: bool,
    pub status: String,
    /// False when the absent-upstream pass was deliberately skipped.
    pub reconciled: bool,
    pub scanned: i64,
    pub counts: Counts,
    pub changes: Vec<Change>,
}

impl RunReport {
    fn dry(source: &str, counts: Counts, plan: &SyncPlan) -> Self {
        Self {
            source: source.to_string(),
            run_id: None,
            dry_run: true,
            status: "dry_run".into(),
            reconciled: plan.reconciled,
            scanned: plan.scanned,
            counts,
            changes: plan.changes.clone(),
        }
    }
}

/// Loads a source and parses its config, refusing kinds the engine cannot drive.
///
/// The parse is what decides the connector for the whole run, so an unsupported
/// kind or a config that no longer validates fails here — before a run row is
/// opened — rather than halfway through a fetch.
async fn load_source(state: &AppState, code: &str) -> AppResult<(SourceRow, SourceConfig)> {
    let row = source::get_by_code(&state.pool, code).await?;
    let cfg = SourceConfig::parse(&row.kind, &row.config)?;
    Ok((row, cfg))
}

/// Closes runs left `running` by a crash, then opens a new one.
///
/// The partial unique index from migration `025` is the authority on "one run per
/// source", so losing a race to another trigger surfaces as a conflict instead of
/// two syncs interleaving.
async fn open_run(
    state: &AppState,
    row: &SourceRow,
    trigger: Trigger,
    actor_user_id: Option<Uuid>,
) -> AppResult<Uuid> {
    model::fail_stale_runs(
        &state.pool,
        row.id,
        STALE_RUN_MINUTES,
        "abandoned by a previous process",
    )
    .await?;
    model::begin_run(&state.pool, row.id, trigger.as_str(), actor_user_id).await
}

/// Runs one sync of `code` and returns what it did.
pub async fn run_source(
    state: &AppState,
    code: &str,
    trigger: Trigger,
    actor_user_id: Option<Uuid>,
    opts: &SyncOptions,
) -> AppResult<RunReport> {
    let (row, cfg) = load_source(state, code).await?;
    // A dry run opens no run row: the status CHECK has no "dry_run" value, and
    // recording a run that wrote nothing would make the history lie.
    if opts.dry_run {
        return execute(state, &row, &cfg, trigger, actor_user_id, opts, None).await;
    }
    let run_id = open_run(state, &row, trigger, actor_user_id).await?;
    execute(
        state,
        &row,
        &cfg,
        trigger,
        actor_user_id,
        opts,
        Some(run_id),
    )
    .await
}

/// Starts a sync in the background and returns its run id immediately (§10:
/// "手动触发（异步，返回 run id）").
///
/// The run row is opened synchronously, so the id is real and already visible in
/// the history, and a configuration problem is reported to the caller instead of
/// becoming a run that fails a second later.
pub async fn spawn_source(
    state: &AppState,
    code: &str,
    trigger: Trigger,
    actor_user_id: Option<Uuid>,
) -> AppResult<Uuid> {
    let (row, cfg) = load_source(state, code).await?;
    let run_id = open_run(state, &row, trigger, actor_user_id).await?;
    let source_label = row.code.clone();
    let state = state.clone();
    let opts = SyncOptions::default();
    tokio::spawn(async move {
        if let Err(e) = execute(
            &state,
            &row,
            &cfg,
            trigger,
            actor_user_id,
            &opts,
            Some(run_id),
        )
        .await
        {
            tracing::warn!(error = %e, source = %source_label, "directory sync failed");
        }
    });
    Ok(run_id)
}

/// The shared body: audit, fetch, plan, apply, close.
#[allow(clippy::too_many_arguments)]
async fn execute(
    state: &AppState,
    row: &SourceRow,
    cfg: &SourceConfig,
    trigger: Trigger,
    actor_user_id: Option<Uuid>,
    opts: &SyncOptions,
    run_id: Option<Uuid>,
) -> AppResult<RunReport> {
    if opts.limit.is_some() && !opts.dry_run {
        tracing::warn!(
            source = %row.code,
            limit = opts.limit.unwrap_or_default(),
            "limited sync requested; absent-upstream reconciliation is skipped"
        );
    }

    audit(
        state,
        AUDIT_SYNC_STARTED,
        "directory_source",
        Some(row.code.clone()),
        actor_user_id,
        json!({
            "source": row.code,
            "trigger": trigger.as_str(),
            "dry_run": opts.dry_run,
            "limit": opts.limit,
            "run_id": run_id,
        }),
    )
    .await;

    // ── Fetch + plan. Nothing is written until the plan is complete. ────
    let started = std::time::Instant::now();
    let planned = fetch_and_plan(state, row, cfg, opts).await;

    let plan = match planned {
        Ok(plan) => plan,
        Err(e) => {
            // Nothing was written, and for a real run the row opened by the
            // caller must still be closed — a permanently `running` row would
            // block every future run of this source.
            if let Some(run_id) = run_id {
                let _ = model::finish_run(
                    &state.pool,
                    run_id,
                    "failed",
                    0,
                    Counts::default(),
                    Some(&e.to_string()),
                    &json!({ "dry_run": false }),
                )
                .await;
            }
            audit(
                state,
                AUDIT_SYNC_FAILED,
                "directory_source",
                Some(row.code.clone()),
                actor_user_id,
                json!({
                    "source": row.code,
                    "trigger": trigger.as_str(),
                    "run_id": run_id,
                    "error": e.to_string(),
                }),
            )
            .await;
            tracing::error!(error = %e, source = %row.code, "directory sync failed before planning");
            crate::metrics::record_directory_sync_outcome("failed", 0);
            return Err(e);
        }
    };

    let counts = plan.counts();
    if opts.dry_run {
        tracing::info!(
            source = %row.code,
            scanned = plan.scanned,
            created = counts.created,
            updated = counts.updated,
            disabled = counts.disabled,
            skipped = counts.skipped,
            conflicts = counts.conflicts,
            errors = counts.errors,
            "directory sync dry run finished"
        );
        return Ok(RunReport::dry(&row.code, counts, &plan));
    }

    let run_id = run_id.expect("a non-dry run always has a run row");
    // Counted here rather than in `run_source` so a dry run can never be counted:
    // it has no run row, and a metric that disagrees with the run history is worse
    // than no metric.
    crate::metrics::inc_directory_sync_run();

    let applied = apply_plan(state, row, run_id, &plan, actor_user_id).await;

    let elapsed_ms = started.elapsed().as_millis() as u64;
    let (status, error) = match &applied {
        // Conflicts and unreadable entries need a human, so the run is not a
        // clean success — and calling it one would train operators to ignore the
        // status (§6.4).
        Ok(()) if counts.conflicts > 0 || counts.errors > 0 => ("partial", None),
        Ok(()) => ("succeeded", None),
        Err(e) => ("failed", Some(e.to_string())),
    };
    // One call per finished run: the counters stay equal to the run history, and
    // the "last success" gauge only advances on a run nobody has to look at.
    crate::metrics::record_directory_sync_outcome(status, counts.conflicts);

    if let Err(e) = model::finish_run(
        &state.pool,
        run_id,
        status,
        plan.scanned,
        counts,
        error.as_deref(),
        &json!({ "elapsed_ms": elapsed_ms, "dry_run": false }),
    )
    .await
    {
        // The sync itself may have succeeded; the history row failed to close.
        tracing::error!(error = %e, %run_id, "failed to close directory sync run");
    }

    audit(
        state,
        if status == "failed" {
            AUDIT_SYNC_FAILED
        } else {
            AUDIT_SYNC_FINISHED
        },
        "directory_source",
        Some(row.code.clone()),
        actor_user_id,
        json!({
            "source": row.code,
            "run_id": run_id,
            "trigger": trigger.as_str(),
            "status": status,
            "scanned": plan.scanned,
            "created": counts.created,
            "updated": counts.updated,
            "disabled": counts.disabled,
            "skipped": counts.skipped,
            "conflicts": counts.conflicts,
            "errors": counts.errors,
            "elapsed_ms": elapsed_ms,
            "error": error,
        }),
    )
    .await;

    match applied {
        Ok(()) => {
            tracing::info!(
                source = %row.code,
                %run_id,
                status,
                scanned = plan.scanned,
                created = counts.created,
                updated = counts.updated,
                disabled = counts.disabled,
                skipped = counts.skipped,
                conflicts = counts.conflicts,
                errors = counts.errors,
                elapsed_ms,
                "directory sync finished"
            );
            Ok(RunReport {
                source: row.code.clone(),
                run_id: Some(run_id),
                dry_run: false,
                status: status.to_string(),
                reconciled: plan.reconciled,
                scanned: plan.scanned,
                counts,
                changes: plan.changes.clone(),
            })
        }
        Err(e) => {
            tracing::error!(error = %e, source = %row.code, %run_id, "directory sync failed");
            Err(e)
        }
    }
}

/// Connects, reads the whole directory, and plans. Never writes.
///
/// This is the only place a source kind is dispatched to a connector, so both
/// kinds feed the same planner and the same reconciliation pass: the connectors
/// return [`UpstreamUser`]s and everything after that is shared.
async fn fetch_and_plan(
    state: &AppState,
    row: &SourceRow,
    cfg: &SourceConfig,
    opts: &SyncOptions,
) -> AppResult<SyncPlan> {
    let credential = source::decrypt_credential(state, row)?;
    let upstream = match cfg {
        SourceConfig::Ldap(cfg) => {
            let mut connector =
                LdapConnector::connect(cfg, credential.as_deref(), row.ca_cert_pem.as_deref())
                    .await?;
            // Unbind even when the search fails, so a broken source does not
            // leak a connection for every retry.
            let fetched = connector.fetch_users(opts.limit).await;
            connector.unbind().await;
            fetched?
        }
        SourceConfig::HttpJson(cfg) => {
            http_json::fetch_users(
                cfg,
                credential.as_deref(),
                state.config.outbound_allow_private,
                opts.limit,
            )
            .await?
        }
    };

    let local = model::load_local_state(&state.pool, row.id, &row.code).await?;
    Ok(plan::plan(
        &upstream,
        &local,
        PlanOptions {
            sync_groups: cfg.groups_configured(row.sync_groups),
            // A limited run only saw part of the directory, so "absent" is not
            // evidence of deletion.
            reconcile: opts.limit.is_none(),
            // §7: the source's own scope, applied on every run including a
            // limited one. An out-of-scope entry is never created or updated; on
            // a full run a linked user who dropped out of scope is disabled with
            // the distinct `out_of_scope` reason (a limited run reconciles
            // nothing, so it disables nobody).
            scope: cfg.scope(),
        },
    ))
}

/// Applies an already-computed plan: user writes in chunks, then the
/// absent-upstream disables, then the per-entry audit records.
///
/// Public because it is the seam the DB-backed tests use to exercise the writes
/// without standing up an LDAP server, which is what actually pins the SQL and
/// the "a second run changes nothing" property. Production code reaches it
/// through [`run_source`], which builds the plan from a live directory.
pub async fn apply_plan(
    state: &AppState,
    row: &SourceRow,
    run_id: Uuid,
    plan: &SyncPlan,
    actor_user_id: Option<Uuid>,
) -> AppResult<()> {
    for chunk in plan.changes.chunks(CHUNK) {
        let mut tx = state.pool.begin().await?;
        let mut created: Vec<(Uuid, &Change)> = Vec::new();

        for change in chunk {
            match change.outcome {
                Outcome::Create => {
                    let new_id = insert_user(&mut tx, row, change).await?;
                    created.push((new_id, change));
                }
                Outcome::Update => {
                    update_user(&mut tx, row.id, change).await?;
                }
                Outcome::Unchanged => {
                    touch_link(&mut tx, row.id, change).await?;
                }
                // Disabled users are handled in `apply_disables`, where the whole
                // set is applied at once; the plan already decided which ones.
                Outcome::Disable | Outcome::Skip | Outcome::Conflict | Outcome::Error => {}
            }
        }
        tx.commit().await?;

        for (user_id, change) in created {
            let external_id = change.external_id.clone();
            audit(
                state,
                AUDIT_USER_CREATED,
                "user",
                Some(user_id.to_string()),
                actor_user_id,
                json!({
                    "source": row.code,
                    "run_id": run_id,
                    "external_id": external_id,
                    "email": change.fields.as_ref().map(|f| f.email.clone()),
                }),
            )
            .await;
        }
    }

    apply_disables(state, row, run_id, plan, actor_user_id).await?;

    // Conflicts and unreadable entries need a human, so they get an audit record
    // each. Bulk outcomes (`updated`) are summarized by the run event instead
    // (§11.1) — the counts are identical, but 100k audit rows are not.
    for change in &plan.changes {
        if matches!(change.outcome, Outcome::Conflict | Outcome::Error) {
            audit(
                state,
                if change.outcome == Outcome::Conflict {
                    AUDIT_CONFLICT
                } else {
                    AUDIT_SYNC_FAILED
                },
                "directory_entry",
                Some(change.external_id.clone()),
                actor_user_id,
                json!({
                    "source": row.code,
                    "run_id": run_id,
                    "outcome": change.outcome,
                    "external_id": change.external_id,
                    "email": change.fields.as_ref().map(|f| f.email.clone()),
                    "reason": change.reason,
                }),
            )
            .await;
        }
        if change.outcome == Outcome::Skip {
            tracing::debug!(
                source = %row.code,
                external_id = %change.external_id,
                reason = %change.reason,
                "directory entry skipped"
            );
        }
    }

    Ok(())
}

/// Disables users the directory no longer lists (D3: never delete).
///
/// Records the sync's own intent in `directory_disabled` rather than only
/// writing `status`: `local_disabled` stays the admin's and `scim_disabled` the
/// IdP's, so each authority's decision survives the others (migration `026`).
/// The local intent is still cleared solely by an admin enable (§4.2). Sessions
/// are revoked so a disabled directory user does not keep browsing until their
/// session expires — the same thing the admin disable path does.
async fn apply_disables(
    state: &AppState,
    row: &SourceRow,
    run_id: Uuid,
    plan: &SyncPlan,
    actor_user_id: Option<Uuid>,
) -> AppResult<()> {
    let targets: Vec<Change> = plan
        .changes
        .iter()
        .filter(|c| c.outcome == Outcome::Disable)
        .cloned()
        .collect();
    if targets.is_empty() {
        return Ok(());
    }
    let ids: Vec<Uuid> = targets.iter().filter_map(|c| c.user_id).collect();
    if ids.is_empty() {
        return Ok(());
    }

    // The plan decided *why* each user is disabled, and the two reasons are not
    // interchangeable to whoever reads the audit: `absent_upstream` is someone the
    // directory no longer lists, `out_of_scope` is someone it still lists but this
    // source no longer owns (§7). Carry the plan's own wording through instead of
    // hardcoding one of them.
    let reasons: HashMap<Uuid, &str> = targets
        .iter()
        .filter_map(|c| c.user_id.map(|id| (id, c.reason.as_str())))
        .collect();

    let mut tx = state.pool.begin().await?;
    let disabled: Vec<Uuid> = sqlx::query_scalar(
        r#"
        UPDATE users SET directory_disabled = TRUE, status = 'disabled', updated_at = NOW()
        WHERE id = ANY($1) AND NOT directory_disabled
        RETURNING id
        "#,
    )
    .bind(&ids)
    .fetch_all(&mut *tx)
    .await?;

    if !disabled.is_empty() {
        sqlx::query("DELETE FROM sessions WHERE user_id = ANY($1)")
            .bind(&disabled)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    for user_id in disabled {
        let reason = reasons
            .get(&user_id)
            .copied()
            .filter(|reason| !reason.is_empty())
            .unwrap_or(plan::REASON_ABSENT_UPSTREAM);
        audit(
            state,
            AUDIT_USER_DISABLED,
            "user",
            Some(user_id.to_string()),
            actor_user_id,
            json!({ "source": row.code, "run_id": run_id, "reason": reason }),
        )
        .await;
    }
    Ok(())
}

async fn insert_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &SourceRow,
    change: &Change,
) -> AppResult<Uuid> {
    let fields = change
        .fields
        .as_ref()
        .expect("Create always carries managed fields");
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO users (id, sub, email, username, display_name, password_hash, status, role,
                           groups, phone, provisioned_via, local_disabled, directory_groups,
                           must_change_password, mfa_required, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, '', 'active', 'member',
                ARRAY[]::text[], NULL, $6, FALSE, $7,
                FALSE, FALSE, NOW(), NOW())
        "#,
    )
    .bind(id)
    .bind(Uuid::new_v4().to_string())
    .bind(&fields.email)
    .bind(&fields.username)
    .bind(&fields.display_name)
    .bind(&row.kind)
    .bind(change.groups.as_deref().unwrap_or(&[]))
    .execute(&mut **tx)
    .await
    .map_err(|e| unique_violation(e, &change.external_id, &fields.email))?;

    sqlx::query(
        r#"
        INSERT INTO directory_entries
            (id, source_id, external_id, external_dn, user_id, source_hash,
             last_seen_at, last_synced_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(row.id)
    .bind(&change.external_id)
    .bind(&change.external_dn)
    .bind(id)
    .bind(fingerprint_of(change))
    .execute(&mut **tx)
    .await?;

    Ok(id)
}

async fn update_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    source_id: Uuid,
    change: &Change,
) -> AppResult<()> {
    let fields = change
        .fields
        .as_ref()
        .expect("Update always carries managed fields");
    let id = change.user_id.expect("Update always has a user");

    // Status is re-derived on every update so a user who reappeared upstream is
    // re-enabled, while the other authorities' intents still win (§4.2): the
    // directory releases only its own claim. `COALESCE` leaves
    // `directory_groups` alone when this run does not own groups.
    //
    // The `status` expression spells out the flags rather than using
    // `STATUS_FROM_FLAGS`: `SET` reads the old row, and this statement is the one
    // changing `directory_disabled`, so it substitutes the new value.
    sqlx::query(
        r#"
        UPDATE users
        SET email = $2,
            username = $3,
            display_name = $4,
            directory_disabled = FALSE,
            status = CASE WHEN local_disabled OR scim_disabled THEN 'disabled' ELSE 'active' END,
            directory_groups = COALESCE($5::text[], directory_groups),
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(&fields.email)
    .bind(&fields.username)
    .bind(&fields.display_name)
    .bind(change.groups.as_deref())
    .execute(&mut **tx)
    .await
    .map_err(|e| unique_violation(e, &change.external_id, &fields.email))?;

    sqlx::query(
        r#"
        UPDATE directory_entries
        SET external_dn = $3, source_hash = $4, last_seen_at = NOW(), last_synced_at = NOW()
        WHERE source_id = $1 AND external_id = $2
        "#,
    )
    .bind(source_id)
    .bind(&change.external_id)
    .bind(&change.external_dn)
    .bind(fingerprint_of(change))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Refreshes `last_seen_at` for an entry that matched the directory exactly.
///
/// `external_dn` is refreshed here too, and is deliberately *not* part of the
/// fingerprint: a DN changes whenever a user moves OU, and treating that as a
/// content change would rewrite the user on every move — while failing to store
/// it would break LDAP bind-through auth (§8) for the moved user.
async fn touch_link(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    source_id: Uuid,
    change: &Change,
) -> AppResult<()> {
    sqlx::query(
        r#"
        UPDATE directory_entries SET external_dn = $3, last_seen_at = NOW()
        WHERE source_id = $1 AND external_id = $2
        "#,
    )
    .bind(source_id)
    .bind(&change.external_id)
    .bind(&change.external_dn)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn fingerprint_of(change: &Change) -> Option<String> {
    change
        .fields
        .as_ref()
        .map(|f| plan::fingerprint(f, change.groups.as_deref()))
}

/// Turns a unique-constraint violation into something an operator can act on.
///
/// The planner already refuses collisions it can see, so reaching this means the
/// local table changed between the snapshot and the write.
fn unique_violation(e: sqlx::Error, external_id: &str, email: &str) -> AppError {
    match &e {
        sqlx::Error::Database(db) if db.constraint() == Some("users_email_key") => {
            AppError::conflict(format!(
                "email {email} was taken while the sync was running (entry {external_id}); \
                 re-run to re-plan against the current state"
            ))
        }
        sqlx::Error::Database(db) if db.constraint() == Some("users_username_key") => {
            AppError::conflict(format!(
                "username for entry {external_id} was taken while the sync was running; \
                 re-run to re-plan against the current state"
            ))
        }
        _ => AppError::from(e),
    }
}

/// Writes one audit event. Errors are the caller's to interpret; the actor is
/// recorded for manual runs so `audit_logs.actor_user_id` stays meaningful.
async fn audit(
    state: &AppState,
    action: &'static str,
    resource_type: &'static str,
    resource_id: Option<String>,
    actor_user_id: Option<Uuid>,
    detail: Value,
) {
    let actor = match actor_user_id {
        Some(id) => load_actor(state, id).await,
        None => None,
    };
    crate::audit::record(
        state,
        AuditEvent {
            actor,
            action,
            resource_type,
            resource_id,
            detail,
            ip: None,
            user_agent: None,
            client_id: None,
        },
    )
    .await;
}

async fn load_actor(state: &AppState, id: Uuid) -> Option<crate::models::User> {
    match crate::models::user_by_id(&state.pool, id).await {
        Ok(user) => Some(user),
        Err(e) => {
            tracing::warn!(error = %e, %id, "sync actor could not be loaded");
            None
        }
    }
}

/// Run history for one source, for the CLI and the admin API.
pub async fn recent_runs(state: &AppState, code: &str, limit: i64) -> AppResult<Vec<RunRow>> {
    let row = source::get_by_code(&state.pool, code).await?;
    model::list_runs(&state.pool, row.id, limit).await
}
