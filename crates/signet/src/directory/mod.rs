//! External IDP (directory) synchronisation with Signet's local user store.
//!
//! This module implements `docs/directory-sync.md`. P0 established the
//! ownership semantics — which users a directory owns and what that forbids
//! locally ([`managed_write_error`], [`managing_source`]). P1 adds the engine
//! that actually writes those users:
//!
//! | Module | Design section | Role |
//! |---|---|---|
//! [`source`] | §4.1, §7.2, §13 | source config, validation, credential handling |
//! [`plan`] | §6.2–§6.4 | pure diffing: upstream entries + local state → plan |
//! [`ldap`] | §7, §8.2 | the LDAP connector: sync reads and login binds |
//! [`ldif`] | §13 | pasted `ldapsearch` output, for the mapping preview |
//! [`http_json`] | §13 | the generic HTTP JSON connector |
//! [`mapping`] | §13 | kind-dispatched mapping preview (pure, no I/O) |
//! [`auth`] | §8 | login path selection and bind-through verification |
//! [`engine`] | §6.1, §11 | orchestration, counters, audit, run history |
//! [`api`] | §10 | admin HTTP surface |
//! [`cli`] | §9 | `signet sync …` |
//!
//! The split between [`plan`] and everything else is deliberate: the plan is a
//! pure function of two snapshots, so `--dry-run` and a real run execute the
//! *same* code path — the only difference is whether the plan is applied. That
//! makes "`--dry-run` output matches the real run" a structural property rather
//! than a promise about two implementations staying in step.

use crate::error::AppResult;
use sqlx::PgPool;
use uuid::Uuid;

pub mod api;
pub mod auth;
pub mod cli;
pub mod engine;
pub mod http_json;
pub mod ldap;
pub mod ldif;
pub mod mapping;
pub mod model;
pub mod plan;
pub mod scheduler;
pub mod source;

/// Audit action recorded when a local write to a directory-owned attribute is
/// refused.
///
/// Named for the directory path that first needed it; SCIM now refuses the same
/// writes against the same attributes and records the same action, with
/// `detail.authority` saying which upstream it was (`crate::authority`).
pub const AUDIT_MANAGED_WRITE_BLOCKED: &str = "directory.managed_write_blocked";

/// Code of the highest-precedence source linking this user, if any.
///
/// A user can be linked by several sources; the lowest `priority` value wins for
/// attribute conflicts (§6.4), and `code` breaks ties so the answer is
/// deterministic. `None` means the user is not directory-managed.
pub async fn managing_source(pool: &PgPool, user_id: Uuid) -> AppResult<Option<String>> {
    let code = sqlx::query_scalar::<_, String>(
        r#"
        SELECT s.code
        FROM directory_entries e
        JOIN directory_sources s ON s.id = e.source_id
        WHERE e.user_id = $1
        ORDER BY s.priority ASC, s.code ASC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(code)
}

/// Code of the highest-precedence **enabled** source linking this user, if any.
///
/// [`managing_source`] answers "who owns this user's attributes" and therefore
/// deliberately ignores `enabled`: switching a source off does not hand its
/// attributes back to the local admin. This answers a different question — "who
/// will verify this user's password at the next login" — where a disabled source
/// is precisely the case that must not count, because it verifies nothing any
/// more. Keeping one query for both questions is what would make a decommissioned
/// directory keep holding people's credentials hostage.
pub async fn enabled_managing_source(pool: &PgPool, user_id: Uuid) -> AppResult<Option<String>> {
    let code = sqlx::query_scalar::<_, String>(
        r#"
        SELECT s.code
        FROM directory_entries e
        JOIN directory_sources s ON s.id = e.source_id
        WHERE e.user_id = $1 AND s.enabled
        ORDER BY s.priority ASC, s.code ASC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(code)
}

/// True when audit events for `action` must not fan out to webhooks.
///
/// `audit::record` dispatches every event to every enabled webhook with no
/// retry and no aggregation (`audit.rs`). Per-entry sync events would therefore
/// turn one 100k-user sync into 100k webhook deliveries (§11.1). The *audit log*
/// still records each one — that is the compliance record — but the fan-out is
/// replaced by the per-run `directory.sync.finished` summary, which carries the
/// same totals.
///
/// Pure, so the policy is unit-testable without a database or a webhook.
pub fn is_summary_only_action(action: &str) -> bool {
    matches!(
        action,
        // Per-entry, high volume.
        "directory.user.created"
            | "directory.user.updated"
            | "directory.user.disabled"
            | "directory.conflict"
    )
}
