//! Who owns a user's upstream-managed attributes, and what that forbids.
//!
//! Two authorities can own a user: a directory source (through the link in
//! `directory_entries`) and SCIM (through `users.scim_managed`). Both freeze the
//! attributes they own against local edits and both refuse a hard delete, so the
//! question "who owns this" and the rules that follow live here rather than
//! being spelled out per caller.
//!
//! The distinction that matters for placement: owning a user's *attributes* is
//! not the same as holding a *disable claim*. A source that is switched off
//! keeps its attributes (`directory::managing_source` ignores `enabled`) but
//! loses its claim, because a switch-off retires its authority — see
//! [`release_dead_authority_claims`].

use crate::error::AppResult;
use sqlx::PgPool;
use uuid::Uuid;

/// The authority that owns a user's upstream-managed attributes.
///
/// An enum rather than an `Option<String>` of the owning code because a SCIM
/// authority has no code: directory source codes are operator-chosen and `"scim"`
/// is even a valid *kind*, so a string would be ambiguous exactly where the
/// answer is used to refuse a write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authority {
    /// Owned by a directory source, named by its `directory_sources.code`.
    Directory(String),
    /// Owned by the SCIM client pushing into `/scim/v2`.
    Scim,
}

impl Authority {
    /// Short name for audit detail and operator-facing messages.
    pub fn code(&self) -> &str {
        match self {
            Authority::Directory(code) => code,
            Authority::Scim => "scim",
        }
    }

    /// The attributes this authority owns, so a local write to them is refused.
    ///
    /// Email, username and display name are owned by both: they are the fields
    /// each upstream provisions and keeps current. `directory_groups` is
    /// directory-only, and deliberately so — SCIM group membership still writes
    /// `users.groups`, the locally-managed column, so claiming it here would
    /// make local group edits fail against a value SCIM overwrites. Moving SCIM
    /// groups onto `directory_groups` is separate work (docs/directory-sync.md
    /// §14, "组模型").
    pub fn managed_fields(&self) -> &'static [&'static str] {
        match self {
            Authority::Directory(_) => &["email", "username", "display_name", "directory_groups"],
            Authority::Scim => &["email", "username", "display_name"],
        }
    }

    /// Why a local write to `field` is refused, or `None` when `field` is not
    /// owned. Pure, so the policy is testable without a database.
    pub fn write_error(&self, field: &str) -> Option<String> {
        self.managed_fields()
            .contains(&field)
            .then(|| format!("{field} is managed by {}", self.describe_for_error()))
    }

    /// Why a local delete is refused. Mirrors D3: an upstream deletion only
    /// disables, so a hard delete is never allowed — use the disable intent for
    /// the owning authority instead.
    pub fn delete_error(&self) -> String {
        match self {
            Authority::Directory(code) => format!(
                "user is managed by directory source {code}; disable it instead of deleting"
            ),
            Authority::Scim => {
                "user is managed by SCIM; disable it instead of deleting".to_string()
            }
        }
    }

    fn describe_for_error(&self) -> String {
        match self {
            Authority::Directory(code) => format!("directory source {code}"),
            Authority::Scim => "SCIM".to_string(),
        }
    }
}

/// The authority owning this user's managed attributes, if any.
///
/// Directory wins when a user is both linked and SCIM-managed: the link carries
/// an explicit priority order across sources and the directory is the attribute
/// source of record. Used by the guards, which need one answer; [`Ownership`]
/// is for surfaces that should show everything the operator has to know.
pub async fn managing_authority(pool: &PgPool, user_id: Uuid) -> AppResult<Option<Authority>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        directory_code: Option<String>,
        scim_managed: bool,
    }

    let row = sqlx::query_as::<_, Row>(
        r#"
        SELECT
            (SELECT s.code
             FROM directory_entries e
             JOIN directory_sources s ON s.id = e.source_id
             WHERE e.user_id = u.id
             ORDER BY s.priority ASC, s.code ASC
             LIMIT 1) AS directory_code,
            u.scim_managed
        FROM users u
        WHERE u.id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.and_then(|r| match (r.directory_code, r.scim_managed) {
        (Some(code), _) => Some(Authority::Directory(code)),
        (None, true) => Some(Authority::Scim),
        (None, false) => None,
    }))
}

/// Releases disable claims that no live authority is backing any more, and the
/// ownership of an authority that has been retired.
///
/// A claim is only meaningful while its author is still in charge, and each
/// authority answers a different liveness question:
///
/// * `directory_disabled` — an **enabled** source links this user. A source that
///   is switched off lists nothing and verifies nothing, the same reason
///   `directory::enabled_managing_source` ignores it.
/// * `scim_disabled` and `scim_managed` — a SCIM client is **configured**.
///   `DELETE /admin/scim/token` retires the IdP's authority; rotating it through
///   `POST` keeps a token and so keeps both (the IdP is still pushing).
///
/// Claims are reconciled because an admin enable cannot override an upstream
/// claim (migration `026`), so a claim with no live authority behind it is a
/// lockout with no way back. Ownership is released for the same reason from the
/// other side: a retired authority owns nothing, and leaving `scim_managed` set
/// would make those accounts permanently uneditable and undeletable locally.
///
/// Call after any act that retires an authority — disabling or deleting a
/// source, revoking the SCIM token.
///
/// The directory condition is "no *enabled* source links this user" and
/// deliberately not "this source links this user": links can disappear without
/// the flag being released — `DELETE /directory/sources/{code}` tells the
/// operator to remove them, and a hand edit can do it too — and a claim whose
/// links are gone has no owner left to release it. Sweeping by liveness instead
/// of by owner is what makes that self-healing.
///
/// Returns how many rows were changed.
pub async fn release_dead_authority_claims(pool: &PgPool) -> AppResult<u64> {
    let scim_live = sqlx::query_scalar::<_, bool>(
        "SELECT COALESCE((SELECT token_hash IS NOT NULL FROM scim_config WHERE id = TRUE), FALSE)",
    )
    .fetch_one(pool)
    .await?;

    let mut tx = pool.begin().await?;

    let directory = sqlx::query(
        r#"
        UPDATE users u
        SET directory_disabled = FALSE,
            status = CASE WHEN u.local_disabled OR u.scim_disabled
                          THEN 'disabled' ELSE 'active' END,
            updated_at = NOW()
        WHERE u.directory_disabled
          AND NOT EXISTS (
              SELECT 1 FROM directory_entries e
              JOIN directory_sources s ON s.id = e.source_id
              WHERE e.user_id = u.id AND s.enabled
          )
        "#,
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();

    // `scim_live` is read outside the transaction so the two halves cannot
    // deadlock against each other, and applied inside so a reader never sees a
    // released claim paired with stale ownership.
    let scim = if scim_live {
        0
    } else {
        sqlx::query(
            r#"
            UPDATE users
            SET scim_disabled = FALSE,
                scim_managed = FALSE,
                status = CASE WHEN local_disabled OR directory_disabled
                              THEN 'disabled' ELSE 'active' END,
                updated_at = NOW()
            WHERE scim_disabled OR scim_managed
            "#,
        )
        .execute(&mut *tx)
        .await?
        .rows_affected()
    };

    tx.commit().await?;
    Ok(directory + scim)
}
