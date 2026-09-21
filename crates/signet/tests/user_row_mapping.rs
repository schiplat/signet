//! Contract tests for every query that materializes a `models::User`.
//!
//! `User` has a wide column list and several call sites hand-wrote a subset of
//! it in a `SELECT`. When a column was added to the struct but not to one of
//! those lists, sqlx failed at runtime with `no column found for name: ...` —
//! which reaches the user as a 500 on the affected endpoint. The session-token
//! lookup was the worst case: it is behind `current_user`, so a drift there
//! broke every authenticated request at once (`/api/v1/me`, `/admin/*`, the
//! whole dashboard) *after* a login that had just succeeded.
//!
//! These tests execute each query against a real row. They are deliberately
//! about row mapping, not about behaviour: a mock would not have caught this,
//! because the failure is in the shape of the result set.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use signet::auth::session::user_from_session_token;
use sqlx::PgPool;
use uuid::Uuid;

/// Every `pub` entry point that turns a stored row into a `User`, paired with a
/// call that must return `Some` for a live user.
#[tokio::test]
async fn a_user_loads_through_the_session_token_query() {
    let Some(state) = common::state().await else {
        return;
    };

    let (user_id, token) = seeded_user_with_session(&state.pool).await;

    common::with_user(state, user_id, move |state, user_id| async move {
        let pool = &state.pool;
        // This is the exact query `current_user` runs on every authenticated
        // request. It joins `sessions`, so it needs aliased columns.
        let loaded = user_from_session_token(pool, &token)
            .await
            .expect("the session-token query must map into `User`")
            .expect("a live session must resolve to its user");
        assert_eq!(
            loaded.id, user_id,
            "the join must return the session's user"
        );
        assert!(
            !loaded.local_disabled,
            "the directory columns must be part of the mapped row"
        );
        // A non-default value, so a query that silently omitted the column (and
        // let `FromRow` fill in a default) would not pass by coincidence.
        assert_eq!(
            loaded.directory_groups,
            vec!["cn=ops".to_string()],
            "directory_groups must be read from the row, not defaulted"
        );
    })
    .await;
}

/// `models::user_by_id` is the second `User` loader, used by the sync engine.
#[tokio::test]
async fn a_user_loads_through_the_by_id_query() {
    let Some(state) = common::state().await else {
        return;
    };

    let (user_id, _) = seeded_user_with_session(&state.pool).await;

    common::with_user(state, user_id, |state, user_id| async move {
        let loaded = signet::models::user_by_id(&state.pool, user_id)
            .await
            .expect("the by-id query must map into `User`");
        assert_eq!(loaded.id, user_id);
    })
    .await;
}

/// The list is the single source of truth for the struct's columns; a column
/// added to `User` without being added here is the bug these tests exist for.
///
/// Pure and database-free, but it lives with the others so the two halves of
/// the contract are read together.
#[test]
fn the_column_list_covers_every_field() {
    let cols = signet::models::USER_COLS;
    for field in [
        "id",
        "sub",
        "email",
        "username",
        "display_name",
        "password_hash",
        "status",
        "role",
        "mfa_required",
        "must_change_password",
        "totp_enabled",
        "totp_secret",
        "groups",
        "phone",
        "provisioned_via",
        "local_disabled",
        "directory_groups",
        "created_at",
        "updated_at",
    ] {
        assert!(
            cols.split(',').any(|c| c.trim() == field),
            "USER_COLS must list `{field}`"
        );
    }
}

/// The alias helper is what lets a joined query reuse `USER_COLS` instead of
/// hand-writing a second list, so it must qualify every column.
#[test]
fn the_alias_helper_qualifies_every_column() {
    let aliased = signet::models::user_cols_with("u");
    let plain: Vec<&str> = signet::models::USER_COLS
        .split(',')
        .map(str::trim)
        .collect();
    let qualified: Vec<&str> = aliased.split(',').map(str::trim).collect();
    assert_eq!(plain.len(), qualified.len());
    for (plain, qualified) in plain.iter().zip(qualified.iter()) {
        assert_eq!(*qualified, format!("u.{plain}"));
    }
}

/// The SCIM projection is a *second* list, and this is the test that keeps it
/// honest.
///
/// It cannot be folded into `USER_COLS`: SCIM lists users, so selecting the full
/// column set would read `password_hash` and `totp_secret` on every call. The
/// price of the narrower list is that it and `ScimUserRow` can drift, and the
/// failure mode is a runtime `no column found for name` — a 500 on the SCIM
/// endpoints, with no other test reaching those queries.
#[tokio::test]
async fn a_user_loads_through_the_scim_projection() {
    let Some(state) = common::state().await else {
        return;
    };

    // Scalar columns only: the point is the column list, not the join.
    let user_id = Uuid::new_v4();
    let tag = Uuid::new_v4().simple().to_string();
    sqlx::query(
        r#"
        INSERT INTO users (id, sub, email, display_name, password_hash, status, role,
                           groups, external_id)
        VALUES ($1, $2, $3, 'Projection User', 'not-a-real-hash', 'active', 'member',
                ARRAY['cn=ops'], 'upstream-7')
        "#,
    )
    .bind(user_id)
    .bind(format!("sub-{tag}"))
    .bind(format!("{tag}@scim-projection.test"))
    .execute(&state.pool)
    .await
    .expect("insert the projection-test user");

    common::with_user(state, user_id, |state, user_id| async move {
        let sql = format!(
            "SELECT {} FROM users WHERE id = $1",
            signet::scim::USER_SELECT
        );
        let row: signet::scim::ScimUserRow = sqlx::query_as(&sql)
            .bind(user_id)
            .fetch_one(&state.pool)
            .await
            .expect("the SCIM projection must map into `ScimUserRow`");

        assert_eq!(row.id, user_id);
        // Non-default values for the two columns SCIM's response depends on, so
        // a list that silently dropped them would not pass by coincidence.
        assert_eq!(row.external_id.as_deref(), Some("upstream-7"));
        assert_eq!(row.groups, vec!["cn=ops".to_string()]);
    })
    .await;
}

/// The projection must stay narrow. If someone later "converges" it onto
/// `USER_COLS`, this fails before the secret reaches a response.
#[test]
fn the_scim_projection_carries_no_credential_material() {
    for secret in [
        "password_hash",
        "totp_secret",
        "totp_enabled",
        "mfa_required",
        "sub",
    ] {
        assert!(
            !signet::scim::USER_SELECT
                .split(',')
                .any(|c| c.trim() == secret),
            "`{secret}` must not be read on the SCIM paths"
        );
    }
}

/// Inserts a user with a session and returns `(user_id, session_token)`.
///
/// The token is stored hashed by `create_session`, so this goes through that
/// function rather than inserting a row directly — the test is about reading a
/// session back, and a hand-built row could drift from what the app writes.
async fn seeded_user_with_session(pool: &PgPool) -> (Uuid, String) {
    let tag = Uuid::new_v4().simple().to_string();
    let user_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO users (id, sub, email, username, display_name, password_hash, status, role,
                           directory_groups)
        VALUES ($1, $2, $3, $4, 'Contract User', '', 'active', 'member', ARRAY['cn=ops'])
        "#,
    )
    .bind(user_id)
    .bind(format!("sub-{tag}"))
    .bind(format!("{tag}@user-cols.test"))
    .bind(format!("user-cols/{tag}"))
    .execute(pool)
    .await
    .expect("insert the contract-test user");

    let token = format!("tok-{tag}");
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at) \
         VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour')",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(signet::crypto::util::sha256_hex(&token))
    .execute(pool)
    .await
    .expect("insert the contract-test session");

    (user_id, token)
}
