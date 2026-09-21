//! Pins the two user-by-id loaders against each other.
//!
//! `models::user_by_id` and `models::active_user_by_id` look like a duplication
//! and are the kind of pair a later cleanup is tempted to merge. They are not
//! the same query: one takes any status, the other requires `active`. This file
//! exists so that merging them, or losing the status filter, fails here.
//!
//! Assertions target the [`AppError`] variant rather than the HTTP status.
//! `IntoResponse` maps `NotFound` → 404 and `Unauthorized` → 401 in one match
//! arm each, so the variant *is* the status for these two; asserting the
//! status would only re-test that match.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use signet::error::AppError;
use signet::models::{active_user_by_id, user_by_id};
use sqlx::PgPool;
use uuid::Uuid;

/// Flips `status` directly. The loaders are what is under test, so the fixture
/// must not go through admin's `set_status`, which writes `local_disabled` too
/// and would make a failure here ambiguous.
async fn set_status(pool: &PgPool, id: Uuid, status: &str) {
    sqlx::query("UPDATE users SET status = $2, updated_at = NOW() WHERE id = $1")
        .bind(id)
        .bind(status)
        .execute(pool)
        .await
        .expect("set user status");
}

#[tokio::test]
async fn user_by_id_returns_a_disabled_account() {
    let Some(state) = common::state().await else {
        return;
    };
    let id = common::create_user(&state.pool, "").await;
    set_status(&state.pool, id, "disabled").await;

    let user = user_by_id(&state.pool, id)
        .await
        .expect("the admin path must still see a disabled account");

    assert_eq!(user.status, "disabled");

    common::delete_user(&state.pool, id).await;
}

#[tokio::test]
async fn active_user_by_id_refuses_a_disabled_account() {
    let Some(state) = common::state().await else {
        return;
    };
    let id = common::create_user(&state.pool, "").await;
    set_status(&state.pool, id, "disabled").await;

    let err = active_user_by_id(&state.pool, id)
        .await
        .expect_err("a disabled account must not be handed to a credential path");

    assert!(
        matches!(err, AppError::Unauthorized(_)),
        "expected 401, got {err:?}"
    );

    common::delete_user(&state.pool, id).await;
}

#[tokio::test]
async fn active_user_by_id_returns_an_active_account() {
    let Some(state) = common::state().await else {
        return;
    };
    let id = common::create_user(&state.pool, "").await;

    let user = active_user_by_id(&state.pool, id)
        .await
        .expect("an active account must load");
    assert_eq!(user.id, id);

    common::delete_user(&state.pool, id).await;
}

#[tokio::test]
async fn active_user_by_id_reports_an_unknown_id_as_unauthorized() {
    let Some(state) = common::state().await else {
        return;
    };

    // Not 404: on an authentication path the caller already knew an id, and
    // telling a disabled account apart from a nonexistent one leaks which
    // accounts exist. Both must look the same from outside.
    let err = active_user_by_id(&state.pool, Uuid::new_v4())
        .await
        .expect_err("an unknown id must not load any user");

    assert!(
        matches!(err, AppError::Unauthorized(_)),
        "expected 401, got {err:?}"
    );
}

#[tokio::test]
async fn user_by_id_reports_an_unknown_id_as_not_found() {
    let Some(state) = common::state().await else {
        return;
    };

    let err = user_by_id(&state.pool, Uuid::new_v4())
        .await
        .expect_err("an unknown id must not load any user");

    assert!(
        matches!(err, AppError::NotFound(_)),
        "expected 404, got {err:?}"
    );
}
