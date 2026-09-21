//! Pins `admin::set_user_access` as one operation instead of a status write
//! plus a flag that had to agree with it.
//!
//! The bug this replaces is silent, which is why it is worth a test file. As
//! two arguments, `("disabled", false)` produced an account that is disabled but
//! carries no local intent, so the next directory sync reads it as "upstream
//! active" and re-enables it — a security decision quietly reversed by a
//! background job. `("active", true)` failed the other way. Neither combination
//! is expressible now, and these tests hold both halves of the pairing down.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use signet::admin::{set_user_access, UserAccess};
use signet::auth::session::{create_session, list_sessions};
use signet::error::AppError;
use uuid::Uuid;

#[tokio::test]
async fn a_disable_records_both_the_status_and_the_local_intent() {
    let Some(state) = common::state().await else {
        return;
    };
    let id = common::create_user(&state.pool, "").await;

    common::with_user(state, id, |state, id| async move {
        let user = set_user_access(&state, id, UserAccess::Disabled)
            .await
            .expect("disable the account");

        assert_eq!(user.status, "disabled");
        assert!(
            user.local_disabled,
            "without the local intent the next sync re-enables the account"
        );
    })
    .await;
}

#[tokio::test]
async fn an_enable_clears_both_the_status_and_the_local_intent() {
    let Some(state) = common::state().await else {
        return;
    };
    let id = common::create_user(&state.pool, "").await;

    common::with_user(state, id, |state, id| async move {
        set_user_access(&state, id, UserAccess::Disabled)
            .await
            .expect("disable first");

        let user = set_user_access(&state, id, UserAccess::Enabled)
            .await
            .expect("enable the account");

        assert_eq!(user.status, "active");
        assert!(
            !user.local_disabled,
            "a stale local intent would let the next sync re-disable the account"
        );
    })
    .await;
}

#[tokio::test]
async fn the_transitions_are_idempotent() {
    let Some(state) = common::state().await else {
        return;
    };
    let id = common::create_user(&state.pool, "").await;

    common::with_user(state, id, |state, id| async move {
        // `admin::batch_disable_users` disables users one at a time and does not
        // pre-filter already-disabled ones, so a repeat must be harmless.
        for _ in 0..2 {
            let user = set_user_access(&state, id, UserAccess::Disabled)
                .await
                .expect("disable twice");
            assert_eq!(user.status, "disabled");
            assert!(user.local_disabled);
        }
    })
    .await;
}

#[tokio::test]
async fn disabling_revokes_the_accounts_sessions() {
    let Some(state) = common::state().await else {
        return;
    };
    let id = common::create_user(&state.pool, "").await;
    create_session(&state.pool, id, 24, None, None)
        .await
        .expect("create a session");

    common::with_user(state, id, |state, id| async move {
        assert_eq!(list_sessions(&state.pool, id).await.unwrap().len(), 1);

        set_user_access(&state, id, UserAccess::Disabled)
            .await
            .expect("disable the account");

        // `user_from_session_token` already refuses a disabled account, so the
        // sessions are unusable either way; this pins that the rows are cleared.
        assert!(
            list_sessions(&state.pool, id).await.unwrap().is_empty(),
            "a disable must not leave session rows behind"
        );
    })
    .await;
}

#[tokio::test]
async fn enabling_does_not_revoke_sessions() {
    let Some(state) = common::state().await else {
        return;
    };
    let id = common::create_user(&state.pool, "").await;
    create_session(&state.pool, id, 24, None, None)
        .await
        .expect("create a session");

    common::with_user(state, id, |state, id| async move {
        set_user_access(&state, id, UserAccess::Enabled)
            .await
            .expect("enable the account");

        // The revocation is tied to disabling, not to the update. An
        // unconditional revoke would sign an admin out on any status write.
        assert_eq!(list_sessions(&state.pool, id).await.unwrap().len(), 1);
    })
    .await;
}

#[tokio::test]
async fn an_unknown_id_reports_not_found() {
    let Some(state) = common::state().await else {
        return;
    };

    let err = set_user_access(&state, Uuid::new_v4(), UserAccess::Disabled)
        .await
        .expect_err("an unknown id must not update anything");

    assert!(
        matches!(err, AppError::NotFound(_)),
        "the admin path distinguishes a missing account, expected 404, got {err:?}"
    );
}

/// The local intent itself, asserted without a database.
///
/// `UserAccess` carries one thing now — the admin's own intent. The name is the
/// pair, so this fails if someone adds a variant. What the intent does to
/// `status` is no longer this type's business: an account is disabled when *any*
/// authority says so, which `tests/disable_flags.rs` walks end to end.
#[test]
fn the_local_intent_follows_the_variant() {
    assert!(!UserAccess::Enabled.local_disabled());
    assert!(UserAccess::Disabled.local_disabled());
}
