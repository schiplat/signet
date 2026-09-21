//! Pins the two "sign out" operations against each other.
//!
//! `revoke_all_sessions` and `revoke_other_sessions` differ by one row: the
//! session the caller is currently using. That is the whole point of the second
//! one, and it is the kind of difference that survives review while being
//! silently wrong — an inverted `<>` still deletes sessions and still returns a
//! plausible count, it just also signs the user out of the device they are
//! holding, or leaves a session behind on a device they lost.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use signet::auth::session::{
    create_session, list_sessions, revoke_all_sessions, revoke_other_sessions, session_id_for_token,
};
use signet::state::AppState;
use uuid::Uuid;

/// Opens `count` sessions for `user_id` and returns their session ids.
async fn sessions_for(state: &AppState, user_id: Uuid, count: usize) -> Vec<Uuid> {
    let mut ids = Vec::with_capacity(count);
    for n in 0..count {
        let token = create_session(&state.pool, user_id, 24, None, Some("test-agent"))
            .await
            .expect("create a session");
        // Read the id back through the token, so the test never has to know how
        // `create_session` generates it.
        let id = session_id_for_token(&state.pool, &token)
            .await
            .expect("resolve the session id")
            .unwrap_or_else(|| panic!("session {n} must be resolvable by its token"));
        ids.push(id);
    }
    ids
}

#[tokio::test]
async fn revoke_other_sessions_keeps_exactly_the_named_session() {
    let Some(state) = common::state().await else {
        return;
    };
    let user_id = common::create_user(&state.pool, "").await;
    let ids = sessions_for(&state, user_id, 3).await;
    let keep = ids[1];

    let revoked = revoke_other_sessions(&state.pool, user_id, keep)
        .await
        .expect("revoke the other sessions");

    assert_eq!(revoked, 2, "three sessions minus the kept one");
    let remaining = list_sessions(&state.pool, user_id)
        .await
        .expect("list the remaining sessions");
    assert_eq!(remaining.len(), 1, "only the kept session may survive");
    assert_eq!(remaining[0].id, keep);

    common::delete_user(&state.pool, user_id).await;
}

#[tokio::test]
async fn revoke_all_sessions_keeps_nothing() {
    let Some(state) = common::state().await else {
        return;
    };
    let user_id = common::create_user(&state.pool, "").await;
    sessions_for(&state, user_id, 3).await;

    let revoked = revoke_all_sessions(&state.pool, user_id)
        .await
        .expect("revoke every session");

    assert_eq!(revoked, 3);
    let remaining = list_sessions(&state.pool, user_id)
        .await
        .expect("list the remaining sessions");
    assert!(
        remaining.is_empty(),
        "the no-cookie branch of a sign-out must not leave a session behind"
    );

    common::delete_user(&state.pool, user_id).await;
}

#[tokio::test]
async fn revoking_sessions_leaves_another_users_sessions_alone() {
    let Some(state) = common::state().await else {
        return;
    };
    let user_id = common::create_user(&state.pool, "").await;
    let bystander_id = common::create_user(&state.pool, "").await;
    let ids = sessions_for(&state, user_id, 2).await;
    let bystander = sessions_for(&state, bystander_id, 1).await;

    revoke_other_sessions(&state.pool, user_id, ids[0])
        .await
        .expect("revoke the other sessions");
    revoke_all_sessions(&state.pool, user_id)
        .await
        .expect("revoke every session");

    // The `WHERE user_id = $1` filter is load-bearing: without it a sign-out
    // would evict every other account on the deployment.
    let remaining = list_sessions(&state.pool, bystander_id)
        .await
        .expect("list the bystander's sessions");
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, bystander[0]);

    common::delete_user(&state.pool, user_id).await;
    common::delete_user(&state.pool, bystander_id).await;
}
