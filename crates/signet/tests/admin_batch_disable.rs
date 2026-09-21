//! `POST /admin/users/batch-disable` — the batch semantics.
//!
//! The handler used to walk the ids and call `set_user_access` per user, which
//! made a selection of N accounts 3+N round trips and recorded nothing in the
//! audit log at all. It now reads the roles in one query, updates in one
//! statement, revokes the sessions in one delete, and writes one audit event per
//! account.
//!
//! The rewrite has two properties that a per-user loop gave for free and a
//! batched statement does not: the permission check still applies to *each*
//! target (a manager must not be able to include an admin in the selection), and
//! the count still reflects only the accounts that actually changed.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// Drives a request and returns the status and body.
async fn call(
    router: &axum::Router,
    cookie: &str,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(match body {
            Some(json) => Body::from(json.to_string()),
            None => Body::empty(),
        })
        .expect("build the request");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the admin router must answer");
    let status = response.status();
    let text = response
        .into_body()
        .collect()
        .await
        .expect("read the response body")
        .to_bytes();
    (status, String::from_utf8_lossy(&text).into_owned())
}

/// A user with `role`, and a live session to check the revocation against.
async fn user_with_role(pool: &PgPool, role: &str) -> Uuid {
    let id = common::create_user(pool, "").await;
    sqlx::query("UPDATE users SET role = $2 WHERE id = $1")
        .bind(id)
        .bind(role)
        .execute(pool)
        .await
        .expect("set the role");
    signet::auth::session::create_session(pool, id, 1, None, None)
        .await
        .expect("create a session");
    id
}

async fn sessions_of(pool: &PgPool, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count the sessions")
}

async fn access_of(pool: &PgPool, user: Uuid) -> (String, bool) {
    sqlx::query_as("SELECT status, local_disabled FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("read the access state")
}

/// A manager is staff, so the route accepts them — but their selection must be
/// filtered, not merely allowed through because they named nobody they cannot
/// touch.
#[tokio::test]
async fn a_manager_cannot_disable_an_admin_through_a_batch() {
    let Some(state) = common::state().await else {
        return;
    };

    let manager = user_with_role(&state.pool, "manager").await;
    let member = user_with_role(&state.pool, "member").await;
    let admin = user_with_role(&state.pool, "admin").await;

    common::with_users(
        state.clone(),
        vec![manager, member, admin],
        |state, users| async move {
            let (manager, member, admin) = (users[0], users[1], users[2]);

            // A session for the manager, since `admin_cookie` creates its own
            // actor; this one is the *target* selector we are testing.
            let cookie = format!(
                "{}={}",
                signet::auth::session::SESSION_COOKIE,
                signet::auth::session::create_session(&state.pool, manager, 1, None, None)
                    .await
                    .expect("create the manager's session")
            );

            let (status, body) = call(
                &common::admin_router(&state),
                &cookie,
                "POST",
                "/admin/users/batch-disable",
                Some(serde_json::json!({ "ids": [member, admin] })),
            )
            .await;

            assert_eq!(status, StatusCode::OK, "body: {body}");
            assert_eq!(
                body, r#"{"disabled":1}"#,
                "only the member is within a manager's reach"
            );

            assert_eq!(
                access_of(&state.pool, member).await,
                ("disabled".to_string(), true),
                "the member must be disabled, with the local intent recorded"
            );
            assert_eq!(
                access_of(&state.pool, admin).await,
                ("active".to_string(), false),
                "the admin must be untouched"
            );
            assert_eq!(
                sessions_of(&state.pool, member).await,
                0,
                "a disabled account must not keep live sessions"
            );
            assert_eq!(
                sessions_of(&state.pool, admin).await,
                1,
                "and an untouched account keeps its own"
            );
        },
    )
    .await;

    common::delete_user(&state.pool, manager).await;
}

#[tokio::test]
async fn the_count_covers_only_the_accounts_that_changed() {
    let Some(state) = common::state().await else {
        return;
    };

    let (caller, cookie) = common::admin_cookie(&state).await;
    let first = common::create_user(&state.pool, "").await;
    let second = common::create_user(&state.pool, "").await;
    let absent = Uuid::new_v4();

    common::with_users(
        state.clone(),
        vec![first, second],
        move |state, users| async move {
            let router = common::admin_router(&state);

            let (status, body) = call(
                &router,
                &cookie,
                "POST",
                "/admin/users/batch-disable",
                Some(serde_json::json!({ "ids": [users[0], absent, users[1]] })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                body, r#"{"disabled":2}"#,
                "an id that does not exist is not a disable"
            );

            // Idempotent: disabling an already-disabled account still reports it,
            // because the row was written and the session sweep ran.
            let (status, body) = call(
                &router,
                &cookie,
                "POST",
                "/admin/users/batch-disable",
                Some(serde_json::json!({ "ids": users })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, r#"{"disabled":2}"#);
        },
    )
    .await;

    common::delete_user(&state.pool, caller).await;
}

/// The bulk path recorded no audit events at all, so a selection of accounts
/// disabled by a manager left nothing behind naming who they were.
#[tokio::test]
async fn every_account_in_the_batch_is_audited() {
    let Some(state) = common::state().await else {
        return;
    };

    let (caller, cookie) = common::admin_cookie(&state).await;
    let first = common::create_user(&state.pool, "").await;
    let second = common::create_user(&state.pool, "").await;

    common::with_users(
        state.clone(),
        vec![first, second],
        move |state, users| async move {
            let (status, body) = call(
                &common::admin_router(&state),
                &cookie,
                "POST",
                "/admin/users/batch-disable",
                Some(serde_json::json!({ "ids": users })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "body: {body}");

            let audited: Vec<(String, String)> = sqlx::query_as(
                "SELECT resource_id, detail->>'email' FROM audit_logs \
                 WHERE action = 'user.disable' AND actor_user_id = $1",
            )
            .bind(caller)
            .fetch_all(&state.pool)
            .await
            .expect("read the audit trail");

            let mut ids: Vec<String> = audited.iter().map(|(id, _)| id.clone()).collect();
            ids.sort();
            let mut expected: Vec<String> = users.iter().map(|u| u.to_string()).collect();
            expected.sort();
            assert_eq!(ids, expected, "one event per disabled account");

            assert!(
                audited.iter().all(|(_, email)| !email.is_empty()),
                "each event names the account: {audited:?}"
            );
        },
    )
    .await;

    common::delete_user(&state.pool, caller).await;
}
