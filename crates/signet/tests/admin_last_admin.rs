//! The last-admin guard.
//!
//! `/setup` re-arms the moment no active `admin` row exists, and it accepts an
//! unauthenticated body — that is its job on first boot. So every admin-API
//! write that can empty the admin set has to refuse to: demotion (the hole this
//! guard closed — an admin could demote *themselves*, the one mutation no other
//! rule blocked), disable, delete, and the batch disable. The guard is
//! transactional with the write it guards and serialized against `/setup` via
//! the same advisory lock, so the tests here only pin the sequential behavior;
//! the mutual-race shape is what the lock is for and cannot be asserted over
//! HTTP one request at a time.
//!
//! The refusal tests need "I am the only active admin" to be true globally, so
//! they serialize on a shared mutex and clear leftover admin rows first: cargo
//! runs one test binary at a time, but the tests inside a binary run in
//! parallel.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

static LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

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

/// Removes every admin row, so "the only active admin" is a state a test can
/// actually establish. Users cascade their sessions and identities; the audit
/// rows keep the actor id only as a nullable reference.
async fn reset_admins(pool: &PgPool) {
    sqlx::query("DELETE FROM users WHERE role = 'admin'")
        .execute(pool)
        .await
        .expect("clear leftover admin rows");
}

async fn role_of(pool: &PgPool, user: Uuid) -> String {
    sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("read the role")
}

#[tokio::test]
async fn the_sole_admin_cannot_demote_themselves() {
    let _guard = LOCK.lock().await;
    let Some(state) = common::state().await else {
        return;
    };
    reset_admins(&state.pool).await;
    // After the reset, `admin_cookie` creates the only active admin — so
    // demoting that very account is the takeover shape: it would re-arm the
    // public `/setup` for whoever asks next.
    let (admin, cookie) = common::admin_cookie(&state).await;

    let (status, body) = call(
        &common::admin_router(&state),
        &cookie,
        "PUT",
        &format!("/admin/users/{admin}"),
        Some(json!({ "role": "member" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("no active administrator"), "{body}");
    assert_eq!(
        role_of(&state.pool, admin).await,
        "admin",
        "no change landed"
    );
}

#[tokio::test]
async fn demotion_succeeds_once_another_active_admin_exists() {
    let _guard = LOCK.lock().await;
    let Some(state) = common::state().await else {
        return;
    };
    // The actor is the second admin; demoting the first one leaves one behind,
    // which is the ordinary succession case the guard must not break.
    let (_, cookie) = common::admin_cookie(&state).await;
    let other = common::create_user(&state.pool, "").await;
    sqlx::query("UPDATE users SET role = 'admin' WHERE id = $1")
        .bind(other)
        .execute(&state.pool)
        .await
        .expect("promote the second admin");

    let (status, body) = call(
        &common::admin_router(&state),
        &cookie,
        "PUT",
        &format!("/admin/users/{other}"),
        Some(json!({ "role": "member" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(role_of(&state.pool, other).await, "member");
}

/// A member control: the guard must fire for admins only, not become some
/// broader write block.
#[tokio::test]
async fn demoting_a_member_is_not_blocked() {
    let _guard = LOCK.lock().await;
    let Some(state) = common::state().await else {
        return;
    };
    let (_, cookie) = common::admin_cookie(&state).await;
    let member = common::create_user(&state.pool, "").await;

    let (status, body) = call(
        &common::admin_router(&state),
        &cookie,
        "PUT",
        &format!("/admin/users/{member}"),
        Some(json!({ "role": "manager" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(role_of(&state.pool, member).await, "manager");
}

/// Function-level pin for the disable arm: `set_user_access` carries no actor
/// concept, so the guard itself must refuse to disable the only active admin.
#[tokio::test]
async fn disabling_the_last_admin_is_refused() {
    let _guard = LOCK.lock().await;
    let Some(state) = common::state().await else {
        return;
    };
    reset_admins(&state.pool).await;
    let (admin, _cookie) = common::admin_cookie(&state).await;

    let err = signet::admin::set_user_access(&state, admin, signet::admin::UserAccess::Disabled)
        .await
        .expect_err("disabling the only active admin must fail");
    assert!(err.to_string().contains("no active administrator"), "{err}");
    let status: String = sqlx::query_scalar("SELECT status FROM users WHERE id = $1")
        .bind(admin)
        .fetch_one(&state.pool)
        .await
        .expect("the admin is unchanged");
    assert_eq!(status, "active");

    // With a second admin present the same call goes through: the guard allows
    // succession, it only refuses the emptying of the set.
    let other = common::create_user(&state.pool, "").await;
    sqlx::query("UPDATE users SET role = 'admin' WHERE id = $1")
        .bind(other)
        .execute(&state.pool)
        .await
        .expect("promote a second admin");
    let user = signet::admin::set_user_access(&state, other, signet::admin::UserAccess::Disabled)
        .await
        .expect("disabling the second admin is allowed");
    assert_eq!(user.status, "disabled");
}
