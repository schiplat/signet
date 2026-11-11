//! Runtime settings: DB overrides layered over the environment, and live apply.
//!
//! The endpoint is the difference between "change the retention window" and
//! "edit `.env`, redeploy, restart"; what has to hold is that a saved value
//! takes precedence, reaches the running state, is validated before it lands,
//! and can be cleared back to the environment value.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

/// The overrides live in one global `app_settings` table, so the tests that
/// write them serialize here: a count assertion in one must not see a row the
/// other is mid-way through adding.
static LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

async fn call(
    state: &signet::state::AppState,
    cookie: &str,
    method: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri("/admin/settings/runtime")
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(match body {
            Some(json) => Body::from(json.to_string()),
            None => Body::empty(),
        })
        .expect("build the request");
    let response = signet::settings::router()
        .with_state(state.clone())
        .oneshot(request)
        .await
        .expect("the settings router must answer");
    let status = response.status();
    let text = response
        .into_body()
        .collect()
        .await
        .expect("read the body")
        .to_bytes();
    let value = serde_json::from_slice(&text).unwrap_or(Value::Null);
    (status, value)
}

/// Removes the keys this module owns, so a leftover row from an earlier run
/// cannot change what another test sees.
async fn clear_overrides(pool: &PgPool) {
    sqlx::query("DELETE FROM app_settings WHERE key LIKE 'runtime.%'")
        .execute(pool)
        .await
        .expect("clear runtime overrides");
}

#[tokio::test]
async fn a_saved_value_overrides_the_environment_and_applies_live() {
    let _guard = LOCK.lock().await;
    let Some(state) = common::state().await else {
        return;
    };
    clear_overrides(&state.pool).await;
    let before = state.rt();

    let (_, cookie) = common::admin_cookie(&state).await;
    let (status, body) = call(&state, &cookie, "GET", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["settings"]["audit_retention_days"],
        json!(before.audit_retention_days)
    );

    // Pick a value that differs from the environment's, so "the DB won" is
    // observable rather than an accidental match.
    let target = if before.audit_retention_days == 7 {
        8
    } else {
        7
    };
    let (status, body) = call(
        &state,
        &cookie,
        "PATCH",
        Some(json!({ "audit_retention_days": target })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["settings"]["audit_retention_days"], json!(target));

    // Live: the running state, not just the row.
    assert_eq!(state.rt().audit_retention_days, target);

    // Reported as a DB override, which is what the UI marks differently from
    // an inherited environment value.
    let (_, body) = call(&state, &cookie, "GET", None).await;
    assert!(
        body["overridden"]
            .as_array()
            .expect("overridden is a list")
            .iter()
            .any(|v| v == "audit_retention_days"),
        "{body}"
    );

    // The reset endpoint drops the override and puts the environment value
    // back in force — including in the live state, not just in the response.
    let (status, body) = call(&state, &cookie, "DELETE", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["settings"]["audit_retention_days"],
        json!(before.audit_retention_days)
    );
    assert_eq!(state.rt().audit_retention_days, before.audit_retention_days);

    let (_, body) = call(&state, &cookie, "GET", None).await;
    assert!(
        body["overridden"]
            .as_array()
            .expect("overridden is a list")
            .is_empty(),
        "{body}"
    );
}

#[tokio::test]
async fn an_out_of_range_value_is_refused_and_nothing_is_written() {
    let _guard = LOCK.lock().await;
    let Some(state) = common::state().await else {
        return;
    };
    clear_overrides(&state.pool).await;
    let (_, cookie) = common::admin_cookie(&state).await;
    let before = state.rt();

    for bad in [
        json!({ "password_min_length": 3 }),
        json!({ "audit_retention_days": 0 }),
        json!({ "session_ttl_hours": 0 }),
        json!({ "rate_limit_per_minute": 0 }),
    ] {
        let (status, body) = call(&state, &cookie, "PATCH", Some(bad.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad} → {body}");
    }
    assert_eq!(state.rt().password_min_length, before.password_min_length);

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM app_settings WHERE key LIKE 'runtime.%'")
            .fetch_one(&state.pool)
            .await
            .expect("count overrides");
    assert_eq!(rows, 0, "a refused patch must not leave a row behind");
}

#[tokio::test]
async fn a_non_admin_cannot_read_or_change_the_settings() {
    let Some(state) = common::state().await else {
        return;
    };
    let member = common::create_user(&state.pool, "").await;
    let token = signet::auth::session::create_session(&state.pool, member, 1, None, None)
        .await
        .expect("create a member session");
    let cookie = format!("{}={token}", signet::auth::session::SESSION_COOKIE);

    let (status, _) = call(&state, &cookie, "GET", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        &state,
        &cookie,
        "PATCH",
        Some(json!({ "audit_retention_days": 7 })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    common::delete_user(&state.pool, member).await;
}
