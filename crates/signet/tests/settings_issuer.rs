//! The issuer as a dashboard setting.
//!
//! What these tests pin down is the contract that makes a web-editable issuer
//! safe enough: the database wins over the environment (so the dashboard stays
//! editable even when `SIGNET_ISSUER` is set; the variable is the fallback),
//! the first save locks further edits until repeated changes are explicitly
//! allowed, clearing the override (DELETE) falls back to the environment, a
//! change applies to this process immediately (discovery and token validation
//! both read the runtime value), and every change is audited.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn call(
    state: &signet::state::AppState,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    let response = signet::settings::router()
        .with_state(state.clone())
        .oneshot(builder.body(body).expect("build request"))
        .await
        .expect("settings router answers");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn oidc_get(state: &signet::state::AppState, uri: &str) -> Value {
    let response = signet::oidc::router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oidc router answers");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// `server.issuer` is a singleton row in a shared database, so the tests in
/// this binary must not interleave: each one would see the other's save.
static ISSUER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Leaves no `server.*` override behind for the next run.
async fn clear_server_rows(pool: &sqlx::PgPool) {
    sqlx::query("DELETE FROM app_settings WHERE key LIKE 'server.%'")
        .execute(pool)
        .await
        .expect("clear issuer settings");
}

#[tokio::test]
async fn the_issuer_is_saved_once_then_locked_until_unlocked() {
    let _guard = ISSUER_LOCK.lock().await;
    let Some(state) = common::state_with(|cfg| {
        cfg.issuer_from_env = false;
        cfg.cookie_secure_forced = false;
    })
    .await
    else {
        return;
    };
    // A previous failed run may have left the override behind; the assertions
    // below start from "no dashboard value".
    clear_server_rows(&state.pool).await;

    let (admin, cookie) = common::admin_cookie(&state).await;
    common::with_user(state.clone(), admin, move |state, _| async move {
        // 1. Nothing saved: the built-in default is in force and edits are open.
        let (status, body) =
            call(&state, "GET", "/admin/settings/server", Some(&cookie), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["source"], json!("default"));
        assert_eq!(body["env_fallback"], json!(false));
        assert_eq!(body["locked"], json!(false));

        // 2. First save through the dashboard: persisted, applied immediately,
        //    and the field locks behind it.
        let (status, body) = call(
            &state,
            "PATCH",
            "/admin/settings/server",
            Some(&cookie),
            Some(json!({ "issuer": "https://sso.example.com" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["source"], json!("database"));
        assert_eq!(body["issuer"], json!("https://sso.example.com"));
        assert_eq!(body["locked"], json!(true));
        assert_eq!(body["allow_repeat_changes"], json!(false));

        assert_eq!(
            state.issuer(),
            "https://sso.example.com",
            "the running process switches to the new issuer"
        );
        assert!(
            state.cookie_secure(),
            "an https issuer secures cookies without a restart"
        );
        let doc = oidc_get(&state, "/.well-known/openid-configuration").await;
        assert_eq!(doc["issuer"], json!("https://sso.example.com"));
        assert_eq!(
            doc["token_endpoint"],
            json!("https://sso.example.com/oauth/token")
        );

        // 3. Locked: a second change is refused until repeated changes are allowed.
        let (status, _) = call(
            &state,
            "PATCH",
            "/admin/settings/server",
            Some(&cookie),
            Some(json!({ "issuer": "https://other.example.com" })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(state.issuer(), "https://sso.example.com");

        // 4. Unlock (audited), then change again.
        let (status, body) = call(
            &state,
            "PATCH",
            "/admin/settings/server",
            Some(&cookie),
            Some(json!({ "allow_repeat_changes": true })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["locked"], json!(false));

        let (status, body) = call(
            &state,
            "PATCH",
            "/admin/settings/server",
            Some(&cookie),
            Some(json!({ "issuer": "https://id.example.com" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(state.issuer(), "https://id.example.com");

        // 5. Shape validation: an origin only, no path.
        let (status, _) = call(
            &state,
            "PATCH",
            "/admin/settings/server",
            Some(&cookie),
            Some(json!({ "issuer": "https://id.example.com/oauth" })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(state.issuer(), "https://id.example.com");

        // 6. Both the change and the unlock were audited.
        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs \
             WHERE action IN ('settings.issuer_update', 'settings.issuer_repeat_policy') \
               AND resource_id = 'issuer'",
        )
        .fetch_one(&state.pool)
        .await
        .expect("count issuer audit events");
        assert!(
            audited >= 3,
            "expected at least three events, found {audited}"
        );

        clear_server_rows(&state.pool).await;
    })
    .await;
}

#[tokio::test]
async fn the_database_overrides_the_environment_and_reset_falls_back() {
    let _guard = ISSUER_LOCK.lock().await;
    // The operator's requirement: with SIGNET_ISSUER present the dashboard is
    // still authoritative. The variable seeds the value, the first save
    // overrides it, and DELETE restores it.
    let Some(state) = common::state_with(|cfg| {
        cfg.issuer_from_env = true;
        cfg.issuer = "https://env.example".into();
        cfg.cookie_secure_forced = false;
    })
    .await
    else {
        return;
    };
    clear_server_rows(&state.pool).await;

    let (admin, cookie) = common::admin_cookie(&state).await;
    common::with_user(state.clone(), admin, move |state, _| async move {
        // 1. No saved value: the environment is the effective fallback.
        let (status, body) =
            call(&state, "GET", "/admin/settings/server", Some(&cookie), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["source"], json!("environment"));
        assert_eq!(body["env_fallback"], json!(true));
        assert_eq!(body["issuer"], json!("https://env.example"));
        assert_eq!(body["locked"], json!(false));
        assert_eq!(state.issuer(), "https://env.example");

        // 2. A dashboard save wins over the environment and applies immediately.
        let (status, body) = call(
            &state,
            "PATCH",
            "/admin/settings/server",
            Some(&cookie),
            Some(json!({ "issuer": "https://db.example" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["source"], json!("database"));
        assert_eq!(body["issuer"], json!("https://db.example"));
        assert_eq!(
            state.issuer(),
            "https://db.example",
            "the database value is the effective issuer, even with the env var set"
        );

        // 3. Clearing the override returns to the environment value.
        let (status, body) = call(
            &state,
            "DELETE",
            "/admin/settings/server",
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["source"], json!("environment"));
        assert_eq!(body["issuer"], json!("https://env.example"));
        assert_eq!(state.issuer(), "https://env.example");
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM app_settings WHERE key LIKE 'server.%'")
                .fetch_one(&state.pool)
                .await
                .expect("count server rows");
        assert_eq!(remaining, 0, "both issuer rows are cleared");

        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs \
             WHERE action = 'settings.issuer_reset' AND resource_id = 'issuer'",
        )
        .fetch_one(&state.pool)
        .await
        .expect("count reset events");
        assert!(audited >= 1, "the reset is audited");

        clear_server_rows(&state.pool).await;
    })
    .await;
}
