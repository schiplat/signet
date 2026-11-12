//! Branding: the product name the UI shows about itself. Public read
//! (sign-in/reset/setup are unauthenticated), admin write with validation,
//! DB > env precedence, and an audit trail without surprises.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn admin_call(
    state: &signet::state::AppState,
    cookie: &str,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            12345,
        ))));
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    let response = signet::settings::router()
        .with_state(state.clone())
        .oneshot(builder.body(body).expect("build request"))
        .await
        .expect("router answers");
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

/// The unauthenticated read lives on the public api_v1 router, not the admin
/// settings router — this is what the sign-in page mounts.
async fn public_branding(state: &signet::state::AppState) -> Value {
    let response = axum::Router::new()
        .route(
            "/branding",
            axum::routing::get(signet::settings::public_branding),
        )
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/branding")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router answers");
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

#[tokio::test]
async fn branding_names_validate_persist_and_reset() {
    let Some(state) = common::state().await else {
        return;
    };
    sqlx::query("DELETE FROM app_settings WHERE key = 'branding.name'")
        .execute(&state.pool)
        .await
        .expect("clear branding");
    let (_, cookie) = common::admin_cookie(&state).await;

    // Public read before anything is set: the built-in default.
    let body = public_branding(&state).await;
    assert_eq!(body["name"], json!("Signet"));

    // Save a name; the public endpoint serves it without authentication.
    let (status, body) = admin_call(
        &state,
        &cookie,
        "PATCH",
        "/admin/settings/branding",
        Some(json!({ "name": "  Acme Identity  " })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], json!("Acme Identity"), "trimmed on save");
    let body = public_branding(&state).await;
    assert_eq!(body["name"], json!("Acme Identity"));

    // Refusals: empty, too long, control characters.
    for bad in ["   ", "", &"x".repeat(65), "bad\u{0007}name"] {
        let (status, _) = admin_call(
            &state,
            &cookie,
            "PATCH",
            "/admin/settings/branding",
            Some(json!({ "name": bad })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?}");
    }

    // Reset falls back to the built-in default (no env override in tests).
    let (status, body) =
        admin_call(&state, &cookie, "DELETE", "/admin/settings/branding", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["overridden"], json!(false));
    let body = public_branding(&state).await;
    assert_eq!(body["name"], json!("Signet"));

    // The audit trail carries the lifecycle.
    let events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action IN ('settings.branding_update', 'settings.branding_reset')",
    )
    .fetch_one(&state.pool)
    .await
    .expect("count audit");
    assert!(events >= 2, "{events} branding audit events");
}
