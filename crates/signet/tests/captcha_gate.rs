//! The CAPTCHA gate on the unauthenticated doors: when a provider is
//! configured, login and password-reset requests must carry a verifiable
//! token; when it is not, nothing changes. The provider is a local stub
//! behind `SIGNET_CAPTCHA_VERIFY_URL` — the override the feature exists to
//! support (self-hosted hCaptcha-compatible services, and this test).
//!
//! One test function drives the whole flow: the verify URL is process-global
//! state, so the stub and its URL are set up once here rather than racing
//! sibling tests.

mod common;

use axum::body::Body;
use axum::http::{Request as HttpRequest, StatusCode};
use axum::{Json, Router};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn call(
    state: &signet::state::AppState,
    method: &str,
    uri: &str,
    body: Value,
) -> (StatusCode, Value) {
    let builder = HttpRequest::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            12345,
        ))));
    // Both gated doors live under the same /api/v1 prefix in the live app;
    // the merged router here is the same shape without the statics.
    let app = signet::auth::router()
        .merge(signet::auth::password_reset::router())
        .with_state(state.clone());
    let response = app
        .oneshot(builder.body(Body::from(body.to_string())).expect("body"))
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

/// The siteverify stub: token "good" verifies, anything else is refused with
/// the same `error-codes` shape the real providers use.
async fn stub_verify(axum::extract::Form(form): axum::extract::Form<HashMapStub>) -> Json<Value> {
    if form.response == "good" {
        Json(json!({ "success": true }))
    } else {
        Json(json!({ "success": false, "error-codes": ["invalid-input-response"] }))
    }
}

/// The form fields both providers post (`secret`, `response`, `remoteip`).
#[derive(serde::Deserialize)]
struct HashMapStub {
    #[allow(dead_code)]
    secret: String,
    response: String,
}

#[tokio::test]
async fn the_gate_challenges_the_unauthenticated_doors() {
    // dev_log_links lets the reset flow run to its always-200 answer without
    // an SMTP relay — the assertion then proves the CAPTCHA gate (not the
    // 503) is what stood between the request and the handler.
    let Some(state) = common::state_with(|cfg| cfg.dev_log_links = true).await else {
        return;
    };
    // Start clean: the namespace persists across runs in the shared test DB.
    sqlx::query("DELETE FROM app_settings WHERE key LIKE 'captcha.%'")
        .execute(&state.pool)
        .await
        .expect("clear captcha settings");

    // ── The stub provider ────────────────────────────────────────────────
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub");
    let stub_addr = listener.local_addr().expect("stub addr");
    let stub = Router::new().route("/siteverify", axum::routing::post(stub_verify));
    tokio::spawn(async move {
        axum::serve(listener, stub).await.expect("stub serves");
    });
    std::env::set_var(
        "SIGNET_CAPTCHA_VERIFY_URL",
        format!("http://{stub_addr}/siteverify"),
    );

    // ── Configure the gate (encrypted secret, same as the SMTP password) ──
    sqlx::query("DELETE FROM app_settings WHERE key LIKE 'captcha.%'")
        .execute(&state.pool)
        .await
        .expect("clear");
    for (key, value) in [
        ("captcha.provider", json!("turnstile")),
        ("captcha.site_key", json!("site-key-1")),
        (
            "captcha.secret_key",
            json!(state.encryptor.encrypt("captcha-secret-1")),
        ),
    ] {
        sqlx::query(
            "INSERT INTO app_settings (key, value, updated_at) VALUES ($1, $2, NOW()) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(key)
        .bind(value)
        .execute(&state.pool)
        .await
        .expect("save captcha setting");
    }

    // Discovery says the gate is on, with the site key and no secret.
    let (status, body) = call(&state, "GET", "/captcha", json!(null)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], json!(true));
    assert_eq!(body["provider"], json!("turnstile"));
    assert_eq!(body["site_key"], json!("site-key-1"));
    assert!(body.get("secret").is_none(), "no secret in the public view");

    // ── Login: no token → refused before any user lookup ────────────────
    let (status, body) = call(
        &state,
        "POST",
        "/login",
        json!({ "email": "nobody@example.com", "password": "whatever" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // A token the provider refuses → same refusal.
    let (status, body) = call(
        &state,
        "POST",
        "/login",
        json!({ "email": "nobody@example.com", "password": "whatever", "captcha_token": "bogus" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // A token the provider accepts → the gate passes and the request
    // continues into the credential check (unknown address → 401).
    let (status, _) = call(
        &state,
        "POST",
        "/login",
        json!({ "email": "nobody@example.com", "password": "whatever", "captcha_token": "good" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the gate passed");

    // ── The reset door is gated the same way ────────────────────────────
    let (status, _) = call(
        &state,
        "POST",
        "/password-reset/request",
        json!({ "email": "nobody@example.com" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "reset without a token");
    let (status, _) = call(
        &state,
        "POST",
        "/password-reset/request",
        json!({ "email": "nobody@example.com", "captcha_token": "good" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reset with a verified token");

    // ── Turning the gate off restores the old behavior ──────────────────
    sqlx::query("DELETE FROM app_settings WHERE key LIKE 'captcha.%'")
        .execute(&state.pool)
        .await
        .expect("clear captcha settings");
    let (status, _) = call(
        &state,
        "POST",
        "/login",
        json!({ "email": "nobody@example.com", "password": "whatever" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "gate off: no challenge");
    let (status, _) = call(&state, "GET", "/captcha", json!(null)).await;
    assert_eq!(status, StatusCode::OK);
    // body checked below via a fresh call (call returns the value here)

    let (_, body) = call(&state, "GET", "/captcha", json!(null)).await;
    assert_eq!(body["enabled"], json!(false), "{body}");
}
