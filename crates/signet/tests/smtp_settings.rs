//! SMTP relay settings: the dashboard-configured relay (DB, password
//! encrypted at rest) overrides the environment, absent fields leave things
//! alone, explicit nulls clear the override, and the whole path never sends
//! the stored password back out.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn call(
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

#[tokio::test]
async fn smtp_settings_configure_encrypt_and_clear() {
    let Some(state) = common::state().await else {
        return;
    };
    // The namespace persists in the shared test DB across runs; start clean.
    sqlx::query("DELETE FROM app_settings WHERE key LIKE 'smtp.%'")
        .execute(&state.pool)
        .await
        .expect("clear the smtp namespace");
    let (_, cookie) = common::admin_cookie(&state).await;

    // Not configured: the view says so, with nothing overridden.
    let (status, body) = call(&state, &cookie, "GET", "/admin/settings/smtp", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["configured"], json!(false));
    assert_eq!(body["overridden"], json!([]));

    // Save a relay; the response shows the effective view, never the password.
    let (status, body) = call(
        &state,
        &cookie,
        "PATCH",
        "/admin/settings/smtp",
        Some(json!({
            "host": "relay.internal.example",
            "port": 587,
            "username": "signet-mailer",
            "password": "s3cret-relay-password",
            "from": "Signet <no-reply@example.com>",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["configured"], json!(true));
    assert_eq!(body["host"], json!("relay.internal.example"));
    assert_eq!(body["port"], json!(587));
    assert_eq!(body["password_set"], json!(true));
    assert_eq!(
        body["overridden"],
        json!(["from", "host", "password", "port", "username"])
    );
    assert!(
        body.to_string().find("s3cret-relay-password").is_none(),
        "the plaintext password must never appear in a response"
    );

    // The stored password is ciphertext, decryptable with the app key.
    let stored: String =
        sqlx::query_scalar("SELECT value->>0 FROM app_settings WHERE key = 'smtp.password'")
            .fetch_one(&state.pool)
            .await
            .expect("read stored password");
    // A jsonb column stores the string wrapped; strip the quotes if present.
    let stored = stored.trim_matches('"').to_string();
    assert_ne!(
        stored, "s3cret-relay-password",
        "the password must not be stored in plaintext"
    );
    let decrypted = state
        .encryptor
        .decrypt(&stored)
        .expect("the stored password decrypts with the application key");
    assert_eq!(decrypted, "s3cret-relay-password");

    // Resolution now reports the relay — the same one email::send would use.
    let smtp = signet::email::resolve(&state)
        .await
        .expect("relay resolves");
    assert_eq!(smtp.host, "relay.internal.example");
    assert_eq!(smtp.port, 587);
    assert_eq!(smtp.password.as_deref(), Some("s3cret-relay-password"));

    // Absent fields leave things alone; explicit null clears the override so
    // the environment (here: nothing) applies again.
    let (status, body) = call(
        &state,
        &cookie,
        "PATCH",
        "/admin/settings/smtp",
        Some(json!({ "username": null })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["cleared"], json!(["username"]));
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM app_settings WHERE key = 'smtp.username'")
            .fetch_one(&state.pool)
            .await
            .expect("count rows");
    assert_eq!(remaining, 0, "the override row is gone");

    // The full reset drops everything in the namespace.
    let (status, body) = call(&state, &cookie, "DELETE", "/admin/settings/smtp", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["rows_deleted"].as_i64().unwrap() >= 4, "{body}");
    let (status, body) = call(&state, &cookie, "GET", "/admin/settings/smtp", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["configured"], json!(false));

    // The audit trail carries the lifecycle without any password material.
    let leaks: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs \
         WHERE action LIKE 'settings.smtp%' \
         AND detail::text LIKE '%s3cret-relay-password%'",
    )
    .fetch_one(&state.pool)
    .await
    .expect("audit check");
    assert_eq!(leaks, 0, "audit events must not contain the password");
}

#[tokio::test]
async fn invalid_relay_values_are_refused() {
    let Some(state) = common::state().await else {
        return;
    };
    let (_, cookie) = common::admin_cookie(&state).await;

    let (status, _) = call(
        &state,
        &cookie,
        "PATCH",
        "/admin/settings/smtp",
        Some(json!({ "from": "not a mailbox" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call(
        &state,
        &cookie,
        "PATCH",
        "/admin/settings/smtp",
        Some(json!({ "port": 0 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Empty string is a mistake, not a value: null is the way to clear.
    let (status, _) = call(
        &state,
        &cookie,
        "PATCH",
        "/admin/settings/smtp",
        Some(json!({ "host": "   " })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
