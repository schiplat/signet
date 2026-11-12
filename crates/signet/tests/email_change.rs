//! Self-service email change: request → verification link → applied.
//!
//! The link token is the authentication for the confirm endpoint; the change
//! retires everything the old email authorized (sessions, refresh tokens,
//! back-channel logout) because the email is a recovery channel.
//!
//! Confirm answers a mail-client click with a 302 to a dashboard flag
//! (`/settings?email_changed=1`, `/settings?email_error=...`), so an assertion
//! here reads the `Location`, never a JSON body.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

fn tag(prefix: &str) -> String {
    format!("{}-{}", prefix, Uuid::new_v4().simple())
}

/// Drives one request against the auth router and returns status, `Location`
/// and body.
async fn call(
    state: &signet::state::AppState,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Option<String>, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            12345,
        ))));
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    let response = signet::auth::router()
        .with_state(state.clone())
        .oneshot(builder.body(body).expect("build request"))
        .await
        .expect("router answers");
    let status = response.status();
    let location = response
        .headers()
        .get(axum::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    (
        status,
        location,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Seeds a change request with a **known** token.
///
/// The real request path enqueues the token into the encrypted outbox, so a
/// test cannot read it back; planting the row directly exercises the confirm
/// endpoint from the link click onwards, which is the security-relevant half.
async fn seed_change(state: &signet::state::AppState, user: Uuid, token: &str, new_email: &str) {
    let token_hash = signet::crypto::util::sha256_hex(token);
    // Earlier failed runs may have left a row with the same deterministic
    // token; clear by hash, whatever user it belongs to.
    sqlx::query("DELETE FROM email_change_tokens WHERE token_hash = $1")
        .bind(&token_hash)
        .execute(&state.pool)
        .await
        .expect("clear prior change tokens");
    sqlx::query(
        r#"
        INSERT INTO email_change_tokens (id, user_id, token_hash, new_email, expires_at)
        VALUES ($1, $2, $3, $4, NOW() + INTERVAL '30 minutes')
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(user)
    .bind(&token_hash)
    .bind(new_email)
    .execute(&state.pool)
    .await
    .expect("seed change token");
}

#[tokio::test]
async fn a_verified_user_can_request_and_confirm_a_change() {
    let Some(state) = common::state().await else {
        return;
    };
    let user = common::create_user(&state.pool, "").await;
    let session = signet::auth::session::create_session(&state.pool, user, 1, None, None)
        .await
        .expect("session");
    let cookie = format!("{}={session}", signet::auth::session::SESSION_COOKIE);
    let new_email = format!("{}@changed.test", tag("ok"));

    // Request: the verification email goes into the outbox (SMTP may be
    // unconfigured; that is the outbox worker's concern, not this endpoint's).
    let (status, _, body) = call(
        &state,
        "POST",
        "/me/email/change-request",
        Some(&cookie),
        Some(json!({ "new_email": new_email })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let queued: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM outbox WHERE kind = 'email' AND email_to = $1")
            .bind(&new_email)
            .fetch_one(&state.pool)
            .await
            .expect("count outbox");
    assert_eq!(queued, 1, "the verification email must be enqueued");

    // A live session and a live refresh token both exist pre-confirm.
    let client_ref = tag("client");
    sqlx::query(
        "INSERT INTO client_apps (id, client_id, client_secret_hash, redirect_uris) \
         VALUES ($1, $2, 'x', ARRAY['http://localhost/cb'])",
    )
    .bind(Uuid::new_v4())
    .bind(&client_ref)
    .execute(&state.pool)
    .await
    .expect("seed client");
    let refresh = signet::crypto::util::random_token(32);
    sqlx::query(
        "INSERT INTO refresh_tokens (id, token_hash, client_id, user_id, scope, expires_at) \
         VALUES ($1, $2, $3, $4, 'openid', NOW() + INTERVAL '1 day')",
    )
    .bind(Uuid::new_v4())
    .bind(signet::crypto::util::sha256_hex(&refresh))
    .bind(&client_ref)
    .bind(user)
    .execute(&state.pool)
    .await
    .expect("seed refresh token");

    seed_change(&state, user, "link-token-1", &new_email).await;
    let (status, location, _) = call(
        &state,
        "GET",
        "/me/email/confirm?token=link-token-1",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        location.as_deref(),
        Some("/settings?email_changed=1"),
        "success lands on the dashboard flag"
    );

    let (email, verified): (String, bool) =
        sqlx::query_as("SELECT email, email_verified FROM users WHERE id = $1")
            .bind(user)
            .fetch_one(&state.pool)
            .await
            .expect("read changed user");
    assert_eq!((email.as_str(), verified), (new_email.as_str(), true));

    // The change retires what the old address authorized.
    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user)
        .fetch_one(&state.pool)
        .await
        .expect("count sessions");
    assert_eq!(sessions, 0, "all sessions die with the old email");
    let tokens: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user)
    .fetch_one(&state.pool)
    .await
    .expect("count refresh tokens");
    assert_eq!(tokens, 0, "refresh tokens die with the old email");

    // Single use: a second link (even a fresh one) is spent only once — and
    // replaying this one reports `expired` via the redirect, not an error page.
    let (status, location, _) = call(
        &state,
        "GET",
        "/me/email/confirm?token=link-token-1",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(location.as_deref(), Some("/settings?email_error=expired"));

    common::delete_user(&state.pool, user).await;
}

#[tokio::test]
async fn confirm_refuses_expired_and_taken_targets() {
    let Some(state) = common::state().await else {
        return;
    };
    let user = common::create_user(&state.pool, "").await;
    let taken = format!("{}@changed.test", tag("taken"));

    // Expired window.
    seed_change(&state, user, "expired-token", &taken).await;
    sqlx::query(
        "UPDATE email_change_tokens SET expires_at = NOW() - INTERVAL '1 minute' \
         WHERE new_email = $1",
    )
    .bind(&taken)
    .execute(&state.pool)
    .await
    .expect("expire the token");
    let (status, location, _) = call(
        &state,
        "GET",
        "/me/email/confirm?token=expired-token",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(location.as_deref(), Some("/settings?email_error=expired"));

    // Taken address: another account owns it by the time the link is clicked.
    let other = common::create_user(&state.pool, "").await;
    let taken_email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(other)
        .fetch_one(&state.pool)
        .await
        .expect("read the other user's email");
    seed_change(&state, user, "taken-token", &taken_email).await;
    let (status, location, _) = call(
        &state,
        "GET",
        "/me/email/confirm?token=taken-token",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(location.as_deref(), Some("/settings?email_error=taken"));

    common::delete_user(&state.pool, user).await;
    common::delete_user(&state.pool, other).await;
}

#[tokio::test]
async fn request_refuses_unverified_current_email_and_taken_new_email() {
    let Some(state) = common::state().await else {
        return;
    };
    let user = common::create_user(&state.pool, "").await;
    // An unverified starting address cannot self-serve a change; an admin can
    // fix that state, the user cannot.
    sqlx::query("UPDATE users SET email_verified = FALSE WHERE id = $1")
        .bind(user)
        .execute(&state.pool)
        .await
        .expect("unverify");
    let session = signet::auth::session::create_session(&state.pool, user, 1, None, None)
        .await
        .expect("session");
    let cookie = format!("{}={session}", signet::auth::session::SESSION_COOKIE);
    let (status, _, _) = call(
        &state,
        "POST",
        "/me/email/change-request",
        Some(&cookie),
        Some(json!({ "new_email": format!("{}@changed.test", tag("x")) })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A taken new address is refused outright (no email is even enqueued).
    let taken = common::create_user(&state.pool, "").await;
    let taken_email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(taken)
        .fetch_one(&state.pool)
        .await
        .expect("read taken email");
    sqlx::query("UPDATE users SET email_verified = TRUE WHERE id = $1")
        .bind(user)
        .execute(&state.pool)
        .await
        .expect("verify");
    let (status, _, body) = call(
        &state,
        "POST",
        "/me/email/change-request",
        Some(&cookie),
        Some(json!({ "new_email": taken_email })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap().contains("already exists"));

    common::delete_user(&state.pool, user).await;
    common::delete_user(&state.pool, taken).await;
}
