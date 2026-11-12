//! Admin API machine credentials (PAT): a bearer token lets automation call
//! the admin API without a browser session, but carries no authority of its
//! own — every call resolves the owning user, so role, status, revocation,
//! expiry and the must-change-password gate all apply at request time.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

async fn call_admin(
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
    let response = signet::admin::router()
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

/// Same, but authenticating with `Authorization: Bearer <token>` instead of
/// the session cookie — exactly what a cron job or CI pipeline sends.
async fn call_admin_bearer(
    state: &signet::state::AppState,
    bearer: &str,
    method: &str,
    uri: &str,
) -> (StatusCode, Value) {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            12345,
        ))));
    let response = signet::admin::router()
        .with_state(state.clone())
        .oneshot(builder.body(Body::empty()).expect("build request"))
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
async fn a_pat_calls_the_admin_api_and_is_reusable() {
    let Some(state) = common::state().await else {
        return;
    };
    let (_, cookie) = common::admin_cookie(&state).await;

    // Mint the token over the session channel.
    let (status, body) = call_admin(
        &state,
        &cookie,
        "POST",
        "/admin/tokens",
        Some(json!({ "name": "ci", "expires_in_days": 30 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().expect("plaintext returned once");
    assert!(token.starts_with("sgn_pat_"), "{body}");
    let token_id = body["id"].as_str().expect("id");

    // The plaintext is a credential, not stored verbatim.
    let stored: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM admin_api_tokens WHERE token_hash = $1")
            .bind(token)
            .fetch_one(&state.pool)
            .await
            .expect("check storage");
    assert_eq!(stored, 0, "the plaintext must never be stored");

    // Bearer calls work — twice: a PAT is reusable until revoked.
    for _ in 0..2 {
        let (status, body) = call_admin_bearer(&state, token, "GET", "/admin/stats").await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    // last_used_at is tracked for the inventory view.
    let used: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_used_at FROM admin_api_tokens WHERE id = $1")
            .bind(token_id.parse::<Uuid>().expect("uuid"))
            .fetch_one(&state.pool)
            .await
            .expect("read last_used_at");
    assert!(used.is_some(), "last_used_at must be stamped");

    // And the listing shows it (with the owner's email).
    let (status, body) = call_admin(&state, &cookie, "GET", "/admin/tokens", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed = body["tokens"]
        .as_array()
        .expect("token list")
        .iter()
        .find(|t| t["id"] == json!(token_id))
        .expect("created token is listed")
        .clone();
    assert_eq!(listed["name"], json!("ci"));
    assert!(listed["user_email"].as_str().unwrap().contains('@'));
}

#[tokio::test]
async fn revocation_expiry_and_owner_status_all_gate_the_token() {
    let Some(state) = common::state().await else {
        return;
    };
    let (_, cookie) = common::admin_cookie(&state).await;

    // Revoked token: dead on the next request.
    let (_, body) = call_admin(
        &state,
        &cookie,
        "POST",
        "/admin/tokens",
        Some(json!({ "name": "revoke-me" })),
    )
    .await;
    let revoked = body["token"].as_str().expect("plaintext");
    let revoked_id = body["id"].as_str().expect("id").to_string();
    let (status, _) = call_admin(
        &state,
        &cookie,
        "DELETE",
        &format!("/admin/tokens/{revoked_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call_admin_bearer(&state, revoked, "GET", "/admin/stats").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked token is dead");

    // Expired token: same.
    let (_, body) = call_admin(
        &state,
        &cookie,
        "POST",
        "/admin/tokens",
        Some(json!({ "name": "expired", "expires_in_days": 1 })),
    )
    .await;
    let expired = body["token"].as_str().expect("plaintext");
    let expired_id = body["id"]
        .as_str()
        .expect("id")
        .parse::<Uuid>()
        .expect("uuid");
    sqlx::query(
        "UPDATE admin_api_tokens SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1",
    )
    .bind(expired_id)
    .execute(&state.pool)
    .await
    .expect("age the token past expiry");
    let (status, _) = call_admin_bearer(&state, expired, "GET", "/admin/stats").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "expired token is dead");

    // Owner demoted to member: the token still resolves, but the admin role
    // check rejects — authority follows the account, not the credential.
    let (_, body) = call_admin(
        &state,
        &cookie,
        "POST",
        "/admin/tokens",
        Some(json!({ "name": "demote-me" })),
    )
    .await;
    let demoted = body["token"].as_str().expect("plaintext");
    sqlx::query("UPDATE users SET role = 'member' WHERE id = (SELECT user_id FROM admin_api_tokens WHERE token_hash = $1)")
        .bind(signet::crypto::util::sha256_hex(demoted))
        .execute(&state.pool)
        .await
        .expect("demote the owner");
    let (status, _) = call_admin_bearer(&state, demoted, "GET", "/admin/stats").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "demoted owner loses authority"
    );

    // Owner disabled: the token resolves to nothing at all. The status column
    // is guarded by a CHECK against the flag columns, so set both together.
    sqlx::query("UPDATE users SET status = 'disabled', local_disabled = TRUE WHERE id = (SELECT user_id FROM admin_api_tokens WHERE token_hash = $1)")
        .bind(signet::crypto::util::sha256_hex(demoted))
        .execute(&state.pool)
        .await
        .expect("disable the owner");
    let (status, _) = call_admin_bearer(&state, demoted, "GET", "/admin/stats").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "disabled owner is unauthenticated"
    );
}

#[tokio::test]
async fn forged_or_garbage_credentials_fail_without_fallback() {
    let Some(state) = common::state().await else {
        return;
    };
    let (_, cookie) = common::admin_cookie(&state).await;

    let (status, _) = call_admin_bearer(&state, "sgn_pat_forged", "GET", "/admin/stats").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "forged token rejected");

    // A cookie-authenticated request is unaffected (the two channels coexist).
    let (status, _) = call_admin(&state, &cookie, "GET", "/admin/stats", None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn member_role_cannot_mint_tokens() {
    let Some(state) = common::state().await else {
        return;
    };
    let user_id = common::create_user(&state.pool, "").await;
    let token = signet::auth::session::create_session(&state.pool, user_id, 1, None, None)
        .await
        .expect("create a member session");
    let cookie = format!("{}={token}", signet::auth::session::SESSION_COOKIE);
    let (status, _) = call_admin(
        &state,
        &cookie,
        "POST",
        "/admin/tokens",
        Some(json!({ "name": "nope" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "members cannot mint PATs");
}
