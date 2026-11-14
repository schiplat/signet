//! Machine-to-machine tokens: client_credentials and introspection.
//!
//! The client-credentials grant makes a client a standalone principal —
//! `sub` is the client itself, user claims are absent by construction, and
//! introspection is the revocation-aware counterpart that a locally-verified
//! JWT cannot provide (a disabled user or client must flip `active` to false
//! before the token expires).
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use jsonwebtoken::{decode, Algorithm, Validation};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

const REDIRECT_URI: &str = "http://localhost/cb";

/// A client with the given grants and extra claims; returns (client_id, secret).
async fn create_client(
    state: &signet::state::AppState,
    grants: &[&str],
    extra_claims: Value,
) -> (String, String) {
    let client_id = format!("m2m-{}", Uuid::new_v4().simple());
    let secret = "m2m-secret-0123456789abcdef";
    let hash = signet::auth::client_secret::digest(&state.client_secret_key, secret);
    sqlx::query(
        r#"
        INSERT INTO client_apps
            (id, client_id, client_secret_hash, redirect_uris, grant_types,
             scopes, ip_allowlist_enabled, extra_claims)
        VALUES ($1, $2, $3, ARRAY[$4], $5, ARRAY['openid'], FALSE, $6)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&client_id)
    .bind(hash)
    .bind(REDIRECT_URI)
    .bind(grants)
    .bind(extra_claims)
    .execute(&state.pool)
    .await
    .expect("insert the m2m client");
    (client_id, secret.to_string())
}

async fn post_token(state: &signet::state::AppState, body: String) -> (StatusCode, Value) {
    let response = signet::oidc::router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    12345,
                ))))
                .body(Body::from(body))
                .expect("build request"),
        )
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

async fn introspect_raw(state: &signet::state::AppState, body: String) -> (StatusCode, Value) {
    let response = signet::oidc::router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    12345,
                ))))
                .body(Body::from(body))
                .expect("build request"),
        )
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

async fn introspect(state: &signet::state::AppState, body: String) -> Value {
    let (status, value) = introspect_raw(state, body).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    value
}

/// Only an access token is introspectable. An id_token is signed by the same
/// key with the same issuer and carries no `token_use` at all, so signature and
/// `iss` cannot distinguish it — a resource server that trusted this response
/// would accept an RP's session token as an API credential.
#[tokio::test]
async fn an_id_token_is_not_introspectable_as_an_access_token() {
    let Some(state) = common::state().await else {
        return;
    };
    let (client_id, secret) = create_client(&state, &["client_credentials"], json!({})).await;
    let user = common::create_user(&state.pool, "").await;
    let sub: String = sqlx::query_scalar("SELECT sub FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&state.pool)
        .await
        .expect("read sub");

    let now = chrono::Utc::now().timestamp();
    // Exactly what IdTokenClaims emits: no token_use, an at_hash, an aud.
    let id_token = state
        .keys
        .load()
        .encode(&json!({
            "iss": state.issuer(),
            "sub": sub,
            "aud": client_id,
            "exp": now + 300,
            "iat": now,
            "at_hash": "abc123",
        }))
        .expect("sign an id_token");
    let (status, body) = introspect_raw(
        &state,
        format!("client_id={client_id}&client_secret={secret}&token={id_token}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["active"],
        json!(false),
        "an id_token must not introspect as an access token"
    );

    // Same for a token with no discriminator at all (e.g. a logout hint's
    // shape): absence must be inactive, never "active by default".
    let bare = state
        .keys
        .load()
        .encode(&json!({
            "iss": state.issuer(),
            "sub": sub,
            "aud": client_id,
            "exp": now + 300,
            "iat": now,
        }))
        .expect("sign a bare token");
    let (_, body) = introspect_raw(
        &state,
        format!("client_id={client_id}&client_secret={secret}&token={bare}"),
    )
    .await;
    assert_eq!(body["active"], json!(false), "{body}");

    common::delete_user(&state.pool, user).await;
}

#[tokio::test]
async fn client_credentials_mints_a_client_principal_without_a_refresh_token() {
    let Some(state) = common::state().await else {
        return;
    };
    let (client_id, secret) = create_client(&state, &["client_credentials"], json!({})).await;

    let (status, body) = post_token(
        &state,
        format!(
            "grant_type=client_credentials&scope=openid&client_id={client_id}&client_secret={secret}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let _ = &body;
    assert!(body["refresh_token"].is_null(), "no refresh token: {body}");
    assert_eq!(body["scope"], json!("openid"));

    // Decode: sub is the client itself, no user claims.
    let token = body["access_token"].as_str().expect("access token");
    let mut validation = Validation::new(Algorithm::RS256);
    let issuer = state.issuer();
    validation.set_issuer(&[issuer.as_str()]);
    validation.validate_aud = false;
    let data = decode::<Value>(token, state.keys.load().decoding(), &validation).expect("decode");
    assert_eq!(data.claims["sub"], json!(client_id));
    assert_eq!(data.claims["token_use"], json!("access"));
    assert!(data.claims.get("email").is_none());
    assert!(data.claims.get("groups").is_none());
}

#[tokio::test]
async fn a_client_without_the_client_credentials_grant_is_refused() {
    let Some(state) = common::state().await else {
        return;
    };
    let (client_id, secret) = create_client(&state, &["authorization_code"], json!({})).await;
    let (status, body) = post_token(
        &state,
        format!("grant_type=client_credentials&client_id={client_id}&client_secret={secret}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], json!("unsupported_grant_type"));
}

#[tokio::test]
async fn extra_claims_resolve_for_m2m_with_literals_and_abort_on_user_fields() {
    let Some(state) = common::state().await else {
        return;
    };
    // Literal values (string/number/boolean) survive the userless mint.
    let (client_id, secret) = create_client(
        &state,
        &["client_credentials"],
        json!({ "team": "infra", "tier": 2, "trusted": true }),
    )
    .await;
    let (status, body) = post_token(
        &state,
        format!("grant_type=client_credentials&client_id={client_id}&client_secret={secret}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().expect("token");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    let data = decode::<Value>(token, state.keys.load().decoding(), &validation).expect("decode");
    assert_eq!(data.claims["team"], json!("infra"));
    assert_eq!(data.claims["tier"], json!(2));
    assert_eq!(data.claims["trusted"], json!(true));

    // A $field placeholder has no user to resolve against: the mint aborts
    // rather than silently dropping a claim the RP was promised.
    let (client_id, secret) =
        create_client(&state, &["client_credentials"], json!({ "who": "$email" })).await;
    let (status, _) = post_token(
        &state,
        format!("grant_type=client_credentials&client_id={client_id}&client_secret={secret}"),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn introspection_reports_active_and_dead_tokens() {
    let Some(state) = common::state().await else {
        return;
    };
    let (client_id, secret) = create_client(&state, &["client_credentials"], json!({})).await;
    let auth = format!("client_id={client_id}&client_secret={secret}");

    let (_, body) = post_token(
        &state,
        format!("grant_type=client_credentials&client_id={client_id}&client_secret={secret}"),
    )
    .await;
    let token = body["access_token"].as_str().expect("token").to_string();

    // Active: the happy path returns the principal and scope.
    let result = introspect(&state, format!("{auth}&token={token}")).await;
    assert_eq!(result["active"], json!(true), "{result}");
    assert_eq!(result["sub"], json!(client_id));
    assert_eq!(result["client_id"], json!(client_id));

    // Tampered / garbage token: inactive, not an error (RFC 7662 §2.2).
    let result = introspect(&state, format!("{auth}&token=garbage")).await;
    assert_eq!(result["active"], json!(false));

    // Bad caller credentials: 401, not active:false.
    let (status, _) = introspect_raw(
        &state,
        format!("token={token}&client_id={client_id}&client_secret=wrong"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The introspection promise this batch exists for: a **disabled user's** token
/// flips `active` to false before expiry — what local JWT verification cannot
/// see.
#[tokio::test]
async fn a_disabled_user_token_introspects_as_inactive() {
    let Some(state) = common::state().await else {
        return;
    };
    let (client_id, secret) = create_client(&state, &["client_credentials"], json!({})).await;
    let user = common::create_user(&state.pool, "").await;
    let sub: String = sqlx::query_scalar("SELECT sub FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&state.pool)
        .await
        .expect("read sub");

    // Mint a user-shaped token directly (signature is what introspect trusts;
    // the user-status check is the behavior under test).
    let now = chrono::Utc::now().timestamp();
    let token = state
        .keys
        .load()
        .encode(&json!({
            "iss": state.issuer(),
            "sub": sub,
            "aud": client_id,
            "exp": now + 3600,
            "iat": now,
            "scope": "openid",
            "token_use": "access",
        }))
        .expect("sign user token");

    let auth = format!("client_id={client_id}&client_secret={secret}");
    let result = introspect(&state, format!("{auth}&token={token}")).await;
    assert_eq!(result["active"], json!(true));

    // Disable the user via the admin path (the CHECK constraint requires the
    // disable flags to agree with status, so raw SQL is not an option).
    signet::admin::set_user_access(&state, user, signet::admin::UserAccess::Disabled)
        .await
        .expect("disable user");
    let result = introspect(&state, format!("{auth}&token={token}")).await;
    assert_eq!(result["active"], json!(false), "{result}");

    common::delete_user(&state.pool, user).await;
}
