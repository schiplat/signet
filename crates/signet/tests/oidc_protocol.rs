//! OIDC protocol surface: the error channels standard clients depend on.
//!
//! Two things are pinned here, both invisible to a browser walk-through but
//! fatal to conformant client libraries:
//!
//! * `authorize` reports post-validation failures by redirecting to the
//!   registered `redirect_uri` with `error=` + `state` (RFC 6749 §4.1.2.1).
//!   `prompt=none` silent renewal reads the outcome from that redirect; a JSON
//!   400 is a dead end.
//! * `token` answers with RFC 6749 §5.2 codes (`invalid_client`,
//!   `unsupported_grant_type`, `invalid_grant`) instead of prose, and a 401
//!   carries `WWW-Authenticate`.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

const REDIRECT_URI: &str = "http://localhost/cb";

/// A client whose secret digest matches `secret`, and whose grant list is
/// deliberately narrow for the grant-enforcement case.
async fn create_client(state: &signet::state::AppState, grants: &[&str]) -> (String, String) {
    let client_id = format!("it-{}", Uuid::new_v4().simple());
    let secret = "test-secret-0123456789abcdef";
    let hash = signet::auth::client_secret::digest(&state.client_secret_key, secret);
    sqlx::query(
        r#"
        INSERT INTO client_apps
            (id, client_id, client_secret_hash, redirect_uris, grant_types, scopes,
             ip_allowlist_enabled)
        VALUES ($1, $2, $3, ARRAY[$4], $5, ARRAY['openid'], FALSE)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&client_id)
    .bind(hash)
    .bind(REDIRECT_URI)
    .bind(grants)
    .execute(&state.pool)
    .await
    .expect("insert a test client");
    (client_id, secret.to_string())
}

/// The OIDC routes with the state under test. `ConnectInfo` is supplied the
/// way `axum::serve` supplies it on a real connection.
fn router(state: &signet::state::AppState) -> axum::Router {
    signet::oidc::router().with_state(state.clone())
}

async fn get(
    state: &signet::state::AppState,
    uri: &str,
    cookie: Option<&str>,
) -> (StatusCode, Option<String>) {
    let response = router(state)
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("cookie", cookie.unwrap_or("signet_session=none"))
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    12345,
                ))))
                .body(Body::empty())
                .expect("build the request"),
        )
        .await
        .expect("router answers");
    let status = response.status();
    let location = response
        .headers()
        .get(axum::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (status, location)
}

async fn post_form(
    state: &signet::state::AppState,
    uri: &str,
    body: String,
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    let response = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/x-www-form-urlencoded")
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    12345,
                ))))
                .body(Body::from(body))
                .expect("build the request"),
        )
        .await
        .expect("router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read the body")
        .to_bytes();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// `prompt=none` with no session is the silent-renewal path: the RP must learn
/// `login_required` from the redirect, with its `state` echoed.
#[tokio::test]
async fn silent_renewal_without_a_session_redirects_with_login_required() {
    let Some(state) = common::state().await else {
        return;
    };
    let (client_id, _) = create_client(&state, &["authorization_code"]).await;
    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={}&scope=openid&state=st-123\
         &code_challenge={}&code_challenge_method=S256&prompt=none",
        urlencoding::encode(REDIRECT_URI),
        "a".repeat(43),
    );
    let (status, location) = get(&state, &uri, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location:?}");
    let location = location.expect("a redirect");
    assert!(location.starts_with(REDIRECT_URI), "{location}");
    assert!(location.contains("error=login_required"), "{location}");
    assert!(location.contains("state=st-123"), "{location}");
}

/// A client that is not registered for `authorization_code` must not receive a
/// code — the admin-facing grant list is part of the contract, not decoration.
#[tokio::test]
async fn a_client_without_the_authorization_code_grant_is_refused_by_redirect() {
    let Some(state) = common::state().await else {
        return;
    };
    let (client_id, _) = create_client(&state, &["refresh_token"]).await;
    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={}&scope=openid&state=st-9\
         &code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(REDIRECT_URI),
        "b".repeat(43),
    );
    let (status, location) = get(&state, &uri, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location:?}");
    let location = location.expect("a redirect");
    assert!(location.contains("error=unauthorized_client"), "{location}");
    assert!(location.contains("state=st-9"), "{location}");
}

/// A malformed PKCE challenge is reported through the redirect too, once the
/// redirect target is known.
#[tokio::test]
async fn a_short_pkce_challenge_is_reported_on_the_redirect() {
    let Some(state) = common::state().await else {
        return;
    };
    let (client_id, _) = create_client(&state, &["authorization_code"]).await;
    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={}&scope=openid&state=st-7\
         &code_challenge=tooshort&code_challenge_method=S256",
        urlencoding::encode(REDIRECT_URI),
    );
    let (status, location) = get(&state, &uri, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location:?}");
    let location = location.expect("a redirect");
    assert!(location.contains("error=invalid_request"), "{location}");
}

/// Wrong client secret: 401 with `invalid_client` and the Basic challenge,
/// which is what lets a client library distinguish this from a bad grant.
#[tokio::test]
async fn a_wrong_client_secret_is_an_invalid_client_with_a_challenge() {
    let Some(state) = common::state().await else {
        return;
    };
    let (client_id, _) = create_client(&state, &["authorization_code"]).await;
    let (status, headers, body) = post_form(
        &state,
        "/oauth/token",
        format!(
            "grant_type=authorization_code&code=nope&redirect_uri={}&client_id={client_id}\
             &client_secret=wrong&code_verifier={}",
            urlencoding::encode(REDIRECT_URI),
            "c".repeat(43),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], json!("invalid_client"), "{body}");
    assert!(
        headers.get(axum::http::header::WWW_AUTHENTICATE).is_some(),
        "a 401 must carry WWW-Authenticate"
    );
}

/// The registered grant list is enforced at the token endpoint as well.
#[tokio::test]
async fn an_unregistered_grant_type_is_refused() {
    let Some(state) = common::state().await else {
        return;
    };
    let (client_id, secret) = create_client(&state, &["authorization_code"]).await;
    let (status, _, body) = post_form(
        &state,
        "/oauth/token",
        format!(
            "grant_type=refresh_token&refresh_token=r&client_id={client_id}\
             &client_secret={secret}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], json!("unsupported_grant_type"), "{body}");
}

/// max_age: a session older than the window must re-authenticate before this
/// client gets a code — the protocol-shaped form of step-up.
#[tokio::test]
async fn an_older_than_max_age_session_is_forced_to_relogin() {
    let Some(state) = common::state().await else {
        return;
    };
    let (client_id, _) = create_client(&state, &["authorization_code"]).await;
    let user = common::create_user(&state.pool, "").await;
    let token = signet::auth::session::create_session(&state.pool, user, 1, None, None)
        .await
        .expect("session");
    // Backdate the session past a 60-second max_age window.
    let updated = sqlx::query(
        "UPDATE sessions SET created_at = NOW() - INTERVAL '1 hour' WHERE token_hash = $1",
    )
    .bind(signet::crypto::util::sha256_hex(&token))
    .execute(&state.pool)
    .await
    .expect("backdate session");
    eprintln!("backdate rows: {}", updated.rows_affected());
    let (dbg_created, dbg_exp): (
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as("SELECT created_at, expires_at FROM sessions WHERE token_hash = $1")
        .bind(signet::crypto::util::sha256_hex(&token))
        .fetch_one(&state.pool)
        .await
        .expect("read session");
    eprintln!("created={dbg_created:?} expires={dbg_exp:?}");
    let cookie = format!("{}={token}", signet::auth::session::SESSION_COOKIE);

    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={}&scope=openid&state=st-ma\
         &code_challenge={}&code_challenge_method=S256&max_age=60",
        urlencoding::encode(REDIRECT_URI),
        "d".repeat(43),
    );
    let (status, location) = get(&state, &uri, Some(&cookie)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("redirect");
    assert!(location.starts_with("/login"), "{location}");

    // The stale session was destroyed: re-using it cannot bypass the gate.
    let alive: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE token_hash = $1")
        .bind(signet::crypto::util::sha256_hex(&token))
        .fetch_one(&state.pool)
        .await
        .expect("count sessions");
    assert_eq!(alive, 0);

    common::delete_user(&state.pool, user).await;
}

/// A fresh session within max_age proceeds normally (to consent).
#[tokio::test]
async fn a_fresh_session_passes_max_age() {
    let Some(state) = common::state().await else {
        return;
    };
    let (client_id, _) = create_client(&state, &["authorization_code"]).await;
    let user = common::create_user(&state.pool, "").await;
    let token = signet::auth::session::create_session(&state.pool, user, 1, None, None)
        .await
        .expect("session");
    let cookie = format!("{}={token}", signet::auth::session::SESSION_COOKIE);

    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={}&scope=openid&state=st-f\
         &code_challenge={}&code_challenge_method=S256&max_age=3600",
        urlencoding::encode(REDIRECT_URI),
        "e".repeat(43),
    );
    let (status, location) = get(&state, &uri, Some(&cookie)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("redirect");
    assert!(location.starts_with("/consent"), "{location}");

    common::delete_user(&state.pool, user).await;
}

/// auth_time: the exchange carries the authentication time stored on the code,
/// read from the session at authorize time.
#[tokio::test]
async fn the_id_token_carries_auth_time_from_the_code() {
    let Some(state) = common::state().await else {
        return;
    };
    let (client_id, secret) = create_client(&state, &["authorization_code"]).await;
    let user = common::create_user(&state.pool, "").await;

    let verifier = "g".repeat(43);
    let code = signet::crypto::util::random_token(32);
    sqlx::query(
        r#"
        INSERT INTO auth_codes (id, code_hash, client_id, user_id, redirect_uri, scope,
                                code_challenge, nonce, expires_at, auth_time)
        VALUES ($1, $2, $3, $4, $5, 'openid', $6, '', NOW() + INTERVAL '5 minutes',
                NOW() - INTERVAL '2 hours')
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(signet::crypto::util::sha256_hex(&code))
    .bind(&client_id)
    .bind(user)
    .bind(REDIRECT_URI)
    .bind(signet::crypto::util::sha256_b64url(&verifier))
    .execute(&state.pool)
    .await
    .expect("insert the auth code");

    let (status, _, body) = post_form(
        &state,
        "/oauth/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={client_id}&client_secret={secret}&code_verifier={verifier}",
            urlencoding::encode(REDIRECT_URI),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let id_token = body["id_token"].as_str().expect("id token");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    let issuer = state.issuer();
    validation.set_issuer(&[issuer.as_str()]);
    validation.validate_aud = false;
    let data = jsonwebtoken::decode::<Value>(id_token, state.keys.load().decoding(), &validation)
        .expect("decode id token");
    let auth_time = data.claims["auth_time"].as_i64().expect("auth_time claim");
    let two_hours_ago = (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp();
    assert!(
        (auth_time - two_hours_ago).abs() < 5,
        "auth_time {auth_time} should be ~{two_hours_ago}"
    );

    common::delete_user(&state.pool, user).await;
}
