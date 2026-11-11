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
use serde_json::json;
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

async fn get(state: &signet::state::AppState, uri: &str) -> (StatusCode, Option<String>) {
    let response = router(state)
        .oneshot(
            Request::builder()
                .uri(uri)
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
    let (status, location) = get(&state, &uri).await;
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
    let (status, location) = get(&state, &uri).await;
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
    let (status, location) = get(&state, &uri).await;
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
