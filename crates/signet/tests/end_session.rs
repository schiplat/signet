//! RP-initiated logout: the CSRF boundary and the redirect allow-list.
//!
//! `GET` is accepted only with a signed `id_token_hint` (a top-level GET
//! carries the Lax cookie, so a link alone must not be enough); `POST` needs
//! none, because a cross-site form POST carries no cookie. The hint is also
//! what authorizes a `post_logout_redirect_uri`, and its `sub` must match the
//! session being ended.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

const CLIENT_ID: &str = "logout-client";
const POST_LOGOUT: &str = "http://localhost/signed-out";

async fn create_client(state: &signet::state::AppState) {
    sqlx::query(
        r#"
        INSERT INTO client_apps
            (id, client_id, client_secret_hash, redirect_uris,
             post_logout_redirect_uris, ip_allowlist_enabled)
        VALUES ($1, $2, 'test', ARRAY['http://localhost/cb'], ARRAY[$3], FALSE)
        ON CONFLICT (client_id) DO NOTHING
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(CLIENT_ID)
    .bind(POST_LOGOUT)
    .execute(&state.pool)
    .await
    .expect("insert the logout client");
}

/// An id_token this issuer signed, for `sub`.
///
/// Carries `at_hash`, which is what marks it as an id_token: an access token is
/// signed by the same key with the same issuer, so the shape is the only thing
/// that distinguishes them.
fn id_token(state: &signet::state::AppState, sub: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    state
        .keys
        .load()
        .encode(&json!({
            "iss": state.issuer(),
            "sub": sub,
            "aud": CLIENT_ID,
            "exp": now + 300,
            "iat": now,
            "at_hash": "abc123",
        }))
        .expect("sign an id_token")
}

/// An access token is not a logout hint, even though this issuer signed it.
#[tokio::test]
async fn an_access_token_is_not_accepted_as_a_hint() {
    let Some(state) = common::state().await else {
        return;
    };
    let user = common::create_user(&state.pool, "").await;
    let (cookie, _) = session_cookie_for(&state, user).await;
    let sub: String = sqlx::query_scalar("SELECT sub FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&state.pool)
        .await
        .expect("read sub");

    let now = chrono::Utc::now().timestamp();
    let access = state
        .keys
        .load()
        .encode(&json!({
            "iss": state.issuer(),
            "sub": sub,
            "aud": CLIENT_ID,
            "exp": now + 3600,
            "iat": now,
            "scope": "openid",
            "token_use": "access",
        }))
        .expect("sign an access token");
    let uri = format!(
        "/oauth/end_session?id_token_hint={}",
        urlencoding::encode(&access)
    );
    let (status, _) = call(&state, "GET", &uri, Some(&cookie), None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an access token must not drive a logout"
    );
    assert_eq!(
        sessions_for(&state, user).await,
        1,
        "the session must survive the refused hint"
    );

    common::delete_user(&state.pool, user).await;
}

async fn session_cookie_for(state: &signet::state::AppState, user: Uuid) -> (String, String) {
    let token = signet::auth::session::create_session(&state.pool, user, 1, None, None)
        .await
        .expect("create a session");
    (
        format!("{}={token}", signet::auth::session::SESSION_COOKIE),
        token,
    )
}

async fn sessions_for(state: &signet::state::AppState, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user)
        .fetch_one(&state.pool)
        .await
        .expect("count sessions")
}

async fn call(
    state: &signet::state::AppState,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    form: Option<&str>,
) -> (StatusCode, Option<String>) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    let body = match form {
        Some(form) => {
            builder = builder.header("content-type", "application/x-www-form-urlencoded");
            Body::from(form.to_string())
        }
        None => Body::empty(),
    };
    let response = signet::oidc::router()
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
    (status, location)
}

#[tokio::test]
async fn get_without_a_hint_is_refused() {
    let Some(state) = common::state().await else {
        return;
    };
    let (status, _) = call(&state, "GET", "/oauth/end_session", None, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call(
        &state,
        "GET",
        "/oauth/end_session?id_token_hint=not-a-jwt",
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a forged hint must not pass"
    );
}

#[tokio::test]
async fn a_valid_hint_ends_the_session_and_honors_the_allow_list() {
    let Some(state) = common::state().await else {
        return;
    };
    create_client(&state).await;
    let user = common::create_user(&state.pool, "").await;
    let sub: String = sqlx::query_scalar("SELECT sub FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&state.pool)
        .await
        .expect("read sub");
    let (cookie, _) = session_cookie_for(&state, user).await;

    let hint = id_token(&state, &sub);
    let uri = format!(
        "/oauth/end_session?id_token_hint={}&post_logout_redirect_uri={}&state=st-1",
        urlencoding::encode(&hint),
        urlencoding::encode(POST_LOGOUT),
    );
    let (status, location) = call(&state, "GET", &uri, Some(&cookie), None).await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT, "{location:?}");
    let location = location.expect("a redirect");
    assert!(location.starts_with(POST_LOGOUT), "{location}");
    assert!(location.contains("state=st-1"), "{location}");
    assert_eq!(sessions_for(&state, user).await, 0, "the session is gone");

    common::delete_user(&state.pool, user).await;
}

#[tokio::test]
async fn a_hint_for_another_account_cannot_end_this_session() {
    let Some(state) = common::state().await else {
        return;
    };
    let victim = common::create_user(&state.pool, "").await;
    let (cookie, _) = session_cookie_for(&state, victim).await;
    let hint = id_token(&state, "somebody-else");

    let uri = format!(
        "/oauth/end_session?id_token_hint={}",
        urlencoding::encode(&hint)
    );
    let (status, _) = call(&state, "GET", &uri, Some(&cookie), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        sessions_for(&state, victim).await,
        1,
        "a mismatched hint must not log the session out"
    );

    common::delete_user(&state.pool, victim).await;
}

#[tokio::test]
async fn post_needs_no_hint_and_clears_the_session() {
    let Some(state) = common::state().await else {
        return;
    };
    let user = common::create_user(&state.pool, "").await;
    let (cookie, _) = session_cookie_for(&state, user).await;

    let (status, location) = call(
        &state,
        "POST",
        "/oauth/end_session",
        Some(&cookie),
        Some(""),
    )
    .await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(location.as_deref(), Some("/"));
    assert_eq!(sessions_for(&state, user).await, 0);

    common::delete_user(&state.pool, user).await;
}

/// A redirect URI that is not on the client's allow-list is ignored even when
/// the hint is genuine: the response falls back to the index, not to the URL.
#[tokio::test]
async fn an_unlisted_post_logout_uri_falls_back_to_the_index() {
    let Some(state) = common::state().await else {
        return;
    };
    create_client(&state).await;
    let user = common::create_user(&state.pool, "").await;
    let sub: String = sqlx::query_scalar("SELECT sub FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&state.pool)
        .await
        .expect("read sub");
    let (cookie, _) = session_cookie_for(&state, user).await;
    let hint = id_token(&state, &sub);

    let uri = format!(
        "/oauth/end_session?id_token_hint={}&post_logout_redirect_uri={}",
        urlencoding::encode(&hint),
        urlencoding::encode("http://attacker.example/out"),
    );
    let (status, location) = call(&state, "GET", &uri, Some(&cookie), None).await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(location.as_deref(), Some("/"));
    assert_eq!(sessions_for(&state, user).await, 0);

    common::delete_user(&state.pool, user).await;
}
