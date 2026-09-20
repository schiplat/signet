use crate::auth::session::{
    cookie_value, destroy_session, user_from_session_token, SESSION_COOKIE,
};
use crate::crypto::util::{random_token, sha256_hex};
use crate::error::{AppError, AppResult};
use crate::http::extract::client_ip;
use crate::http::source_ip::check_client_source_ip;
use crate::models::ClientApp;
use crate::state::AppState;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{Duration, Utc};
use serde::Deserialize;
use std::net::SocketAddr;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

pub async fn authorize(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<AuthorizeQuery>,
) -> AppResult<Response> {
    // Static validation (no client lookup yet — avoids leaking client metadata
    // to unauthenticated callers).
    let response_type = q
        .response_type
        .as_deref()
        .ok_or_else(|| AppError::bad_request("missing response_type"))?;
    if response_type != "code" {
        return Err(AppError::bad_request("unsupported response_type"));
    }

    let client_id = q
        .client_id
        .as_deref()
        .ok_or_else(|| AppError::bad_request("missing client_id"))?;
    let redirect_uri = q
        .redirect_uri
        .as_deref()
        .ok_or_else(|| AppError::bad_request("missing redirect_uri"))?;
    let scope = crate::oidc::normalize_scope(q.scope.as_deref().unwrap_or("openid"));
    if !scope.split_whitespace().any(|s| s == "openid") {
        return Err(AppError::bad_request("scope must include openid"));
    }
    // state is REQUIRED (OIDC Core) — mitigates login CSRF.
    let state_val = q
        .state
        .as_deref()
        .ok_or_else(|| AppError::bad_request("missing state"))?;
    let code_challenge = q
        .code_challenge
        .as_deref()
        .ok_or_else(|| AppError::bad_request("missing code_challenge"))?;
    let method = q.code_challenge_method.as_deref().unwrap_or("plain");
    if method != "S256" {
        return Err(AppError::bad_request("code_challenge_method must be S256"));
    }

    let prompt = q.prompt.as_deref().unwrap_or("");
    let has_prompt = |p: &str| prompt.split_whitespace().any(|s| s == p);

    // Authenticate first (no client lookup until the caller is authenticated).
    let token = cookie_value(&headers, SESSION_COOKIE);
    let user = match &token {
        Some(t) => user_from_session_token(&state.pool, t).await?,
        None => None,
    };
    let Some(user) = user else {
        if has_prompt("none") {
            return Err(AppError::bad_request("login_required"));
        }
        return Ok(redirect_to_login(&q, q.prompt.as_deref()));
    };

    let client = sqlx::query_as::<_, ClientApp>(
        r#"
        SELECT id, client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
               grant_types, pkce_required, scopes, enabled,
               ip_allowlist_enabled, allowed_cidrs
        FROM client_apps
        WHERE client_id = $1
        "#,
    )
    .bind(client_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::bad_request("unknown client_id"))?;

    if !client.enabled {
        return Err(AppError::bad_request("client disabled"));
    }
    if !client.redirect_uris.iter().any(|u| u == redirect_uri) {
        return Err(AppError::bad_request("redirect_uri not allowed"));
    }
    crate::oidc::validate_client_scope(&scope, &client.scopes)?;
    let source = client_ip(&headers, Some(addr));
    check_client_source_ip(
        client.ip_allowlist_enabled,
        &client.allowed_cidrs,
        source.as_deref(),
    )?;

    // prompt=login forces re-authentication: clear the session so the user must
    // sign in again, then redirect to login WITHOUT the login prompt (so it
    // isn't re-triggered after authentication).
    if has_prompt("login") {
        if let Some(t) = &token {
            destroy_session(&state.pool, t).await?;
        }
        return Ok(redirect_to_login(
            &q,
            prompt_without(prompt, "login").as_deref(),
        ));
    }

    // Consent gate: skip only if the user has already granted every requested
    // scope for this client (partial grants force a re-consent).
    let granted: Option<String> = sqlx::query_scalar(
        "SELECT scopes FROM oauth_consents WHERE user_id = $1 AND client_id = $2",
    )
    .bind(user.id)
    .bind(client_id)
    .fetch_optional(&state.pool)
    .await?;
    let fully_consented = granted
        .as_deref()
        .is_some_and(|g| crate::oidc::scope_covered(g, &scope));
    if !fully_consented || has_prompt("consent") {
        if has_prompt("none") {
            return Err(AppError::bad_request("consent_required"));
        }
        return Ok(redirect_to_consent(&q, &client.scopes, &scope));
    }

    let code = random_token(32);
    let code_hash = sha256_hex(&code);
    let expires_at = Utc::now() + Duration::seconds(state.config.auth_code_ttl_secs);

    sqlx::query(
        r#"
        INSERT INTO auth_codes (
            id, code_hash, client_id, user_id, redirect_uri, scope,
            code_challenge, code_challenge_method, nonce, expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'S256', $8, $9)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(code_hash)
    .bind(client_id)
    .bind(user.id)
    .bind(redirect_uri)
    .bind(&scope)
    .bind(code_challenge)
    .bind(&q.nonce)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;

    let mut url =
        url::Url::parse(redirect_uri).map_err(|_| AppError::bad_request("bad redirect_uri"))?;
    url.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", state_val);

    Ok(Redirect::to(url.as_str()).into_response())
}

fn redirect_to_login(q: &AuthorizeQuery, prompt: Option<&str>) -> Response {
    let scope = crate::oidc::normalize_scope(q.scope.as_deref().unwrap_or("openid"));
    let return_to = format!(
        "/oauth/authorize?{}",
        authorize_query_string(q, prompt, &scope)
    );
    let loc = format!("/login?return_to={}", urlencoding::encode(&return_to));
    (StatusCode::SEE_OTHER, [(axum::http::header::LOCATION, loc)]).into_response()
}

fn redirect_to_consent(q: &AuthorizeQuery, allowed: &[String], scope: &str) -> Response {
    // Optional scopes are those the client is allowed to have but did not
    // request this time — surfaced as opt-in checkboxes (GitHub-style).
    let optional: Vec<&str> = allowed
        .iter()
        .map(String::as_str)
        .filter(|s| !crate::oidc::scope_contains(scope, s))
        .collect();
    let mut loc = format!(
        "/consent?{}",
        authorize_query_string(q, q.prompt.as_deref(), scope)
    );
    if !optional.is_empty() {
        loc.push_str("&optional_scopes=");
        loc.push_str(&urlencoding::encode(&optional.join(" ")));
    }
    (StatusCode::SEE_OTHER, [(axum::http::header::LOCATION, loc)]).into_response()
}

fn prompt_without(prompt: &str, removed: &str) -> Option<String> {
    let remaining: Vec<&str> = prompt
        .split_whitespace()
        .filter(|s| *s != removed)
        .collect();
    if remaining.is_empty() {
        None
    } else {
        Some(remaining.join(" "))
    }
}

fn authorize_query_string(q: &AuthorizeQuery, prompt: Option<&str>, scope: &str) -> String {
    let mut parts = Vec::new();
    if let Some(v) = &q.response_type {
        parts.push(format!("response_type={}", urlencoding::encode(v)));
    }
    if let Some(v) = &q.client_id {
        parts.push(format!("client_id={}", urlencoding::encode(v)));
    }
    if let Some(v) = &q.redirect_uri {
        parts.push(format!("redirect_uri={}", urlencoding::encode(v)));
    }
    parts.push(format!("scope={}", urlencoding::encode(scope)));
    if let Some(v) = &q.state {
        parts.push(format!("state={}", urlencoding::encode(v)));
    }
    if let Some(v) = &q.nonce {
        parts.push(format!("nonce={}", urlencoding::encode(v)));
    }
    if let Some(v) = prompt {
        parts.push(format!("prompt={}", urlencoding::encode(v)));
    }
    if let Some(v) = &q.code_challenge {
        parts.push(format!("code_challenge={}", urlencoding::encode(v)));
    }
    if let Some(v) = &q.code_challenge_method {
        parts.push(format!("code_challenge_method={}", urlencoding::encode(v)));
    }
    parts.join("&")
}
