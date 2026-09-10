use crate::client_ip::check_client_source_ip;
use crate::crypto_util::{random_token, sha256_b64url, sha256_hex};
use crate::error::{AppError, AppResult};
use crate::http_util::client_ip;
use crate::models::{ClientApp, User};
use crate::password::verify_password;
use crate::state::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Form;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone_number: Option<String>,
}

#[derive(Debug, Serialize)]
struct AccessTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    scope: String,
    token_use: String,
}

pub async fn token(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> AppResult<impl IntoResponse> {
    let (client_id, client_secret) = resolve_client_credentials(&headers, &form)?;
    let client = load_client(&state, &client_id).await?;
    if !verify_password(&client_secret, &client.client_secret_hash)? {
        return Err(AppError::unauthorized("invalid client credentials"));
    }
    let source = client_ip(&headers, Some(addr));
    check_client_source_ip(
        client.ip_allowlist_enabled,
        &client.allowed_cidrs,
        source.as_deref(),
    )?;

    let body = match form.grant_type.as_str() {
        "authorization_code" => issue_from_code(&state, &client, &form).await?,
        "refresh_token" => issue_from_refresh(&state, &client, &form).await?,
        _ => return Err(AppError::bad_request("unsupported grant_type")),
    };
    Ok((StatusCode::OK, axum::Json(body)))
}

fn resolve_client_credentials(
    headers: &HeaderMap,
    form: &TokenForm,
) -> AppResult<(String, String)> {
    resolve_client_credentials_parts(
        headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    )
}

pub(crate) fn resolve_client_credentials_parts(
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> AppResult<(String, String)> {
    if let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) {
        let raw = auth.to_str().unwrap_or_default();
        if let Some(b64) = raw.strip_prefix("Basic ") {
            use base64::Engine;
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) {
                if let Ok(s) = String::from_utf8(decoded) {
                    if let Some((id, secret)) = s.split_once(':') {
                        return Ok((id.to_string(), secret.to_string()));
                    }
                }
            }
        }
    }

    let id = form_client_id.ok_or_else(|| AppError::unauthorized("missing client_id"))?;
    let secret =
        form_client_secret.ok_or_else(|| AppError::unauthorized("missing client_secret"))?;
    Ok((id.to_string(), secret.to_string()))
}

pub(crate) async fn load_client(state: &AppState, client_id: &str) -> AppResult<ClientApp> {
    sqlx::query_as::<_, ClientApp>(
        r#"
        SELECT id, client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
               grant_types, pkce_required, scopes, enabled,
               ip_allowlist_enabled, allowed_cidrs
        FROM client_apps
        WHERE client_id = $1 AND enabled = TRUE
        "#,
    )
    .bind(client_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("unknown client"))
}

async fn issue_from_code(
    state: &AppState,
    client: &ClientApp,
    form: &TokenForm,
) -> AppResult<serde_json::Value> {
    let code = form
        .code
        .as_deref()
        .ok_or_else(|| AppError::bad_request("missing code"))?;
    let redirect_uri = form
        .redirect_uri
        .as_deref()
        .ok_or_else(|| AppError::bad_request("missing redirect_uri"))?;
    let code_verifier = form
        .code_verifier
        .as_deref()
        .ok_or_else(|| AppError::bad_request("missing code_verifier"))?;

    let code_hash = sha256_hex(code);
    let row = sqlx::query_as::<_, AuthCodeRow>(
        r#"
        SELECT id, client_id, user_id, redirect_uri, scope, code_challenge, nonce, expires_at, consumed_at
        FROM auth_codes
        WHERE code_hash = $1
        "#,
    )
    .bind(code_hash)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::bad_request("invalid code"))?;

    if row.consumed_at.is_some() {
        return Err(AppError::bad_request("code already used"));
    }
    if row.expires_at < Utc::now() {
        return Err(AppError::bad_request("code expired"));
    }
    if row.client_id != client.client_id {
        return Err(AppError::bad_request("client mismatch"));
    }
    if row.redirect_uri != redirect_uri {
        return Err(AppError::bad_request("redirect_uri mismatch"));
    }

    let expected = sha256_b64url(code_verifier);
    if expected != row.code_challenge {
        return Err(AppError::bad_request("invalid code_verifier"));
    }

    sqlx::query("UPDATE auth_codes SET consumed_at = NOW() WHERE id = $1")
        .bind(row.id)
        .execute(&state.pool)
        .await?;

    let user = load_user(state, row.user_id).await?;
    build_token_response(state, client, &user, &row.scope, row.nonce).await
}

async fn issue_from_refresh(
    state: &AppState,
    client: &ClientApp,
    form: &TokenForm,
) -> AppResult<serde_json::Value> {
    let refresh = form
        .refresh_token
        .as_deref()
        .ok_or_else(|| AppError::bad_request("missing refresh_token"))?;
    let token_hash = sha256_hex(refresh);

    let row = sqlx::query_as::<_, RefreshRow>(
        r#"
        SELECT id, client_id, user_id, scope, expires_at, revoked_at
        FROM refresh_tokens
        WHERE token_hash = $1
        "#,
    )
    .bind(token_hash)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::bad_request("invalid refresh_token"))?;

    if row.revoked_at.is_some() || row.expires_at < Utc::now() {
        return Err(AppError::bad_request("refresh_token expired or revoked"));
    }
    if row.client_id != client.client_id {
        return Err(AppError::bad_request("client mismatch"));
    }

    // rotate
    sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1")
        .bind(row.id)
        .execute(&state.pool)
        .await?;

    let user = load_user(state, row.user_id).await?;
    build_token_response(state, client, &user, &row.scope, None).await
}

async fn load_user(state: &AppState, user_id: Uuid) -> AppResult<User> {
    sqlx::query_as::<_, User>(
        r#"
        SELECT id, sub, email, username, display_name, password_hash, status, role,
               mfa_required, must_change_password, totp_enabled, totp_secret, groups, phone,
               provisioned_via, created_at, updated_at
        FROM users WHERE id = $1 AND status = 'active'
        "#,
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("user inactive"))
}

async fn build_token_response(
    state: &AppState,
    client: &ClientApp,
    user: &User,
    scope: &str,
    nonce: Option<String>,
) -> AppResult<serde_json::Value> {
    let now = Utc::now();
    let access_exp = now + Duration::seconds(state.config.access_token_ttl_secs);
    let id_exp = now + Duration::seconds(state.config.id_token_ttl_secs);

    let access_claims = AccessTokenClaims {
        iss: state.config.issuer.clone(),
        sub: user.sub.clone(),
        aud: client.client_id.clone(),
        exp: access_exp.timestamp(),
        iat: now.timestamp(),
        scope: scope.to_string(),
        token_use: "access".into(),
    };
    let access_token = state.keys.encode(&access_claims)?;

    let id_claims = IdTokenClaims {
        iss: state.config.issuer.clone(),
        sub: user.sub.clone(),
        aud: client.client_id.clone(),
        exp: id_exp.timestamp(),
        iat: now.timestamp(),
        nonce,
        email: crate::oidc::scope_contains(scope, "email").then(|| user.email.clone()),
        name: crate::oidc::scope_contains(scope, "profile").then(|| user.display_name.clone()),
        preferred_username: crate::oidc::scope_contains(scope, "profile")
            .then(|| user.username.clone().unwrap_or_else(|| user.email.clone())),
        groups: crate::oidc::scope_contains(scope, "groups").then(|| user.groups.clone()),
        phone_number: crate::oidc::scope_contains(scope, "phone")
            .then(|| user.phone.clone())
            .flatten(),
    };
    let id_token = state.keys.encode(&id_claims)?;

    let refresh = random_token(32);
    let refresh_hash = sha256_hex(&refresh);
    let refresh_exp = now + Duration::days(state.config.refresh_token_ttl_days);
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (id, token_hash, client_id, user_id, scope, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(refresh_hash)
    .bind(&client.client_id)
    .bind(user.id)
    .bind(scope)
    .bind(refresh_exp)
    .execute(&state.pool)
    .await?;

    crate::metrics::inc_tokens_issued();

    Ok(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": state.config.access_token_ttl_secs,
        "refresh_token": refresh,
        "id_token": id_token,
        "scope": scope,
    }))
}

#[derive(Debug, sqlx::FromRow)]
struct AuthCodeRow {
    id: Uuid,
    client_id: String,
    user_id: Uuid,
    redirect_uri: String,
    scope: String,
    code_challenge: String,
    nonce: Option<String>,
    expires_at: chrono::DateTime<Utc>,
    consumed_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, sqlx::FromRow)]
struct RefreshRow {
    id: Uuid,
    client_id: String,
    user_id: Uuid,
    scope: String,
    expires_at: chrono::DateTime<Utc>,
    revoked_at: Option<chrono::DateTime<Utc>>,
}
