use crate::crypto::util::sha256_hex;
use crate::error::AppResult;
use crate::http::extract::client_ip;
use crate::http::source_ip::check_client_source_ip;
use crate::oidc::token::{load_client, resolve_client_credentials_parts};
use crate::state::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Form;
use serde::Deserialize;
use std::net::SocketAddr;

/// RFC 7009 — Token Revocation.
///
/// Revokes a refresh token. Access tokens are short-lived stateless JWTs and are
/// not stored, so they cannot be revoked server-side (documented limitation).
#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub token: String,
    #[serde(rename = "token_type_hint")]
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

pub async fn revoke(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<RevokeForm>,
) -> AppResult<impl IntoResponse> {
    // RFC 7009 requires the client to authenticate.
    let (client_id, client_secret) = resolve_client_credentials_parts(
        &headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    )?;
    let client = load_client(&state, &client_id).await?;
    if !crate::auth::client_secret::verify(
        &state,
        &client.client_id,
        &client_secret,
        &client.client_secret_hash,
    )
    .await?
    {
        return Err(crate::error::AppError::oauth_unauthorized(
            "invalid_client",
            "invalid client credentials",
        ));
    }

    // Same source restriction as authorize and token: an IP allowlist bounds
    // where the client's credentials may be used, and revocation is a use.
    let source = client_ip(&headers, Some(addr));
    check_client_source_ip(
        client.ip_allowlist_enabled,
        &client.allowed_cidrs,
        source.as_deref(),
    )?;

    let token_hash = sha256_hex(&form.token);
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = NOW() \
         WHERE token_hash = $1 AND client_id = $2 AND revoked_at IS NULL",
    )
    .bind(token_hash)
    .bind(&client.client_id)
    .execute(&state.pool)
    .await?;

    // RFC 7009 §2.2: respond 200 OK even if the token was invalid/unknown.
    Ok(StatusCode::OK)
}
