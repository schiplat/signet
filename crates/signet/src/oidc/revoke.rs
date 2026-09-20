use crate::auth::password::verify_password;
use crate::crypto::util::sha256_hex;
use crate::error::AppResult;
use crate::oidc::token::{load_client, resolve_client_credentials_parts};
use crate::state::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Form;
use serde::Deserialize;

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
    if !verify_password(&client_secret, &client.client_secret_hash)? {
        return Err(crate::error::AppError::unauthorized(
            "invalid client credentials",
        ));
    }

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
