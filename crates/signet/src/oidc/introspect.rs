//! RFC 7662 — Token Introspection.
//!
//! A resource server that does not parse JWTs locally asks this endpoint
//! "is this token still good?" and gets the canonical answer: `active` is
//! false the moment the signature fails, the token expires, the owning user is
//! disabled or deleted, or the client was disabled. That last part is what a
//! locally-verified JWT cannot tell you — revocation-awareness without
//! waiting for expiry.
//!
//! Authenticated like `/oauth/token` (client secret, Basic or form); any
//! enabled registered client may introspect.

use crate::error::AppResult;
use crate::oidc::token::{load_client, resolve_client_credentials_parts};
use crate::state::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Form;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

#[derive(Debug, Deserialize)]
pub struct IntrospectForm {
    pub token: String,
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

pub async fn introspect(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<IntrospectForm>,
) -> AppResult<axum::response::Response> {
    let (client_id, client_secret) = resolve_client_credentials_parts(
        &headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    )?;
    let caller = load_client(&state, &client_id).await?;
    if !crate::auth::client_secret::verify(
        &state,
        &caller.client_id,
        &client_secret,
        &caller.client_secret_hash,
    )
    .await?
    {
        return Err(crate::error::AppError::oauth_unauthorized(
            "invalid_client",
            "invalid client credentials",
        ));
    }
    let source = crate::http::extract::client_ip(&headers, Some(addr));
    crate::http::source_ip::check_client_source_ip(
        caller.ip_allowlist_enabled,
        &caller.allowed_cidrs,
        source.as_deref(),
    )?;

    // RFC 7662 §2.2: the error cases below are not errors — an unknown or dead
    // token is simply `{ "active": false }`.
    let inactive = || axum::Json(json!({ "active": false })).into_response();

    let claims = match crate::oidc::decode_access_token(&state, &form.token) {
        Ok(claims) => claims,
        Err(_) => return Ok(inactive()),
    };
    // Only an access token is introspectable. Everything else this issuer signs
    // is a *different* credential with a different audience contract — an
    // id_token belongs to the RP's session, a logout hint authorizes a logout —
    // and a resource server must not accept one as an API token. Signature and
    // issuer alone cannot say which kind arrived: they are identical on every
    // token this instance mints, and an id_token carries no `token_use` at all.
    // So the discriminator is required, not optional: absence is inactive.
    if claims.token_use.as_deref() != Some("access") {
        return Ok(inactive());
    }
    if claims.exp < chrono::Utc::now().timestamp() {
        return Ok(inactive());
    }

    // A user token's subject must still exist and be active — the check local
    // JWT verification skips. A client-credentials token (sub == aud, both the
    // client id) has no user row; its client row was already checked when the
    // caller authenticated, and `load_client` refuses a disabled client.
    if claims.sub != claims.aud {
        let active: Option<String> = sqlx::query_scalar("SELECT status FROM users WHERE sub = $1")
            .bind(&claims.sub)
            .fetch_optional(&state.pool)
            .await?;
        if active.as_deref() != Some("active") {
            return Ok(inactive());
        }
    }

    Ok(axum::Json(json!({
        "active": true,
        "scope": claims.scope,
        "client_id": claims.aud,
        "token_use": claims.token_use,
        "sub": claims.sub,
        "exp": claims.exp,
        "iat": claims.iat,
        "iss": claims.iss,
    }))
    .into_response())
}
