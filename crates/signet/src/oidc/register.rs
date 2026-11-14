use crate::crypto::util::{prefixed_token, sha256_hex};
use crate::developer::{normalize_scopes, normalize_uris};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use uuid::Uuid;

/// RFC 7591 — OAuth 2.0 Dynamic Client Registration.
///
/// Requires a single-use initial access token issued by an administrator via
/// `POST /api/v1/admin/clients/registration-tokens`.
#[derive(Debug, Deserialize)]
pub struct RegisterBody {
    pub redirect_uris: Vec<String>,
    #[serde(rename = "client_name")]
    pub client_name: Option<String>,
    #[allow(dead_code)]
    pub grant_types: Option<Vec<String>>,
    /// This service's native shape: a JSON array.
    pub scopes: Option<Vec<String>>,
    /// RFC 7591 §2 uses the space-separated `scope` string, not an array.
    /// Accepting it keeps conformant clients working without a translation
    /// layer; `scopes` wins when both are present.
    pub scope: Option<String>,
    #[serde(rename = "initial_access_token")]
    pub initial_access_token: Option<String>,
}

pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RegisterBody>,
) -> AppResult<impl IntoResponse> {
    let token = bearer_token(&headers)
        .or_else(|| body.initial_access_token.clone())
        .ok_or_else(|| AppError::unauthorized("missing initial access token"))?;
    let token_hash = sha256_hex(&token);

    // Single-use: the DELETE ... RETURNING is the consume claim. A concurrent
    // registration presenting the same token finds nothing left to delete and
    // is refused, instead of two clients registering on one token.
    let consumed = sqlx::query_scalar::<_, Uuid>(
        "DELETE FROM registration_access_tokens \
         WHERE token_hash = $1 AND expires_at > NOW() RETURNING id",
    )
    .bind(&token_hash)
    .fetch_optional(&state.pool)
    .await?;
    if consumed.is_none() {
        return Err(AppError::unauthorized(
            "invalid or expired registration token",
        ));
    }

    let redirect_uris = normalize_uris(&body.redirect_uris)?;
    let requested_scopes = body.scopes.or_else(|| {
        body.scope
            .map(|raw| raw.split_whitespace().map(str::to_string).collect())
    });
    let scopes = normalize_scopes(
        requested_scopes.unwrap_or_else(|| vec!["openid".into(), "profile".into(), "email".into()]),
    )?;

    let client_name = body
        .client_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(name) = client_name {
        if name.chars().count() > 200 {
            return Err(AppError::bad_request(
                "client_name must be at most 200 characters",
            ));
        }
    }

    let client_id = prefixed_token("sgn_cl", 12);
    let secret = prefixed_token("sgn_cs", 32);
    let secret_hash = crate::auth::client_secret::digest(&state.client_secret_key, &secret);
    let id = Uuid::new_v4();
    let issued_at = chrono::Utc::now().timestamp();

    sqlx::query(
        r#"
        INSERT INTO client_apps (
            id, client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
            grant_types, pkce_required, scopes, enabled,
            ip_allowlist_enabled, allowed_cidrs, client_name
        )
        VALUES (
            $1, $2, $3, $4, ARRAY[]::text[],
            ARRAY['authorization_code', 'refresh_token'],
            TRUE, $5, TRUE, FALSE, ARRAY[]::text[], $6
        )
        "#,
    )
    .bind(id)
    .bind(&client_id)
    .bind(secret_hash)
    .bind(&redirect_uris)
    .bind(&scopes)
    .bind(client_name.unwrap_or(""))
    .execute(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("client_apps_client_id_key") => {
            AppError::bad_request("client_id collision, retry")
        }
        other => AppError::from(other),
    })?;

    crate::audit::record(
        &state,
        crate::audit::AuditEvent {
            actor: None,
            action: "client.register",
            resource_type: "client",
            resource_id: Some(client_id.clone()),
            detail: json!({
                "redirect_uris": redirect_uris,
                "client_name": body.client_name,
                "via": "rfc7591",
            }),
            ip: crate::http::extract::client_ip(&headers, Some(addr)),
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({
        "client_id": client_id,
        "client_secret": secret,
        "client_id_issued_at": issued_at,
        "client_secret_expires_at": 0,
        // No `registration_access_token` / `registration_client_uri`: RFC 7591
        // §5.1/§5.3 make those a promise of a client-management API, and there
        // is no `GET/PUT /oauth/register/{client_id}` here. Advertising them
        // sent conformant clients to a 404 with a token that could never
        // authenticate. Managing a registered client is a dashboard operation.
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
    })))
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let v = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    v.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

// Redirect-URI and scope rules live in `crate::developer::{normalize_uris,
// normalize_scopes}` — the one shared copy across the admin surface, RFC 7591
// registration and self-service registration.
