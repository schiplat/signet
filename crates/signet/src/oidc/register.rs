use crate::crypto::util::{random_token, sha256_hex};
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
    pub scopes: Option<Vec<String>>,
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
    let scopes = normalize_scopes(
        body.scopes
            .unwrap_or_else(|| vec!["openid".into(), "profile".into(), "email".into()]),
    )?;

    let client_id = format!("cl_{}", random_token(12));
    let secret = random_token(32);
    let secret_hash = crate::auth::client_secret::digest(&state.client_secret_key, &secret);
    let id = Uuid::new_v4();
    let issued_at = chrono::Utc::now().timestamp();

    sqlx::query(
        r#"
        INSERT INTO client_apps (
            id, client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
            grant_types, pkce_required, scopes, enabled,
            ip_allowlist_enabled, allowed_cidrs
        )
        VALUES (
            $1, $2, $3, $4, ARRAY[]::text[],
            ARRAY['authorization_code', 'refresh_token'],
            TRUE, $5, TRUE, FALSE, ARRAY[]::text[]
        )
        "#,
    )
    .bind(id)
    .bind(&client_id)
    .bind(secret_hash)
    .bind(&redirect_uris)
    .bind(&scopes)
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

fn normalize_uris(uris: &[String]) -> AppResult<Vec<String>> {
    let mut out = Vec::new();
    for u in uris {
        let t = u.trim();
        if t.is_empty() {
            continue;
        }
        if !(t.starts_with("http://") || t.starts_with("https://")) {
            return Err(AppError::bad_request(format!(
                "redirect_uri must be http(s): {t}"
            )));
        }
        // RFC 6749 §3.1.2: a registered redirect URI must not carry a fragment.
        // The exact-match comparison at authorize makes it harmless today, but
        // accepting one stores a value no conformant client will ever send.
        if t.contains('#') {
            return Err(AppError::bad_request(format!(
                "redirect_uri must not contain a fragment: {t}"
            )));
        }
        out.push(t.to_string());
    }
    if out.is_empty() {
        return Err(AppError::bad_request("at least one redirect_uri required"));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn normalize_scopes(scopes: Vec<String>) -> AppResult<Vec<String>> {
    let mut out: Vec<String> = scopes
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    out.sort();
    out.dedup();
    if !out.iter().any(|s| s == "openid") {
        return Err(AppError::bad_request("scopes must include openid"));
    }
    Ok(out)
}
