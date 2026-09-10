use crate::admin::{require_admin_user, require_staff_user};
use crate::audit::{record, AuditEvent};
use crate::client_ip::normalize_cidrs;
use crate::crypto_util::random_token;
use crate::error::{AppError, AppResult};
use crate::password::hash_password;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

const CLIENT_RETURNING: &str = r#"
    id, client_id, redirect_uris, post_logout_redirect_uris,
    grant_types, pkce_required, scopes, enabled,
    ip_allowlist_enabled, allowed_cidrs, created_at, updated_at
"#;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/clients", get(list_clients).post(create_client))
        .route(
            "/admin/clients/{id}",
            put(update_client).delete(delete_client),
        )
        .route("/admin/clients/{id}/disable", post(disable_client))
        .route("/admin/clients/{id}/enable", post(enable_client))
        .route("/admin/clients/{id}/rotate-secret", post(rotate_secret))
        .route(
            "/admin/clients/registration-tokens",
            post(create_registration_token),
        )
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct AdminClient {
    pub id: Uuid,
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub pkce_required: bool,
    pub scopes: Vec<String>,
    pub enabled: bool,
    pub ip_allowlist_enabled: bool,
    pub allowed_cidrs: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct ClientCreated {
    client: AdminClient,
    client_secret: String,
}

#[derive(Debug, Deserialize)]
struct CreateClientBody {
    client_id: String,
    client_secret: Option<String>,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Option<Vec<String>>,
    pkce_required: Option<bool>,
    scopes: Option<Vec<String>>,
    /// Default true (minimum privilege).
    ip_allowlist_enabled: Option<bool>,
    allowed_cidrs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct UpdateClientBody {
    redirect_uris: Option<Vec<String>>,
    post_logout_redirect_uris: Option<Vec<String>>,
    pkce_required: Option<bool>,
    scopes: Option<Vec<String>>,
    ip_allowlist_enabled: Option<bool>,
    allowed_cidrs: Option<Vec<String>>,
}

async fn list_clients(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<AdminClient>>> {
    require_staff_user(&state, &headers).await?;
    let rows = sqlx::query_as::<_, AdminClient>(&format!(
        "SELECT {CLIENT_RETURNING} FROM client_apps ORDER BY created_at DESC"
    ))
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

async fn create_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateClientBody>,
) -> AppResult<Json<ClientCreated>> {
    let actor = require_staff_user(&state, &headers).await?;

    let client_id = normalize_client_id(&body.client_id)?;
    let redirect_uris = normalize_uris(&body.redirect_uris)?;
    let post_logout = body
        .post_logout_redirect_uris
        .map(|u| normalize_uris(&u))
        .transpose()?
        .unwrap_or_default();
    let pkce_required = body.pkce_required.unwrap_or(true);
    let scopes = normalize_scopes(
        body.scopes
            .unwrap_or_else(|| vec!["openid".into(), "profile".into(), "email".into()]),
    )?;

    let ip_allowlist_enabled = body.ip_allowlist_enabled.unwrap_or(true);
    let allowed_cidrs = normalize_cidrs(&body.allowed_cidrs.unwrap_or_default())?;
    if ip_allowlist_enabled && allowed_cidrs.is_empty() {
        return Err(AppError::bad_request(
            "allowed_cidrs required when IP allowlist is enabled (or disable allowlist)",
        ));
    }

    let plaintext = match body.client_secret {
        Some(s) if !s.trim().is_empty() => {
            if s.len() < 16 {
                return Err(AppError::bad_request(
                    "client_secret must be at least 16 characters",
                ));
            }
            s
        }
        _ => random_token(32),
    };
    let secret_hash = hash_password(&plaintext)?;
    let id = Uuid::new_v4();

    let client = sqlx::query_as::<_, AdminClient>(&format!(
        r#"
        INSERT INTO client_apps (
            id, client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
            grant_types, pkce_required, scopes, enabled,
            ip_allowlist_enabled, allowed_cidrs
        )
        VALUES (
            $1, $2, $3, $4, $5,
            ARRAY['authorization_code', 'refresh_token'],
            $6, $7, TRUE,
            $8, $9
        )
        RETURNING {CLIENT_RETURNING}
        "#
    ))
    .bind(id)
    .bind(&client_id)
    .bind(secret_hash)
    .bind(&redirect_uris)
    .bind(&post_logout)
    .bind(pkce_required)
    .bind(&scopes)
    .bind(ip_allowlist_enabled)
    .bind(&allowed_cidrs)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("client_apps_client_id_key") => {
            AppError::bad_request("client_id already exists")
        }
        other => AppError::from(other),
    })?;

    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "client.create",
            resource_type: "client",
            resource_id: Some(client.client_id.clone()),
            detail: json!({
                "redirect_uris": client.redirect_uris,
                "ip_allowlist_enabled": client.ip_allowlist_enabled,
                "allowed_cidrs": client.allowed_cidrs,
            }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(ClientCreated {
        client,
        client_secret: plaintext,
    }))
}

async fn update_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateClientBody>,
) -> AppResult<Json<AdminClient>> {
    let actor = require_staff_user(&state, &headers).await?;
    let existing = load_admin_client(&state, id).await?;

    let redirect_uris = if let Some(u) = body.redirect_uris {
        normalize_uris(&u)?
    } else {
        existing.redirect_uris.clone()
    };
    let post_logout = if let Some(u) = body.post_logout_redirect_uris {
        let mut out = Vec::new();
        for x in u {
            let t = x.trim();
            if t.is_empty() {
                continue;
            }
            if !(t.starts_with("http://") || t.starts_with("https://")) {
                return Err(AppError::bad_request(format!(
                    "redirect_uri must be http(s): {t}"
                )));
            }
            out.push(t.to_string());
        }
        out.sort();
        out.dedup();
        out
    } else {
        existing.post_logout_redirect_uris.clone()
    };
    let pkce_required = body.pkce_required.unwrap_or(existing.pkce_required);
    let scopes = if let Some(s) = body.scopes {
        normalize_scopes(s)?
    } else {
        existing.scopes.clone()
    };
    let ip_allowlist_enabled = body
        .ip_allowlist_enabled
        .unwrap_or(existing.ip_allowlist_enabled);
    let allowed_cidrs = if let Some(c) = body.allowed_cidrs {
        normalize_cidrs(&c)?
    } else {
        existing.allowed_cidrs.clone()
    };
    if ip_allowlist_enabled && allowed_cidrs.is_empty() {
        return Err(AppError::bad_request(
            "allowed_cidrs required when IP allowlist is enabled (or disable allowlist)",
        ));
    }

    let client = sqlx::query_as::<_, AdminClient>(&format!(
        r#"
        UPDATE client_apps
        SET redirect_uris = $2,
            post_logout_redirect_uris = $3,
            pkce_required = $4,
            scopes = $5,
            ip_allowlist_enabled = $6,
            allowed_cidrs = $7,
            updated_at = NOW()
        WHERE id = $1
        RETURNING {CLIENT_RETURNING}
        "#
    ))
    .bind(id)
    .bind(&redirect_uris)
    .bind(&post_logout)
    .bind(pkce_required)
    .bind(&scopes)
    .bind(ip_allowlist_enabled)
    .bind(&allowed_cidrs)
    .fetch_one(&state.pool)
    .await?;

    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "client.update",
            resource_type: "client",
            resource_id: Some(client.client_id.clone()),
            detail: json!({
                "ip_allowlist_enabled": client.ip_allowlist_enabled,
                "allowed_cidrs": client.allowed_cidrs,
            }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(client))
}

async fn delete_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_admin_user(&state, &headers).await?;
    let existing = load_admin_client(&state, id).await?;

    sqlx::query("DELETE FROM client_apps WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?;

    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "client.delete",
            resource_type: "client",
            resource_id: Some(existing.client_id),
            detail: json!({}),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn disable_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<AdminClient>> {
    let actor = require_staff_user(&state, &headers).await?;
    let client = set_enabled(&state, id, false).await?;
    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "client.disable",
            resource_type: "client",
            resource_id: Some(client.client_id.clone()),
            detail: json!({}),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;
    Ok(Json(client))
}

async fn enable_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<AdminClient>> {
    let actor = require_staff_user(&state, &headers).await?;
    let client = set_enabled(&state, id, true).await?;
    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "client.enable",
            resource_type: "client",
            resource_id: Some(client.client_id.clone()),
            detail: json!({}),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;
    Ok(Json(client))
}

async fn rotate_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ClientCreated>> {
    let actor = require_staff_user(&state, &headers).await?;
    let plaintext = random_token(32);
    let secret_hash = hash_password(&plaintext)?;

    let client = sqlx::query_as::<_, AdminClient>(&format!(
        r#"
        UPDATE client_apps
        SET client_secret_hash = $2, updated_at = NOW()
        WHERE id = $1
        RETURNING {CLIENT_RETURNING}
        "#
    ))
    .bind(id)
    .bind(secret_hash)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("client not found".into()))?;

    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "client.rotate_secret",
            resource_type: "client",
            resource_id: Some(client.client_id.clone()),
            detail: json!({}),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(ClientCreated {
        client,
        client_secret: plaintext,
    }))
}

/// Issues a single-use RFC 7591 initial access token for dynamic registration.
async fn create_registration_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_admin_user(&state, &headers).await?;
    let plaintext = random_token(32);
    let token_hash = crate::crypto_util::sha256_hex(&plaintext);
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);

    sqlx::query(
        r#"
        INSERT INTO registration_access_tokens (id, token_hash, created_by, expires_at)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&token_hash)
    .bind(actor.id)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;

    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "client.registration_token",
            resource_type: "client",
            resource_id: None,
            detail: json!({ "expires_at": expires_at.to_rfc3339() }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    // Plaintext is returned exactly once; only its hash is stored.
    Ok(Json(json!({
        "token": plaintext,
        "expires_at": expires_at.to_rfc3339(),
    })))
}

async fn load_admin_client(state: &AppState, id: Uuid) -> AppResult<AdminClient> {
    sqlx::query_as::<_, AdminClient>(&format!(
        "SELECT {CLIENT_RETURNING} FROM client_apps WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("client not found".into()))
}

async fn set_enabled(state: &AppState, id: Uuid, enabled: bool) -> AppResult<AdminClient> {
    sqlx::query_as::<_, AdminClient>(&format!(
        r#"
        UPDATE client_apps
        SET enabled = $2, updated_at = NOW()
        WHERE id = $1
        RETURNING {CLIENT_RETURNING}
        "#
    ))
    .bind(id)
    .bind(enabled)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("client not found".into()))
}

fn normalize_client_id(raw: &str) -> AppResult<String> {
    let id = raw.trim().to_lowercase();
    if id.is_empty() || id.len() > 64 {
        return Err(AppError::bad_request("invalid client_id"));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::bad_request(
            "client_id may only contain a-z, 0-9, '-' and '_'",
        ));
    }
    Ok(id)
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
