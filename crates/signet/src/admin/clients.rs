use crate::admin::{require_admin_user, require_staff_user};
use crate::audit::{record, AuditEvent};
use crate::crypto::util::prefixed_token;
use crate::developer::{normalize_scopes, normalize_uris};
use crate::error::{AppError, AppResult};
use crate::http::extract::AuditIp;
use crate::http::source_ip::normalize_cidrs;
use crate::state::AppState;
use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

const CLIENT_RETURNING: &str = r#"
    id, client_id, client_name, redirect_uris, post_logout_redirect_uris,
    grant_types, extra_claims, backchannel_logout_uri, scopes, enabled,
    ip_allowlist_enabled, allowed_cidrs, created_at, updated_at, owner_id
"#;

/// `CLIENT_RETURNING` with the `c.` alias the list query needs for its join.
///
/// `RETURNING` clauses cannot join, so the single-client endpoints return a
/// NULL `owner_email` and [`with_owner_email`] fills it in. The list query is
/// the one place the owner address comes straight out of SQL.
const CLIENT_LIST_COLUMNS: &str = r#"
    c.id, c.client_id, c.client_name, c.redirect_uris, c.post_logout_redirect_uris,
    c.grant_types, c.extra_claims, c.backchannel_logout_uri, c.scopes, c.enabled,
    c.ip_allowlist_enabled, c.allowed_cidrs, c.created_at, c.updated_at,
    c.owner_id, u.email AS owner_email
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
    /// Display name; `''` for clients that predate self-service registration
    /// or were created without one — the dashboard falls back to client_id.
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub extra_claims: Option<serde_json::Value>,
    pub backchannel_logout_uri: Option<String>,
    pub scopes: Vec<String>,
    pub enabled: bool,
    pub ip_allowlist_enabled: bool,
    pub allowed_cidrs: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// The user who self-registered this client; `None` for clients created by
    /// an administrator (or whose owner was deleted). Ownership means "who may
    /// manage it on the My apps page", not a restriction on the admin surface.
    pub owner_id: Option<Uuid>,
    /// Owner's email. Only the list query joins it; single-client responses
    /// fill it through [`with_owner_email`], so the field is optional there.
    #[sqlx(default)]
    pub owner_email: Option<String>,
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
    scopes: Option<Vec<String>>,
    /// Subset of {authorization_code, refresh_token, client_credentials}.
    /// Absent → the classic web-app pair; `client_credentials` is opt-in
    /// because it makes the client a standalone principal.
    grant_types: Option<Vec<String>>,
    /// Static or `$field` claims merged into this client's tokens.
    extra_claims: Option<serde_json::Value>,
    /// OIDC Back-Channel Logout endpoint.
    backchannel_logout_uri: Option<String>,
    /// Default true (minimum privilege).
    ip_allowlist_enabled: Option<bool>,
    allowed_cidrs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct UpdateClientBody {
    redirect_uris: Option<Vec<String>>,
    post_logout_redirect_uris: Option<Vec<String>>,
    scopes: Option<Vec<String>>,
    grant_types: Option<Vec<String>>,
    extra_claims: Option<serde_json::Value>,
    backchannel_logout_uri: Option<String>,
    ip_allowlist_enabled: Option<bool>,
    allowed_cidrs: Option<Vec<String>>,
}

async fn list_clients(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<AdminClient>>> {
    require_staff_user(&state, &headers).await?;
    let rows = sqlx::query_as::<_, AdminClient>(&format!(
        "SELECT {CLIENT_LIST_COLUMNS} FROM client_apps c \
         LEFT JOIN users u ON u.id = c.owner_id \
         ORDER BY c.created_at DESC"
    ))
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

/// Fills `owner_email` on a single-client response.
///
/// The `RETURNING` clauses cannot join, so this is one extra query on admin
/// mutations (rare) and keeps every response shape identical — the dashboard
/// renders the Owner column from whichever endpoint produced the row.
async fn with_owner_email(state: &AppState, client: &mut AdminClient) -> AppResult<()> {
    if let Some(owner_id) = client.owner_id {
        client.owner_email = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(owner_id)
            .fetch_optional(&state.pool)
            .await?;
    }
    Ok(())
}

async fn create_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Json(body): Json<CreateClientBody>,
) -> AppResult<Json<ClientCreated>> {
    let actor = require_staff_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);

    let client_id = normalize_client_id(&body.client_id)?;
    let redirect_uris = normalize_uris(&body.redirect_uris)?;
    let post_logout = body
        .post_logout_redirect_uris
        .map(|u| normalize_uris(&u))
        .transpose()?
        .unwrap_or_default();
    let scopes = normalize_scopes(
        body.scopes
            .unwrap_or_else(|| vec!["openid".into(), "profile".into(), "email".into()]),
    )?;
    let grant_types = normalize_grant_types(
        body.grant_types.as_ref(),
        &["authorization_code", "refresh_token"],
    )?;
    let extra_claims = normalize_extra_claims(body.extra_claims.as_ref())?;

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
        _ => prefixed_token("sgn_cs", 32),
    };
    let secret_hash = crate::auth::client_secret::digest(&state.client_secret_key, &plaintext);
    let id = Uuid::new_v4();

    let mut client = sqlx::query_as::<_, AdminClient>(&format!(
        r#"
        INSERT INTO client_apps (
            id, client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
            grant_types, extra_claims, backchannel_logout_uri, scopes, enabled,
            ip_allowlist_enabled, allowed_cidrs
        )
        VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9, TRUE,
            $10, $11
        )
        RETURNING {CLIENT_RETURNING}
        "#
    ))
    .bind(id)
    .bind(&client_id)
    .bind(secret_hash)
    .bind(&redirect_uris)
    .bind(&post_logout)
    .bind(&grant_types)
    .bind(&extra_claims)
    .bind(
        body.backchannel_logout_uri
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    )
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
        &state,
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
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    with_owner_email(&state, &mut client).await?;
    Ok(Json(ClientCreated {
        client,
        client_secret: plaintext,
    }))
}

async fn update_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateClientBody>,
) -> AppResult<Json<AdminClient>> {
    let actor = require_staff_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);
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
            if t.contains('#') {
                return Err(AppError::bad_request(format!(
                    "redirect_uri must not contain a fragment: {t}"
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
    // Absent fields keep the stored value, which is what makes a form that
    // does not render grants/claims safe to save.
    let grant_types = normalize_grant_types(
        body.grant_types.as_ref().or(Some(&existing.grant_types)),
        &[],
    )?;
    let extra_claims = normalize_extra_claims(
        body.extra_claims
            .as_ref()
            .or(existing.extra_claims.as_ref()),
    )?;

    let mut client = sqlx::query_as::<_, AdminClient>(&format!(
        r#"
        UPDATE client_apps
        SET redirect_uris = $2,
            post_logout_redirect_uris = $3,
            grant_types = $4,
            extra_claims = $5,
            backchannel_logout_uri = $6,
            scopes = $7,
            ip_allowlist_enabled = $8,
            allowed_cidrs = $9,
            updated_at = NOW()
        WHERE id = $1
        RETURNING {CLIENT_RETURNING}
        "#
    ))
    .bind(id)
    .bind(&redirect_uris)
    .bind(&post_logout)
    .bind(&grant_types)
    .bind(&extra_claims)
    .bind(
        body.backchannel_logout_uri
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    )
    .bind(&scopes)
    .bind(ip_allowlist_enabled)
    .bind(&allowed_cidrs)
    .fetch_one(&state.pool)
    .await?;

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "client.update",
            resource_type: "client",
            resource_id: Some(client.client_id.clone()),
            // On an IdP, the redirect URIs are the takeover surface: an update
            // that points a client at an attacker-controlled callback is the
            // step before every code-interception scheme, so the change is
            // recorded as before → after, not just the resulting state.
            detail: json!({
                "redirect_uris": { "before": existing.redirect_uris, "after": client.redirect_uris },
                "post_logout_redirect_uris": { "before": existing.post_logout_redirect_uris, "after": client.post_logout_redirect_uris },
                "scopes": { "before": existing.scopes, "after": client.scopes },
                "ip_allowlist_enabled": client.ip_allowlist_enabled,
                "allowed_cidrs": client.allowed_cidrs,
            }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    with_owner_email(&state, &mut client).await?;
    Ok(Json(client))
}

async fn delete_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_admin_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);
    let existing = load_admin_client(&state, id).await?;

    sqlx::query("DELETE FROM client_apps WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?;

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "client.delete",
            resource_type: "client",
            resource_id: Some(existing.client_id),
            detail: json!({}),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn disable_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<AdminClient>> {
    let actor = require_staff_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);
    let mut client = set_enabled(&state, id, false).await?;
    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "client.disable",
            resource_type: "client",
            resource_id: Some(client.client_id.clone()),
            detail: json!({}),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;
    with_owner_email(&state, &mut client).await?;
    Ok(Json(client))
}

async fn enable_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<AdminClient>> {
    let actor = require_staff_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);
    let mut client = set_enabled(&state, id, true).await?;
    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "client.enable",
            resource_type: "client",
            resource_id: Some(client.client_id.clone()),
            detail: json!({}),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;
    with_owner_email(&state, &mut client).await?;
    Ok(Json(client))
}

async fn rotate_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ClientCreated>> {
    let actor = require_staff_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);
    let plaintext = prefixed_token("sgn_cs", 32);
    let secret_hash = crate::auth::client_secret::digest(&state.client_secret_key, &plaintext);

    let mut client = sqlx::query_as::<_, AdminClient>(&format!(
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
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "client.rotate_secret",
            resource_type: "client",
            resource_id: Some(client.client_id.clone()),
            detail: json!({}),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    with_owner_email(&state, &mut client).await?;
    Ok(Json(ClientCreated {
        client,
        client_secret: plaintext,
    }))
}

/// Issues a single-use RFC 7591 initial access token for dynamic registration.
async fn create_registration_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_admin_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);
    let plaintext = prefixed_token("sgn_reg", 32);
    let token_hash = crate::crypto::util::sha256_hex(&plaintext);
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
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "client.registration_token",
            resource_type: "client",
            resource_id: None,
            detail: json!({ "expires_at": expires_at.to_rfc3339() }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
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

/// The grant types a client may be registered for. `client_credentials` makes
/// the client a standalone principal with no user behind its tokens, so it is
/// opt-in per client rather than part of the default pair.
pub(crate) const ALLOWED_GRANT_TYPES: &[&str] =
    &["authorization_code", "refresh_token", "client_credentials"];

fn normalize_grant_types(grants: Option<&Vec<String>>, default: &[&str]) -> AppResult<Vec<String>> {
    let Some(grants) = grants else {
        return Ok(default.iter().map(|s| s.to_string()).collect());
    };
    let mut out: Vec<String> = grants
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if out.is_empty() {
        return Err(AppError::bad_request(
            "at least one grant type is required (a client with none can do nothing)",
        ));
    }
    out.sort();
    out.dedup();
    for g in &out {
        if !ALLOWED_GRANT_TYPES.contains(&g.as_str()) {
            return Err(AppError::bad_request(format!(
                "unsupported grant_type: {g} (allowed: {})",
                ALLOWED_GRANT_TYPES.join(", ")
            )));
        }
    }
    Ok(out)
}

/// `extra_claims` must be an object of scalars (or `$field` placeholders).
fn normalize_extra_claims(raw: Option<&serde_json::Value>) -> AppResult<Option<serde_json::Value>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    let Some(obj) = raw.as_object() else {
        return Err(AppError::bad_request(
            "extra_claims must be an object of claim name -> value",
        ));
    };
    if obj.len() > 32 {
        return Err(AppError::bad_request(
            "extra_claims accepts at most 32 entries",
        ));
    }
    for (name, value) in obj {
        if !(value.is_string() || value.is_boolean() || value.is_number()) {
            return Err(AppError::bad_request(format!(
                "extra claim `{name}` must be a string, number or boolean (string values                  starting with `$` resolve per user: $sub, $email, $username, $display_name,                  $phone)"
            )));
        }
    }
    Ok(Some(raw.clone()))
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

// Redirect-URI and scope rules live in `developer::{normalize_uris,
// normalize_scopes}` — the one shared copy across the admin surface, RFC 7591
// registration and self-service registration.
