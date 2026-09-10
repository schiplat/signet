//! Admin + user APIs for federated identity management.
//!
//! Admin surface (`/api/v1/admin/sso/providers*`): CRUD for upstream
//! providers with the client secret write-only (rotate-only, never
//! serialized back), enable/disable, and the computed callback URL each
//! provider must be registered with.
//!
//! User surface (`/api/v1/auth/sso/identities*`): list the signed-in user's
//! linked third-party accounts and unlink them. Unlinking is refused when it
//! would remove the user's last usable login method (no password set and
//! this is the last identity), preventing lockout.

use crate::audit::{record, AuditEvent};
use crate::auth::current_user;
use crate::error::{AppError, AppResult};
use crate::models::User;
use crate::roles::require_admin_role;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/sso/providers", get(admin_list).post(admin_create))
        .route(
            "/admin/sso/providers/{code}",
            axum::routing::put(admin_update).delete(admin_delete),
        )
        .route(
            "/admin/sso/providers/{code}/enabled",
            post(admin_set_enabled),
        )
        .route(
            "/admin/settings/sso",
            get(get_sso_settings).patch(patch_sso_settings),
        )
        // Public: the login page needs the enabled-provider list pre-auth.
        .route("/auth/sso/providers", get(public_enabled_providers))
        .route("/auth/sso/identities", get(list_my_identities))
        .route(
            "/auth/sso/identities/{provider_code}",
            axum::routing::delete(unlink_identity),
        )
        .route("/auth/sso/callback-url", get(callback_url))
}

/// Whether first-time SSO with a verified email may create a local member.
///
/// Reads `app_settings.sso.jit_provision`; if the row is missing, falls back
/// to `SIGNET_SSO_JIT_PROVISION` (default true).
pub async fn sso_jit_provision_enabled(pool: &PgPool, env_default: bool) -> AppResult<bool> {
    let value: Option<Value> =
        sqlx::query_scalar("SELECT value FROM app_settings WHERE key = 'sso.jit_provision'")
            .fetch_optional(pool)
            .await?;
    Ok(value.and_then(|v| v.as_bool()).unwrap_or(env_default))
}

async fn set_sso_jit_provision(pool: &PgPool, enabled: bool) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO app_settings (key, value, updated_at)
        VALUES ('sso.jit_provision', $1, NOW())
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
        "#,
    )
    .bind(json!(enabled))
    .execute(pool)
    .await?;
    Ok(())
}

async fn get_sso_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let actor = current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let jit_provision =
        sso_jit_provision_enabled(&state.pool, state.config.sso_jit_provision).await?;
    Ok(Json(json!({ "jit_provision": jit_provision })))
}

#[derive(Debug, Deserialize)]
struct PatchSsoSettings {
    jit_provision: bool,
}

async fn patch_sso_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PatchSsoSettings>,
) -> AppResult<Json<Value>> {
    let actor = current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    set_sso_jit_provision(&state.pool, body.jit_provision).await?;
    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "settings.sso_update",
            resource_type: "settings",
            resource_id: Some("sso.jit_provision".into()),
            detail: json!({ "jit_provision": body.jit_provision }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;
    Ok(Json(json!({ "jit_provision": body.jit_provision })))
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

/// Serialized provider row — client_secret never leaves the server.
#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct AdminProvider {
    code: String,
    provider_type: String,
    display_name: String,
    client_id: String,
    issuer_url: Option<String>,
    scopes: Option<String>,
    enabled: bool,
    /// Count of user bindings, for the admin list view.
    bindings: i64,
    /// Concrete redirect URI to register with this provider, computed from
    /// the public base URL. Filled in after the query (see admin_list).
    #[sqlx(skip)]
    callback_url: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

/// Public base URL for provider redirect URIs: SIGNET_PUBLIC_BASE_URL when
/// set, falling back to the issuer (single-host deployments).
pub(crate) fn public_base(state: &AppState) -> String {
    state
        .config
        .public_base_url
        .clone()
        .unwrap_or_else(|| state.config.issuer.clone())
        .trim_end_matches('/')
        .to_string()
}

/// The one redirect-URI pattern shared by every provider type. Platform
/// quirks (WeChat encoding, Feishu app tokens, OIDC discovery) are absorbed
/// by the adapters, never by the URL shape.
fn provider_callback_url(state: &AppState, code: &str) -> String {
    format!("{}/api/v1/auth/sso/{}/callback", public_base(state), code)
}

async fn require_admin(state: &AppState, headers: &HeaderMap) -> AppResult<User> {
    let user = current_user(state, headers).await?;
    require_admin_role(&user)?;
    Ok(user)
}

async fn admin_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    require_admin(&state, &headers).await?;
    let mut providers: Vec<AdminProvider> = sqlx::query_as(
        r#"
        SELECT p.code, p.provider_type, p.display_name, p.client_id, p.issuer_url,
               p.scopes, p.enabled,
               (SELECT COUNT(*) FROM user_identities ui WHERE ui.provider_code = p.code) AS bindings,
               p.created_at, p.updated_at
        FROM upstream_providers p
        ORDER BY p.code
        "#,
    )
    .fetch_all(&state.pool)
    .await?;
    for p in &mut providers {
        p.callback_url = provider_callback_url(&state, &p.code);
    }
    Ok(Json(json!({ "providers": providers })))
}

#[derive(Debug, Deserialize)]
struct ProviderBody {
    code: String,
    provider_type: String,
    display_name: String,
    client_id: String,
    /// Write-only: empty/absent on update means "keep the stored secret".
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    issuer_url: Option<String>,
    #[serde(default)]
    scopes: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

const VALID_TYPES: &[&str] = &["github", "google", "feishu", "wechat", "oidc"];

fn validate_body(body: &ProviderBody) -> AppResult<()> {
    let code_ok = !body.code.is_empty()
        && body
            .code
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !code_ok {
        return Err(AppError::bad_request(
            "code must be non-empty [a-zA-Z0-9_-]",
        ));
    }
    if !VALID_TYPES.contains(&body.provider_type.as_str()) {
        return Err(AppError::bad_request("unknown provider_type"));
    }
    if body.provider_type == "oidc" && body.issuer_url.as_deref().unwrap_or("").is_empty() {
        return Err(AppError::bad_request("oidc providers require issuer_url"));
    }
    if body.client_id.trim().is_empty() {
        return Err(AppError::bad_request("client_id is required"));
    }
    Ok(())
}

async fn admin_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ProviderBody>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_admin(&state, &headers).await?;
    validate_body(&body)?;
    let secret = body
        .client_secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::bad_request("client_secret is required"))?;
    let secret_enc = state.encryptor.encrypt(secret);

    // `scopes`/`display_name` are NOT NULL in the schema: empty form values
    // bind as "" (empty string), never SQL NULL.
    let scopes_value = body
        .scopes
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    let display_value = if body.display_name.trim().is_empty() {
        body.code.clone()
    } else {
        body.display_name.trim().to_string()
    };

    sqlx::query(
        r#"
        INSERT INTO upstream_providers
            (code, provider_type, display_name, client_id, client_secret_enc,
             issuer_url, scopes, enabled)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(&body.code)
    .bind(&body.provider_type)
    .bind(&display_value)
    .bind(body.client_id.trim())
    .bind(&secret_enc)
    .bind(
        body.issuer_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    )
    .bind(&scopes_value)
    .bind(body.enabled.unwrap_or(true))
    .execute(&state.pool)
    .await
    .map_err(|e| db_conflict(e, &body.code))?;

    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "admin.sso_provider.create",
            resource_type: "sso_provider",
            resource_id: Some(body.code.clone()),
            detail: json!({ "provider_type": body.provider_type }),
            ip: None,
            user_agent: None,
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "ok": true, "code": body.code })))
}

async fn admin_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
    Json(body): Json<ProviderBody>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_admin(&state, &headers).await?;
    validate_body(&body)?;

    // NOT NULL columns: empty form values become "" / code, never SQL NULL.
    let scopes_value = body
        .scopes
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    let display_value = if body.display_name.trim().is_empty() {
        code.clone()
    } else {
        body.display_name.trim().to_string()
    };

    let result = if body
        .client_secret
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty())
    {
        // Rotation: only when a new secret was supplied.
        let secret_enc = state
            .encryptor
            .encrypt(body.client_secret.as_deref().unwrap_or_default().trim());
        sqlx::query(
            r#"
            UPDATE upstream_providers SET
                provider_type = $2, display_name = $3, client_id = $4,
                client_secret_enc = $5, issuer_url = $6, scopes = $7,
                enabled = $8, updated_at = NOW()
            WHERE code = $1
            "#,
        )
        .bind(&code)
        .bind(&body.provider_type)
        .bind(&display_value)
        .bind(body.client_id.trim())
        .bind(&secret_enc)
        .bind(
            body.issuer_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty()),
        )
        .bind(&scopes_value)
        .bind(body.enabled.unwrap_or(true))
        .execute(&state.pool)
        .await
    } else {
        sqlx::query(
            r#"
            UPDATE upstream_providers SET
                provider_type = $2, display_name = $3, client_id = $4,
                issuer_url = $5, scopes = $6, enabled = $7, updated_at = NOW()
            WHERE code = $1
            "#,
        )
        .bind(&code)
        .bind(&body.provider_type)
        .bind(&display_value)
        .bind(body.client_id.trim())
        .bind(
            body.issuer_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty()),
        )
        .bind(&scopes_value)
        .bind(body.enabled.unwrap_or(true))
        .execute(&state.pool)
        .await
    };
    if result?.rows_affected() == 0 {
        return Err(AppError::not_found("provider not found"));
    }

    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "admin.sso_provider.update",
            resource_type: "sso_provider",
            resource_id: Some(code.clone()),
            detail: json!({ "secret_rotated": body.client_secret.is_some() }),
            ip: None,
            user_agent: None,
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "ok": true })))
}

async fn admin_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_admin(&state, &headers).await?;
    let result = sqlx::query("DELETE FROM upstream_providers WHERE code = $1")
        .bind(&code)
        .execute(&state.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found("provider not found"));
    }
    // user_identities rows cascade; record how many links were dropped.
    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "admin.sso_provider.delete",
            resource_type: "sso_provider",
            resource_id: Some(code.clone()),
            detail: json!({}),
            ip: None,
            user_agent: None,
            client_id: None,
        },
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

async fn admin_set_enabled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_admin(&state, &headers).await?;
    let enabled = body
        .get("enabled")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| AppError::bad_request("enabled (bool) is required"))?;
    let result = sqlx::query(
        "UPDATE upstream_providers SET enabled = $2, updated_at = NOW() WHERE code = $1",
    )
    .bind(&code)
    .bind(enabled)
    .execute(&state.pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found("provider not found"));
    }
    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "admin.sso_provider.update",
            resource_type: "sso_provider",
            resource_id: Some(code.clone()),
            detail: json!({ "enabled": enabled }),
            ip: None,
            user_agent: None,
            client_id: None,
        },
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

fn db_conflict(e: sqlx::Error, code: &str) -> AppError {
    if let sqlx::Error::Database(db) = &e {
        if db
            .constraint()
            .is_some_and(|c| c.contains("upstream_providers_pkey"))
        {
            return AppError::bad_request(format!("provider '{code}' already exists"));
        }
    }
    AppError::from(e)
}

// ---------------------------------------------------------------------------
// User surface
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct UserIdentity {
    provider_code: String,
    provider_type: String,
    provider_display_name: String,
    email: Option<String>,
    linked_at: chrono::DateTime<chrono::Utc>,
    last_login_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Enabled providers, for the login page buttons. Public (no auth): the login
/// page itself needs this list before the visitor is authenticated.
async fn public_enabled_providers(
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT code, provider_type, display_name FROM upstream_providers \
         WHERE enabled = TRUE ORDER BY code",
    )
    .fetch_all(&state.pool)
    .await?;
    let providers: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(code, provider_type, display_name)| {
            json!({ "code": code, "type": provider_type, "display_name": display_name })
        })
        .collect();
    Ok(Json(json!({ "providers": providers })))
}

async fn list_my_identities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let user = current_user(&state, &headers).await?;
    let rows: Vec<UserIdentity> = sqlx::query_as(
        r#"
        SELECT ui.provider_code, p.provider_type, p.display_name AS provider_display_name,
               ui.email, ui.linked_at, ui.last_login_at
        FROM user_identities ui
        JOIN upstream_providers p ON p.code = ui.provider_code
        WHERE ui.user_id = $1
        ORDER BY ui.linked_at
        "#,
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({ "identities": rows })))
}

async fn unlink_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider_code): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let user = current_user(&state, &headers).await?;

    // Lockout guard (pre-check): the user must keep at least one login
    // method after the unlink — a usable password or another identity.
    let has_password = !user.password_hash.is_empty();
    let linked: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_identities WHERE user_id = $1")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await?;
    if !has_password && linked <= 1 {
        return Err(AppError::bad_request("cannot unlink the last login method"));
    }

    let deleted =
        sqlx::query("DELETE FROM user_identities WHERE user_id = $1 AND provider_code = $2")
            .bind(user.id)
            .bind(&provider_code)
            .execute(&state.pool)
            .await?;
    if deleted.rows_affected() == 0 {
        return Err(AppError::not_found("identity not linked"));
    }

    record(
        &state.pool,
        AuditEvent {
            resource_id: Some(user.id.to_string()),
            actor: Some(user),
            action: "auth.identity.unlink",
            resource_type: "user",
            detail: json!({ "provider": provider_code }),
            ip: None,
            user_agent: None,
            client_id: None,
        },
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

/// The callback URL pattern admins must register with each provider.
async fn callback_url(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    require_admin(&state, &headers).await?;
    Ok(Json(json!({
        // Same shape for every provider; {provider} is the configured code.
        "callback_url": provider_callback_url(&state, "{provider}"),
    })))
}
