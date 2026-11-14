//! Self-service client registration and management — the dashboard
//! counterpart of GitHub's "Developer settings".
//!
//! Any signed-in user can register an OAuth client through a web form and
//! becomes its owner. Ownership is enforced in SQL: every read and write on
//! this surface filters `WHERE owner_id = $user`, and a miss is reported as a
//! plain 404, so one user cannot even learn that another user's client exists.
//! The admin surface (`crate::admin::clients`) keeps full reach over every
//! client regardless of ownership; owners get exactly the four operations the
//! form needs: create, rename/re-target, rotate the secret, delete.
//!
//! Trust model matches GitHub's: registration is gated by *authentication*,
//! not by approval. The damage a rogue application can do is bounded where it
//! has always been bounded — at the authorize/consent step, where each user
//! decides what scopes to grant; and by the global rate limiter in front of
//! every `/api/v1` route.
//!
//! Defaults mirror RFC 7591 dynamic registration (`crate::oidc::register`):
//! generated `sgn_cl_…` client_id, the authorization_code + refresh_token grant
//! pair, PKCE on, no IP allowlist. The client picks neither its client_id nor
//! its secret, so nothing an applicant types can collide with or weaken
//! another client.

use crate::audit::{record, AuditEvent};
use crate::auth::session::current_user;
use crate::crypto::util::prefixed_token;
use crate::error::{AppError, AppResult};
use crate::http::extract::AuditIp;
use crate::state::AppState;
use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/me/clients", get(list_my_clients).post(create_my_client))
        .route(
            "/me/clients/{id}",
            put(update_my_client).delete(delete_my_client),
        )
        .route(
            "/me/clients/{id}/rotate-secret",
            post(rotate_my_client_secret),
        )
}

/// Read-side projection of a client as its owner may see it.
///
/// Deliberately narrower than [`crate::admin::clients::AdminClient`]: the
/// owner does not manage grant types, extra claims, back-channel logout or IP
/// allowlists — those stay admin-level decisions, and the columns are simply
/// not read here.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct SelfClient {
    pub id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const SELF_CLIENT_RETURNING: &str = "
    id, client_id, client_name, redirect_uris, scopes, enabled, created_at, updated_at
";

/// Create/rotate response: the plaintext secret travels to the dashboard
/// exactly once — only its hash is stored (same contract as the admin surface
/// and RFC 7591 registration).
#[derive(Debug, Serialize)]
pub struct ClientSecretIssued {
    client: SelfClient,
    client_secret: String,
}

#[derive(Debug, Deserialize)]
struct CreateSelfClientBody {
    client_name: String,
    redirect_uris: Vec<String>,
    scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct UpdateSelfClientBody {
    client_name: Option<String>,
    redirect_uris: Option<Vec<String>>,
}

async fn list_my_clients(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<SelfClient>>> {
    let user = current_user(&state, &headers).await?;
    let rows = sqlx::query_as::<_, SelfClient>(&format!(
        "SELECT {SELF_CLIENT_RETURNING} FROM client_apps \
         WHERE owner_id = $1 ORDER BY created_at DESC"
    ))
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

async fn create_my_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Json(body): Json<CreateSelfClientBody>,
) -> AppResult<Json<ClientSecretIssued>> {
    let user = current_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);

    let client_name = normalize_client_name(&body.client_name)?;
    let redirect_uris = normalize_uris(&body.redirect_uris)?;
    let scopes = normalize_scopes(
        body.scopes
            .unwrap_or_else(|| vec!["openid".into(), "profile".into(), "email".into()]),
    )?;

    let client_id = prefixed_token("sgn_cl", 12);
    let secret = prefixed_token("sgn_cs", 32);
    let secret_hash = crate::auth::client_secret::digest(&state.client_secret_key, &secret);
    let id = Uuid::new_v4();

    let client = sqlx::query_as::<_, SelfClient>(&format!(
        r#"
        INSERT INTO client_apps (
            id, client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
            grant_types, pkce_required, scopes, enabled,
            ip_allowlist_enabled, allowed_cidrs, client_name, owner_id
        )
        VALUES (
            $1, $2, $3, $4, ARRAY[]::text[],
            ARRAY['authorization_code', 'refresh_token'],
            TRUE, $5, TRUE, FALSE, ARRAY[]::text[], $6, $7
        )
        RETURNING {SELF_CLIENT_RETURNING}
        "#
    ))
    .bind(id)
    .bind(&client_id)
    .bind(&secret_hash)
    .bind(&redirect_uris)
    .bind(&scopes)
    .bind(&client_name)
    .bind(user.id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("client_apps_client_id_key") => {
            AppError::bad_request("client_id collision, retry")
        }
        other => AppError::from(other),
    })?;

    record(
        &state,
        AuditEvent {
            actor: Some(user),
            action: "client.create",
            resource_type: "client",
            resource_id: Some(client.client_id.clone()),
            detail: json!({
                "redirect_uris": client.redirect_uris,
                "client_name": client.client_name,
                "via": "self_service",
            }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(ClientSecretIssued {
        client,
        client_secret: secret,
    }))
}

async fn update_my_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateSelfClientBody>,
) -> AppResult<Json<SelfClient>> {
    let user = current_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);

    // Absent fields keep the stored value, so the read must be ownership-
    // scoped too: a client that exists but belongs to someone else is a 404
    // here, not a template for the UPDATE below.
    let existing = sqlx::query_as::<_, SelfClient>(&format!(
        "SELECT {SELF_CLIENT_RETURNING} FROM client_apps WHERE id = $1 AND owner_id = $2"
    ))
    .bind(id)
    .bind(user.id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("client not found".into()))?;

    let client_name = match body.client_name {
        Some(n) => normalize_client_name(&n)?,
        None => existing.client_name.clone(),
    };
    let redirect_uris = match body.redirect_uris {
        Some(u) => normalize_uris(&u)?,
        None => existing.redirect_uris.clone(),
    };

    let client = sqlx::query_as::<_, SelfClient>(&format!(
        r#"
        UPDATE client_apps
        SET client_name = $1, redirect_uris = $2, updated_at = NOW()
        WHERE id = $3 AND owner_id = $4
        RETURNING {SELF_CLIENT_RETURNING}
        "#
    ))
    .bind(&client_name)
    .bind(&redirect_uris)
    .bind(id)
    .bind(user.id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("client not found".into()))?;

    record(
        &state,
        AuditEvent {
            actor: Some(user),
            action: "client.update",
            resource_type: "client",
            resource_id: Some(client.client_id.clone()),
            detail: json!({
                "redirect_uris": client.redirect_uris,
                "client_name": client.client_name,
                "via": "self_service",
            }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(client))
}

async fn rotate_my_client_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ClientSecretIssued>> {
    let user = current_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);

    let secret = prefixed_token("sgn_cs", 32);
    let secret_hash = crate::auth::client_secret::digest(&state.client_secret_key, &secret);

    let client = sqlx::query_as::<_, SelfClient>(&format!(
        r#"
        UPDATE client_apps
        SET client_secret_hash = $1, updated_at = NOW()
        WHERE id = $2 AND owner_id = $3
        RETURNING {SELF_CLIENT_RETURNING}
        "#
    ))
    .bind(secret_hash)
    .bind(id)
    .bind(user.id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("client not found".into()))?;

    record(
        &state,
        AuditEvent {
            actor: Some(user),
            action: "client.rotate_secret",
            resource_type: "client",
            resource_id: Some(client.client_id.clone()),
            detail: json!({ "via": "self_service" }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(ClientSecretIssued {
        client,
        client_secret: secret,
    }))
}

async fn delete_my_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let user = current_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);

    let existing = sqlx::query_as::<_, SelfClient>(
        "SELECT id, client_id, client_name, redirect_uris, scopes, enabled, created_at, updated_at \
         FROM client_apps WHERE id = $1 AND owner_id = $2",
    )
    .bind(id)
    .bind(user.id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("client not found".into()))?;

    // Ownership is already established above; the plain delete keeps the same
    // CASCADE semantics as the admin path (consents, auth codes and refresh
    // tokens go with the client).
    sqlx::query("DELETE FROM client_apps WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?;

    record(
        &state,
        AuditEvent {
            actor: Some(user),
            action: "client.delete",
            resource_type: "client",
            resource_id: Some(existing.client_id),
            detail: json!({ "via": "self_service" }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "ok": true })))
}

/// Shared redirect-URI validation. Was duplicated as private copies in
/// `admin/clients.rs` and `oidc/register.rs`; self-service registration is
/// the third caller, so the rules now live in exactly one place. Behavior is
/// unchanged: http(s) only, no fragment (RFC 6749 §3.1.2), at least one URI,
/// sorted and deduplicated for stable comparisons downstream.
pub(crate) fn normalize_uris(uris: &[String]) -> AppResult<Vec<String>> {
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

/// Shared scope validation: `openid` is mandatory because the whole surface
/// speaks OIDC. Same dedup/sort contract as [`normalize_uris`].
pub(crate) fn normalize_scopes(scopes: Vec<String>) -> AppResult<Vec<String>> {
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

/// A display name is required for a self-registered app: the consent screen
/// shows it to every user who authorizes the client, so "untitled app" is not
/// an acceptable outcome. The cap keeps a long name from breaking the
/// consent layout; admins can always rename from the Clients page.
fn normalize_client_name(raw: &str) -> AppResult<String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(AppError::bad_request("client_name is required"));
    }
    if name.chars().count() > 200 {
        return Err(AppError::bad_request(
            "client_name must be at most 200 characters",
        ));
    }
    Ok(name.to_string())
}
