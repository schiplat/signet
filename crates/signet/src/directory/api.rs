//! Admin HTTP surface for directory sources (§10).
//!
//! Everything here is `admin`-only: a source row carries a credential that can
//! read the whole directory, so read access to the list is already sensitive.
//! The stored credential and CA body are never returned — only whether they are
//! set — so a misdirected response cannot leak them.

use crate::audit::AuditEvent;
use crate::directory::engine::{self, Trigger};
use crate::directory::mapping;
use crate::directory::model;
use crate::directory::source::{self, SourceView, SOURCE_VIEW_COLS};
use crate::error::{AppError, AppResult};
use crate::roles::require_admin_role;
use crate::state::AppState;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/directory/sources",
            get(list_sources).post(create_source),
        )
        .route(
            "/admin/directory/sources/{code}",
            put(update_source).delete(delete_source),
        )
        .route("/admin/directory/sources/{code}/enabled", post(set_enabled))
        .route("/admin/directory/sources/{code}/sync", post(trigger_sync))
        .route("/admin/directory/sources/{code}/runs", get(list_runs))
        .route("/admin/directory/sources/{code}/runs/{id}", get(get_run))
        .route(
            "/admin/directory/sources/preview-mapping",
            // A pasted sample is embedded in the body as a string, so one sample
            // byte can cost up to two body bytes. The explicit limit keeps the
            // friendly "sample too large" message from being pre-empted by the
            // framework's own 413.
            post(preview_mapping).layer(DefaultBodyLimit::max(4 * 1024 * 1024)),
        )
}

#[derive(Debug, Deserialize)]
struct CreateSourceBody {
    code: String,
    name: String,
    kind: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_priority")]
    priority: i32,
    config: Value,
    /// Service-account password / bearer token. Required for `ldap`: binding
    /// anonymously usually succeeds but silently returns a reduced view of the
    /// directory, which is far harder to diagnose than an error here.
    credential: Option<String>,
    ca_cert_pem: Option<String>,
    #[serde(default = "default_true")]
    sync_groups: bool,
    interval_minutes: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct UpdateSourceBody {
    name: String,
    kind: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_priority")]
    priority: i32,
    config: Value,
    /// Tri-state: omit to keep the stored credential, send `""` to clear it, or
    /// send a value to replace it. This is what lets the UI round-trip a source
    /// without ever handling the plaintext secret.
    credential: Option<String>,
    /// Tri-state, like `credential`.
    ca_cert_pem: Option<String>,
    #[serde(default = "default_true")]
    sync_groups: bool,
    interval_minutes: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct EnabledBody {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct RunsQuery {
    limit: Option<i64>,
}

fn default_priority() -> i32 {
    100
}

fn default_true() -> bool {
    true
}

async fn list_sources(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<SourceView>>> {
    require_admin(&state, &headers).await?;
    Ok(Json(source::list(&state.pool).await?))
}

async fn create_source(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateSourceBody>,
) -> AppResult<Json<SourceView>> {
    let actor = require_admin(&state, &headers).await?;
    let code = body.code.trim().to_string();
    source::validate_payload(
        &code,
        &body.name,
        &body.kind,
        &body.config,
        body.ca_cert_pem.as_deref(),
        body.interval_minutes,
    )?;
    // Parsed rather than re-read from `body`: the requirement follows the auth
    // scheme the config declares, and asking the same parser the engine will use
    // keeps the two from disagreeing.
    let parsed = source::SourceConfig::parse(&body.kind, &body.config)?;
    source::ensure_destination_allowed(&state, &parsed).await?;
    let credential_enc = source::encrypt_credential(&state, body.credential.as_deref());
    if parsed.requires_credential() && credential_enc.is_none() {
        return Err(AppError::bad_request(
            "credential is required: this source authenticates as a service account",
        ));
    }

    let view = sqlx::query_as::<_, SourceView>(&format!(
        r#"
        INSERT INTO directory_sources
            (id, code, name, kind, enabled, priority, config, credential_enc, ca_cert_pem,
             sync_groups, interval_minutes)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING {SOURCE_VIEW_COLS}
        "#
    ))
    .bind(Uuid::new_v4())
    .bind(&code)
    .bind(body.name.trim())
    .bind(&body.kind)
    .bind(body.enabled)
    .bind(body.priority)
    .bind(&body.config)
    .bind(&credential_enc)
    .bind(non_empty(body.ca_cert_pem.as_deref()))
    .bind(body.sync_groups)
    .bind(body.interval_minutes)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("directory_sources_code_key") => {
            AppError::conflict(format!("a source with code `{code}` already exists"))
        }
        other => AppError::from(other),
    })?;

    audit(
        &state,
        &headers,
        Some(actor),
        "directory.source.created",
        &view.code,
        json!({ "kind": view.kind, "priority": view.priority }),
    )
    .await;
    Ok(Json(view))
}

async fn update_source(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
    Json(body): Json<UpdateSourceBody>,
) -> AppResult<Json<SourceView>> {
    let actor = require_admin(&state, &headers).await?;
    let existing = source::get_by_code(&state.pool, &code).await?;
    if existing.kind != body.kind {
        // Changing the kind would reinterpret `config` and orphan every existing
        // link, so it is not an update — create a new source instead.
        return Err(AppError::bad_request(format!(
            "kind cannot change (source is `{}`); create a new source instead",
            existing.kind
        )));
    }
    source::validate_payload(
        &code,
        &body.name,
        &body.kind,
        &body.config,
        body.ca_cert_pem
            .as_deref()
            .and_then(|pem| (!pem.trim().is_empty()).then_some(pem)),
        body.interval_minutes,
    )?;

    let parsed = source::SourceConfig::parse(&body.kind, &body.config)?;
    source::ensure_destination_allowed(&state, &parsed).await?;
    let credential_enc = source::encrypt_credential(&state, body.credential.as_deref());
    // A credential may be cleared only when the (possibly new) auth scheme does
    // not need one: flipping a Bearer source to `auth: none` while sending ""
    // must not be blocked by the same rule that stops an LDAP source from losing
    // its service account.
    if parsed.requires_credential()
        && credential_enc.is_none()
        && (body.credential.is_some() || existing.credential_enc.is_none())
    {
        return Err(AppError::bad_request(
            "credential is required: this source authenticates as a service account",
        ));
    }

    let view = sqlx::query_as::<_, SourceView>(&format!(
        r#"
        UPDATE directory_sources
        SET name = $2,
            enabled = $3,
            priority = $4,
            config = $5,
            credential_enc = CASE WHEN $6::bool THEN $7 ELSE credential_enc END,
            ca_cert_pem = CASE WHEN $8::bool THEN $9 ELSE ca_cert_pem END,
            sync_groups = $10,
            interval_minutes = $11,
            updated_at = NOW()
        WHERE code = $1
        RETURNING {SOURCE_VIEW_COLS}
        "#
    ))
    .bind(&code)
    .bind(body.name.trim())
    .bind(body.enabled)
    .bind(body.priority)
    .bind(&body.config)
    .bind(body.credential.is_some())
    .bind(&credential_enc)
    .bind(body.ca_cert_pem.is_some())
    .bind(body.ca_cert_pem.as_deref().and_then(non_empty_owned))
    .bind(body.sync_groups)
    .bind(body.interval_minutes)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found(format!("directory source not found: {code}")))?;

    audit(
        &state,
        &headers,
        Some(actor),
        "directory.source.updated",
        &view.code,
        json!({
            "kind": view.kind,
            "priority": view.priority,
            "enabled": view.enabled,
            "credential_rotated": body.credential.is_some(),
        }),
    )
    .await;
    Ok(Json(view))
}

async fn delete_source(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> AppResult<Json<Value>> {
    let actor = require_admin(&state, &headers).await?;
    let row = source::get_by_code(&state.pool, &code).await?;

    // Deleting a source cascades to its links, which would silently turn its
    // users from "directory-managed" into ordinary local accounts — including
    // their now-frozen attributes. Refuse while links exist so the operator has
    // to decide what happens to those users.
    let links: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM directory_entries WHERE source_id = $1")
            .bind(row.id)
            .fetch_one(&state.pool)
            .await?;
    if links > 0 {
        return Err(AppError::conflict(format!(
            "source `{code}` still manages {links} user(s); disable it instead, or remove \
             the links first"
        )));
    }

    sqlx::query("DELETE FROM directory_sources WHERE id = $1")
        .bind(row.id)
        .execute(&state.pool)
        .await?;

    // The same liveness sweep as disabling: a deleted source is not live either.
    // The `links > 0` guard above means this cannot be about the source's own
    // links — it is about claims already orphaned by links removed by hand, which
    // is exactly what this endpoint's error message invites the operator to do.
    // Without it those accounts stay disabled with no authority left to release
    // them (migration `026`).
    let released = crate::directory::release_orphaned_claims(&state.pool).await?;
    if released > 0 {
        tracing::info!(
            source = %code,
            released,
            "released orphaned directory disable claims"
        );
    }

    audit(
        &state,
        &headers,
        Some(actor),
        "directory.source.deleted",
        &code,
        json!({ "kind": row.kind }),
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

async fn set_enabled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
    Json(body): Json<EnabledBody>,
) -> AppResult<Json<SourceView>> {
    let actor = require_admin(&state, &headers).await?;
    let view = sqlx::query_as::<_, SourceView>(&format!(
        "UPDATE directory_sources SET enabled = $2, updated_at = NOW() \
         WHERE code = $1 RETURNING {SOURCE_VIEW_COLS}"
    ))
    .bind(&code)
    .bind(body.enabled)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found(format!("directory source not found: {code}")))?;

    // Switching a source off retires its authority, so the disable claims it was
    // holding go with it. Left in place they would outlive the source: an admin
    // enable cannot override an upstream claim, so those accounts would have no
    // way back (migration `026`).
    if !view.enabled {
        let released = crate::directory::release_orphaned_claims(&state.pool).await?;
        if released > 0 {
            tracing::info!(
                source = %view.code,
                released,
                "released directory disable claims from a disabled source"
            );
        }
    }

    audit(
        &state,
        &headers,
        Some(actor),
        if body.enabled {
            "directory.source.enabled"
        } else {
            "directory.source.disabled"
        },
        &view.code,
        json!({}),
    )
    .await;
    Ok(Json(view))
}

async fn trigger_sync(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> AppResult<Json<Value>> {
    let actor = require_admin(&state, &headers).await?;
    // Runs in the background; the run id lets the caller poll `/runs/{id}`.
    let run_id = engine::spawn_source(&state, &code, Trigger::Manual, Some(actor.id)).await?;
    Ok(Json(json!({ "run_id": run_id, "source": code })))
}

/// Checks a mapping against a pasted sample, before anything is saved.
///
/// Deliberately *not* audited: it writes nothing, reads nothing from the
/// database and holds no credential, and it is called on every mapping edit —
/// auditing it would bury the events that matter under keystroke traffic. The
/// source configuration it previews is audited when it is actually stored.
///
/// The sample is used in-memory only. It is never persisted and never logged:
/// it is a slice of the customer's directory, which is exactly the kind of thing
/// that should not end up in a log line.
async fn preview_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<mapping::PreviewRequest>,
) -> AppResult<Json<mapping::MappingPreview>> {
    require_admin(&state, &headers).await?;
    Ok(Json(mapping::preview(&body)?))
}

async fn list_runs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
    Query(q): Query<RunsQuery>,
) -> AppResult<Json<Vec<model::RunRow>>> {
    require_admin(&state, &headers).await?;
    Ok(Json(
        engine::recent_runs(&state, &code, q.limit.unwrap_or(20)).await?,
    ))
}

async fn get_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((code, id)): Path<(String, Uuid)>,
) -> AppResult<Json<model::RunRow>> {
    require_admin(&state, &headers).await?;
    let row = source::get_by_code(&state.pool, &code).await?;
    model::get_run(&state.pool, row.id, id)
        .await?
        .map(Json)
        .ok_or_else(|| AppError::not_found("run not found"))
}

async fn require_admin(state: &AppState, headers: &HeaderMap) -> AppResult<crate::models::User> {
    let actor = crate::auth::current_user(state, headers).await?;
    require_admin_role(&actor)?;
    Ok(actor)
}

async fn audit(
    state: &AppState,
    headers: &HeaderMap,
    actor: Option<crate::models::User>,
    action: &'static str,
    code: &str,
    detail: Value,
) {
    crate::audit::record(
        state,
        AuditEvent {
            actor,
            action,
            resource_type: "directory_source",
            resource_id: Some(code.to_string()),
            detail,
            ip: None,
            user_agent: crate::http::extract::user_agent(headers),
            client_id: None,
        },
    )
    .await;
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

fn non_empty_owned(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}
