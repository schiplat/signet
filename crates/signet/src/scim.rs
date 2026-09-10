use crate::error::{AppError, AppResult};
use crate::models::normalize_username;
use crate::password::{hash_password, record_password_history};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/scim/v2/Users", get(list_users).post(create_user))
        .route(
            "/scim/v2/Users/{id}",
            get(get_user)
                .put(put_user)
                .patch(patch_user)
                .delete(delete_user),
        )
        .route("/scim/v2/Groups", get(list_groups).post(create_group))
        .route(
            "/scim/v2/Groups/{id}",
            get(get_group).patch(patch_group).delete(delete_group),
        )
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(service_provider_config),
        )
}

/// Enforce the SCIM bearer token. Returns 401 when SCIM has no configured token.
async fn authorize(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT token_hash FROM scim_config WHERE id = TRUE")
            .fetch_optional(&state.pool)
            .await?
            .flatten();

    let Some(stored_hash) = stored else {
        return Err(AppError::unauthorized("SCIM is not configured"));
    };

    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);

    match provided {
        Some(p) if crate::crypto_util::sha256_hex(p) == stored_hash => Ok(()),
        _ => Err(AppError::unauthorized("invalid SCIM bearer token")),
    }
}

// --- Users ---

#[derive(Debug, sqlx::FromRow)]
struct ScimUserRow {
    id: Uuid,
    email: String,
    username: Option<String>,
    display_name: String,
    status: String,
    groups: Vec<String>,
    external_id: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

fn user_resource(u: &ScimUserRow) -> Value {
    json!({
        "schemas": [USER_SCHEMA],
        "id": u.id.to_string(),
        "externalId": u.external_id,
        "userName": u.username.as_deref().unwrap_or(&u.email),
        "displayName": u.display_name,
        "name": { "formatted": u.display_name },
        "active": u.status == "active",
        "emails": [{ "value": u.email, "primary": true }],
        "groups": u.groups.iter().map(|g| json!({ "value": g, "display": g })).collect::<Vec<_>>(),
        "meta": {
            "resourceType": "User",
            "created": u.created_at.to_rfc3339(),
            "lastModified": u.updated_at.to_rfc3339(),
        },
    })
}

const USER_SELECT: &str =
    "id, email, username, display_name, status, groups, external_id, created_at, updated_at";

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default)]
    pub start_index: Option<i64>,
    #[serde(default)]
    pub count: Option<i64>,
}

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Value>> {
    authorize(&state, &headers).await?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.pool)
        .await?;
    let rows = sqlx::query_as::<_, ScimUserRow>(&format!(
        "SELECT {USER_SELECT} FROM users ORDER BY created_at ASC LIMIT $1 OFFSET $2"
    ))
    .bind(q.count.unwrap_or(100).clamp(1, 1000))
    .bind(q.start_index.unwrap_or(1).max(1) - 1)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "itemsPerPage": rows.len(),
        "startIndex": q.start_index.unwrap_or(1),
        "Resources": rows.iter().map(user_resource).collect::<Vec<_>>(),
    })))
}

#[derive(Debug, Deserialize)]
struct EmailAttr {
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    primary: Option<bool>,
}

/// Picks the primary email from a SCIM `emails` array (falling back to the
/// first non-empty value), normalized for storage.
fn primary_email(emails: &[EmailAttr]) -> Option<String> {
    let pick = emails
        .iter()
        .filter(|e| e.value.as_deref().is_some_and(|v| !v.trim().is_empty()))
        .find(|e| e.primary == Some(true))
        .or_else(|| {
            emails
                .iter()
                .find(|e| e.value.as_deref().is_some_and(|v| !v.trim().is_empty()))
        });
    pick.and_then(|e| e.value.as_deref())
        .map(|v| v.trim().to_lowercase())
}

#[derive(Debug, Deserialize)]
struct CreateUserBody {
    #[serde(rename = "userName")]
    user_name: String,
    #[serde(rename = "displayName", default)]
    display_name: Option<String>,
    #[serde(rename = "externalId", default)]
    external_id: Option<String>,
    #[serde(default)]
    active: Option<bool>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    emails: Vec<EmailAttr>,
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateUserBody>,
) -> AppResult<Json<Value>> {
    authorize(&state, &headers).await?;
    let username = body.user_name.trim().to_lowercase();
    if username.is_empty() {
        return Err(AppError::bad_request("userName is required"));
    }
    let email = primary_email(&body.emails).unwrap_or_else(|| username.clone());

    // Enforce uniqueness across both identifier namespaces so login stays
    // unambiguous (a username must not equal any email and vice versa).
    let username_exists: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = $1 OR email = $1")
            .bind(&username)
            .fetch_one(&state.pool)
            .await?;
    if username_exists > 0 {
        return Err(AppError::bad_request("userName already exists"));
    }
    if email != username {
        let email_exists: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1 OR username = $1")
                .bind(&email)
                .fetch_one(&state.pool)
                .await?;
        if email_exists > 0 {
            return Err(AppError::bad_request("email already exists"));
        }
    }

    let display_name = body
        .display_name
        .clone()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| username.clone());

    let id = Uuid::new_v4();
    let sub = id.to_string();
    let password = body
        .password
        .unwrap_or_else(|| crate::crypto_util::random_token(24));
    let password_hash = hash_password(&password)?;
    let status = if body.active == Some(false) {
        "disabled"
    } else {
        "active"
    };

    let row = sqlx::query_as::<_, ScimUserRow>(&format!(
        r#"
        INSERT INTO users (id, sub, email, username, display_name, password_hash, status, role, groups, phone, external_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'user', ARRAY[]::text[], NULL, $8, NOW(), NOW())
        RETURNING {USER_SELECT}
        "#
    ))
    .bind(id)
    .bind(&sub)
    .bind(&email)
    .bind(&username)
    .bind(&display_name)
    .bind(&password_hash)
    .bind(status)
    .bind(body.external_id.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("users_email_key") => {
            AppError::bad_request("email already exists")
        }
        sqlx::Error::Database(db) if db.constraint() == Some("users_username_key") => {
            AppError::bad_request("userName already exists")
        }
        sqlx::Error::Database(db) if db.constraint() == Some("users_external_id_key") => {
            AppError::bad_request("externalId already exists")
        }
        other => AppError::from(other),
    })?;

    record_password_history(&state.pool, row.id, &password_hash).await?;

    crate::audit::record(
        &state.pool,
        crate::audit::AuditEvent {
            actor: None,
            action: "scim.user.create",
            resource_type: "user",
            resource_id: Some(row.id.to_string()),
            detail: json!({ "email": row.email }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(user_resource(&row)))
}

async fn get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    authorize(&state, &headers).await?;
    let row = find_user(&state, &id).await?;
    Ok(Json(user_resource(&row)))
}

async fn find_user(state: &AppState, id: &str) -> AppResult<ScimUserRow> {
    if let Ok(uuid) = Uuid::parse_str(id) {
        if let Some(r) = sqlx::query_as::<_, ScimUserRow>(&format!(
            "SELECT {USER_SELECT} FROM users WHERE id = $1"
        ))
        .bind(uuid)
        .fetch_optional(&state.pool)
        .await?
        {
            return Ok(r);
        }
    }
    sqlx::query_as::<_, ScimUserRow>(&format!(
        "SELECT {USER_SELECT} FROM users WHERE external_id = $1 OR email = $1 OR username = $1"
    ))
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("user not found".into()))
}

#[derive(Debug, Deserialize)]
struct PutUserBody {
    #[serde(rename = "userName", default)]
    user_name: Option<String>,
    #[serde(rename = "displayName", default)]
    display_name: Option<String>,
    #[serde(rename = "externalId", default)]
    external_id: Option<String>,
    #[serde(default)]
    active: Option<bool>,
    #[serde(default)]
    emails: Vec<EmailAttr>,
}

async fn put_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<PutUserBody>,
) -> AppResult<Json<Value>> {
    authorize(&state, &headers).await?;
    let existing = find_user(&state, &id).await?;

    let username = normalize_username(body.user_name.as_deref());
    let email = primary_email(&body.emails);
    let display_name = body.display_name.map(|s| s.trim().to_string());
    let status = body.active.map(|a| if a { "active" } else { "disabled" });

    if let Some(u) = &username {
        if existing.username.as_deref() != Some(u.as_str()) {
            let n: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM users WHERE (username = $1 OR email = $1) AND id <> $2",
            )
            .bind(u)
            .bind(existing.id)
            .fetch_one(&state.pool)
            .await?;
            if n > 0 {
                return Err(AppError::bad_request("userName already exists"));
            }
        }
    }
    if let Some(e) = &email {
        if existing.email != *e {
            let n: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM users WHERE (email = $1 OR username = $1) AND id <> $2",
            )
            .bind(e)
            .bind(existing.id)
            .fetch_one(&state.pool)
            .await?;
            if n > 0 {
                return Err(AppError::bad_request("email already exists"));
            }
        }
    }

    let row = sqlx::query_as::<_, ScimUserRow>(&format!(
        r#"
        UPDATE users SET
            email = COALESCE($2, email),
            username = COALESCE($3, username),
            display_name = COALESCE($4, display_name),
            status = COALESCE($5, status),
            external_id = $6,
            updated_at = NOW()
        WHERE id = $1
        RETURNING {USER_SELECT}
        "#
    ))
    .bind(existing.id)
    .bind(email.as_deref())
    .bind(username.as_deref())
    .bind(display_name.as_deref())
    .bind(status)
    .bind(
        body.external_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("users_email_key") => {
            AppError::bad_request("email already exists")
        }
        sqlx::Error::Database(db) if db.constraint() == Some("users_username_key") => {
            AppError::bad_request("userName already exists")
        }
        sqlx::Error::Database(db) if db.constraint() == Some("users_external_id_key") => {
            AppError::bad_request("externalId already exists")
        }
        other => AppError::from(other),
    })?;

    Ok(Json(user_resource(&row)))
}

#[derive(Debug, Deserialize)]
struct PatchUserBody {
    #[serde(default)]
    operations: Vec<PatchOp>,
}

#[derive(Debug, Deserialize)]
struct PatchOp {
    #[serde(default)]
    value: Value,
}

async fn patch_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<PatchUserBody>,
) -> AppResult<Json<Value>> {
    authorize(&state, &headers).await?;
    let existing = find_user(&state, &id).await?;

    let mut active = existing.status == "active";
    let mut display_name = existing.display_name.clone();
    for op in &body.operations {
        if let Some(a) = op.value.get("active").and_then(|v| v.as_bool()) {
            active = a;
        }
        if let Some(d) = op.value.get("displayName").and_then(|v| v.as_str()) {
            display_name = d.trim().to_string();
        }
    }

    let row = sqlx::query_as::<_, ScimUserRow>(&format!(
        "UPDATE users SET status = $2, display_name = $3, updated_at = NOW() WHERE id = $1 RETURNING {USER_SELECT}"
    ))
    .bind(existing.id)
    .bind(if active { "active" } else { "disabled" })
    .bind(&display_name)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(user_resource(&row)))
}

async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    authorize(&state, &headers).await?;
    let existing = find_user(&state, &id).await?;

    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(existing.id)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(existing.id)
        .execute(&state.pool)
        .await?;

    crate::audit::record(
        &state.pool,
        crate::audit::AuditEvent {
            actor: None,
            action: "scim.user.delete",
            resource_type: "user",
            resource_id: Some(existing.id.to_string()),
            detail: json!({ "email": existing.email }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(
        json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"] }),
    ))
}

// --- Groups ---

#[derive(Debug, sqlx::FromRow)]
struct ScimGroupRow {
    id: Uuid,
    display_name: String,
    external_id: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

fn group_resource(g: &ScimGroupRow, members: Vec<Value>) -> Value {
    json!({
        "schemas": [GROUP_SCHEMA],
        "id": g.id.to_string(),
        "externalId": g.external_id,
        "displayName": g.display_name,
        "members": members,
        "meta": {
            "resourceType": "Group",
            "created": g.created_at.to_rfc3339(),
            "lastModified": g.updated_at.to_rfc3339(),
        },
    })
}

async fn group_members(state: &AppState, name: &str) -> AppResult<Vec<Value>> {
    let rows: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, email FROM users WHERE $1 = ANY(groups) ORDER BY email")
            .bind(name)
            .fetch_all(&state.pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|(id, email)| json!({ "value": id.to_string(), "display": email }))
        .collect())
}

async fn list_groups(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    authorize(&state, &headers).await?;
    let rows = sqlx::query_as::<_, ScimGroupRow>(
        "SELECT id, display_name, external_id, created_at, updated_at FROM scim_groups ORDER BY display_name",
    )
    .fetch_all(&state.pool)
    .await?;

    let mut resources = Vec::new();
    for g in &rows {
        let members = group_members(&state, &g.display_name).await?;
        resources.push(group_resource(g, members));
    }

    Ok(Json(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": rows.len(),
        "Resources": resources,
    })))
}

#[derive(Debug, Deserialize)]
struct CreateGroupBody {
    #[serde(rename = "displayName")]
    display_name: String,
    #[serde(rename = "externalId", default)]
    external_id: Option<String>,
}

async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateGroupBody>,
) -> AppResult<Json<Value>> {
    authorize(&state, &headers).await?;
    let name = body.display_name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::bad_request("displayName required"));
    }

    let row = sqlx::query_as::<_, ScimGroupRow>(
        r#"
        INSERT INTO scim_groups (id, display_name, external_id) VALUES ($1, $2, $3)
        RETURNING id, display_name, external_id, created_at, updated_at
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&name)
    .bind(
        body.external_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("scim_groups_display_name_key") => {
            AppError::bad_request("group already exists")
        }
        other => AppError::from(other),
    })?;

    Ok(Json(group_resource(&row, vec![])))
}

async fn get_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    authorize(&state, &headers).await?;
    let row = find_group(&state, &id).await?;
    let members = group_members(&state, &row.display_name).await?;
    Ok(Json(group_resource(&row, members)))
}

async fn find_group(state: &AppState, id: &str) -> AppResult<ScimGroupRow> {
    if let Ok(uuid) = Uuid::parse_str(id) {
        if let Some(r) = sqlx::query_as::<_, ScimGroupRow>(
            "SELECT id, display_name, external_id, created_at, updated_at FROM scim_groups WHERE id = $1",
        )
        .bind(uuid)
        .fetch_optional(&state.pool)
        .await?
        {
            return Ok(r);
        }
    }
    sqlx::query_as::<_, ScimGroupRow>(
        "SELECT id, display_name, external_id, created_at, updated_at FROM scim_groups WHERE display_name = $1 OR external_id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("group not found".into()))
}

#[derive(Debug, Deserialize)]
struct PatchGroupBody {
    #[serde(default)]
    operations: Vec<GroupPatchOp>,
}

#[derive(Debug, Deserialize)]
struct GroupPatchOp {
    #[serde(default)]
    value: Vec<GroupMemberRef>,
}

#[derive(Debug, Deserialize)]
struct GroupMemberRef {
    #[serde(default)]
    value: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    display: Option<String>,
}

async fn patch_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<PatchGroupBody>,
) -> AppResult<Json<Value>> {
    authorize(&state, &headers).await?;
    let group = find_group(&state, &id).await?;

    for op in &body.operations {
        for m in &op.value {
            let user_id = m.value.as_ref().and_then(|v| Uuid::parse_str(v).ok());
            if let Some(user_id) = user_id {
                add_group_to_user(&state, user_id, &group.display_name).await?;
            }
        }
    }

    let members = group_members(&state, &group.display_name).await?;
    Ok(Json(group_resource(&group, members)))
}

async fn add_group_to_user(state: &AppState, user_id: Uuid, group_name: &str) -> AppResult<()> {
    sqlx::query(
        "UPDATE users SET groups = ARRAY(SELECT DISTINCT unnest(array_append(groups, $2))), updated_at = NOW() WHERE id = $1",
    )
    .bind(user_id)
    .bind(group_name)
    .execute(&state.pool)
    .await?;
    Ok(())
}

async fn delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    authorize(&state, &headers).await?;
    let group = find_group(&state, &id).await?;

    sqlx::query(
        "UPDATE users SET groups = array_remove(groups, $2), updated_at = NOW() WHERE $2 = ANY(groups)",
    )
    .bind(group.id)
    .bind(&group.display_name)
    .execute(&state.pool)
    .await?;

    sqlx::query("DELETE FROM scim_groups WHERE id = $1")
        .bind(group.id)
        .execute(&state.pool)
        .await?;

    Ok(Json(
        json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"] }),
    ))
}

async fn service_provider_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    authorize(&state, &headers).await?;
    Ok(Json(json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": false, "maxResults": 100 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{ "name": "OAuth Bearer Token", "type": "oauthbearertoken" }],
    })))
}
