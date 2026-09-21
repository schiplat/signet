use crate::auth::password::{hash_password, record_password_history};
use crate::auth::session::revoke_all_sessions;
use crate::error::{AppError, AppResult};
use crate::models::{insert_user, normalize_username, NewUser, User};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
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
        Some(p) if crate::crypto::util::sha256_hex(p) == stored_hash => Ok(()),
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

/// Projects a full [`User`] onto the SCIM read shape.
///
/// `ScimUserRow` stays a projection of its own because SCIM's list and get
/// paths select it directly; the insert no longer builds one, and this keeps
/// both feeding `user_resource` the same way. Every field lines up one-to-one,
/// so the conversion cannot lose a value — it is also why `USER_COLS` had to
/// carry `external_id`, without which the SCIM response would have no id to
/// echo back.
impl From<&User> for ScimUserRow {
    fn from(u: &User) -> Self {
        Self {
            id: u.id,
            email: u.email.clone(),
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            status: u.status.clone(),
            groups: u.groups.clone(),
            external_id: u.external_id.clone(),
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
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
        .unwrap_or_else(|| crate::crypto::util::random_token(24));
    let password_hash = hash_password(&password)?;
    let status = if body.active == Some(false) {
        "disabled"
    } else {
        "active"
    };

    let mut new_user = NewUser::new(id, &sub, &email, &display_name, &password_hash);
    // SCIM `active: false` provisions a disabled account, so this is the one
    // creation path that sets the status.
    new_user.status = status;
    new_user.username = Some(username.as_str());
    new_user.external_id = body
        .external_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let user = insert_user(&state.pool, &new_user)
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
    let row = ScimUserRow::from(&user);

    record_password_history(&state.pool, row.id, &password_hash).await?;

    crate::audit::record(
        &state,
        crate::audit::AuditEvent {
            actor: None,
            action: "scim.user.create",
            resource_type: "user",
            resource_id: Some(row.id.to_string()),
            detail: json!({ "email": row.email }),
            ip: None,
            user_agent: crate::http::extract::user_agent(&headers),
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

/// A SCIM PATCH body for users.
///
/// `Exposed for tests` — see [`user_attrs_from_body`].
#[derive(Debug, Deserialize)]
pub struct PatchUserBody {
    /// SCIM spells this `Operations`; RFC 7644's examples and every IdP surveyed
    /// send it capitalised, so the lowercase spelling is accepted as an alias
    /// rather than as the only name.
    ///
    /// This mattered more than it looks. `#[serde(default)]` means an
    /// unrecognised spelling deserialises to an *empty* list rather than an
    /// error, so with only `operations` accepted, a real client's body was
    /// discarded whole and the route answered `200` with the unchanged user —
    /// a PATCH that reported success and changed nothing.
    #[serde(default, rename = "Operations", alias = "operations")]
    operations: Vec<PatchOp>,
}

/// One SCIM PATCH operation.
///
/// `Exposed for tests` — the route is a thin wrapper over
/// [`user_attrs_from_patch`], and the interesting part is interpreting these.
#[derive(Debug, Deserialize)]
pub struct PatchOp {
    /// `add` / `remove` / `replace`. Absent on some clients' operations.
    #[serde(default)]
    op: String,
    /// `active`, `displayName`, or an attribute-qualified path. When present, the
    /// value is the attribute's new value; when absent, the value is an object
    /// carrying the attributes.
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    value: Value,
}

/// The user attributes a PATCH can change.
///
/// Only the attributes this route stores are modelled. `emails` and `userName`
/// are deliberately absent: writing them means deciding what a UNIQUE violation
/// means for a provisioning client, which is separate work (docs/directory-sync.md
/// §14).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct UserAttrs {
    /// `None` leaves `status` as it is.
    pub active: Option<bool>,
    /// `None` leaves `display_name` as it is.
    pub display_name: Option<String>,
}

/// Interprets RFC 7644 §3.5.2 operations into the attributes to write.
///
/// `Exposed for tests`; the handler is a thin wrapper over this.
///
/// Two things have to be right here, and both were wrong before:
///
/// * **`op` matters.** The field was not even deserialized, so `remove` was
///   treated as a write like any other. On the group route that inverted the
///   request (removing a member added them); here, `{"op":"remove","path":
///   "active"}` — one of the standard ways an IdP deprovisions — carried no
///   `value` and so silently did nothing at all.
/// * **`path` matters, and it changes the value's shape.** Okta sends
///   `{"op":"replace","value":{"active":false}}`; Entra sends
///   `{"op":"Replace","path":"active","value":false}` — a scalar. Reading only
///   the object form meant Entra's deactivation was accepted and ignored, which
///   is the worst kind of failure for a deprovisioning request: a 200 that did
///   not do it.
///
/// `op` is matched case-insensitively because Entra capitalises it (`Replace`)
/// while the RFC's examples are lowercase.
pub fn user_attrs_from_patch(ops: &[PatchOp]) -> AppResult<UserAttrs> {
    let mut attrs = UserAttrs::default();

    for op in ops {
        let name = normalize_op(&op.op)?;
        match op.path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
            Some(path) => match attribute_of(path).as_str() {
                "active" => match name {
                    // The RFC gives `active` a default of `true`, so unsetting it
                    // cannot mean "activate" — and deprovisioning by removing
                    // `active` is common enough that ignoring it is not an option.
                    "remove" => attrs.active = Some(false),
                    _ => attrs.active = Some(scalar_bool(&op.value, "active")?),
                },
                "displayname" => match name {
                    // `users.display_name` is NOT NULL, so there is nothing to
                    // unassign. Ignoring a `remove` is better than failing an
                    // IdP's sync over an attribute we cannot clear.
                    "remove" => {}
                    _ => attrs.display_name = Some(scalar_string(&op.value, "displayName")?),
                },
                // An attribute this route does not store (`name.givenName`,
                // `emails`, …). Ignored rather than rejected: a PATCH routinely
                // carries attributes we have no column for, and 400ing the whole
                // operation would fail the rest of the sync.
                _ => {}
            },
            // No `path`: the value object carries the attributes. This is the
            // shape Okta uses.
            None => {
                if let Some(obj) = op.value.as_object() {
                    if let Some(v) = obj.get("active") {
                        attrs.active = Some(coerce_bool(v, "active")?);
                    }
                    if let Some(v) = obj.get("displayName") {
                        let s = v.as_str().ok_or_else(|| not_a_string("displayName", v))?;
                        attrs.display_name = Some(s.trim().to_string());
                    }
                }
            }
        }
    }

    Ok(attrs)
}

/// The attributes to write for a PATCH body, as the route receives it.
///
/// `Exposed for tests`: this is the boundary where the body's field *names*
/// matter, and where a misspelled one degrades to "no operations" instead of an
/// error (see [`PatchUserBody`]).
pub fn user_attrs_from_body(body: PatchUserBody) -> AppResult<UserAttrs> {
    user_attrs_from_patch(&body.operations)
}

/// Lowercases and validates `op`, defaulting a missing one to `replace`.
///
/// An unrecognised operation is rejected rather than guessed at: the whole
/// problem this function exists to fix is operations being treated as something
/// they are not.
fn normalize_op(op: &str) -> AppResult<&'static str> {
    match op.trim().to_ascii_lowercase().as_str() {
        "" | "replace" => Ok("replace"),
        "add" => Ok("add"),
        "remove" => Ok("remove"),
        other => Err(AppError::bad_request(format!(
            "unsupported PATCH op `{other}`; expected add, remove or replace"
        ))),
    }
}

/// The attribute a `path` names, lowercased, with any schema URN or sub-attribute
/// selector removed.
///
/// `urn:ietf:params:scim:schemas:core:2.0:User:active` and `emails[type eq
/// "work"].value` both have to reduce to `active` and `emails` respectively.
fn attribute_of(path: &str) -> String {
    let path = path.trim();
    let path = path.rsplit(':').next().unwrap_or(path);
    let path = path.split(['[', '.']).next().unwrap_or(path);
    path.trim().to_ascii_lowercase()
}

/// Reads a boolean sent as the direct `value` of a path-qualified operation.
fn scalar_bool(value: &Value, attribute: &str) -> AppResult<bool> {
    coerce_bool(value, attribute)
}

/// Accepts a real boolean and the string spellings some clients send.
fn coerce_bool(value: &Value, attribute: &str) -> AppResult<bool> {
    match value {
        Value::Bool(b) => Ok(*b),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(AppError::bad_request(format!(
                "`{attribute}` must be a boolean, got `{s}`"
            ))),
        },
        other => Err(AppError::bad_request(format!(
            "`{attribute}` must be a boolean, got {other}"
        ))),
    }
}

fn scalar_string(value: &Value, attribute: &str) -> AppResult<String> {
    value
        .as_str()
        .map(|s| s.trim().to_string())
        .ok_or_else(|| not_a_string(attribute, value))
}

fn not_a_string(attribute: &str, value: &Value) -> AppError {
    AppError::bad_request(format!("`{attribute}` must be a string, got {value}"))
}

async fn patch_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<PatchUserBody>,
) -> AppResult<Json<Value>> {
    authorize(&state, &headers).await?;
    let existing = find_user(&state, &id).await?;

    // Attributes the PATCH did not mention keep their current value — a PATCH is
    // partial by definition, so "absent" must not be read as "set to default".
    let attrs = user_attrs_from_body(body)?;
    let active = attrs.active.unwrap_or(existing.status == "active");
    let display_name = attrs
        .display_name
        .unwrap_or_else(|| existing.display_name.clone());

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
) -> AppResult<StatusCode> {
    authorize(&state, &headers).await?;
    let existing = find_user(&state, &id).await?;

    revoke_all_sessions(&state.pool, existing.id).await?;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(existing.id)
        .execute(&state.pool)
        .await?;

    crate::audit::record(
        &state,
        crate::audit::AuditEvent {
            actor: None,
            action: "scim.user.delete",
            resource_type: "user",
            resource_id: Some(existing.id.to_string()),
            detail: json!({ "email": existing.email }),
            ip: None,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    // 204, not `200` with a body. RFC 7644 §3.6 defines DELETE success as `204 No
    // Content`; the previous response was worse than merely non-conformant — it
    // was a `200` carrying a `2.0:Error` schema, telling a conforming client both
    // "this worked" and "this failed" at once.
    Ok(StatusCode::NO_CONTENT)
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

/// A SCIM PATCH body for groups. `Exposed for tests`; see [`group_member_changes_from_body`].
#[derive(Debug, Deserialize)]
pub struct PatchGroupBody {
    /// `Operations`, for the same reason as on the user body.
    #[serde(default, rename = "Operations", alias = "operations")]
    operations: Vec<GroupPatchOp>,
}

/// One SCIM PATCH operation on a group.
///
/// `Exposed for tests` — see [`group_member_changes`].
#[derive(Debug, Deserialize)]
pub struct GroupPatchOp {
    /// `add` / `remove` / `replace`.
    #[serde(default)]
    op: String,
    /// Usually `members`, optionally with a value filter:
    /// `members[value eq "<id>"]`.
    #[serde(default)]
    path: Option<String>,
    /// Present on `add` and `replace`; often absent on `remove`, which may name
    /// the member in `path` instead.
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

/// What a group PATCH asks of the membership.
#[derive(Debug, PartialEq, Eq)]
pub enum GroupMemberChange {
    Add(Vec<Uuid>),
    /// An empty list means "every member" — `remove` on `members` with nothing
    /// selecting a particular member.
    Remove(Vec<Uuid>),
    /// The membership becomes exactly this list.
    Replace(Vec<Uuid>),
}

/// Interprets group PATCH operations into membership changes.
///
/// `Exposed for tests`; the handler is a thin wrapper over this.
///
/// The `op` was previously ignored entirely and every operation was applied as
/// an add, so `{"op":"remove","path":"members[value eq \"<id>\"]"}` — Okta's way
/// of removing one member — **added** that member to the group. Returned as
/// changes rather than applied directly so the interpretation can be tested
/// without a database, and so the handler stays a short list of SQL calls.
pub fn group_member_changes(ops: &[GroupPatchOp]) -> AppResult<Vec<GroupMemberChange>> {
    let mut changes = Vec::new();

    for op in ops {
        let ids = member_ids(op);
        match normalize_op(&op.op)? {
            "add" => changes.push(GroupMemberChange::Add(ids)),
            "replace" => changes.push(GroupMemberChange::Replace(ids)),
            // No ids and no filter: the operation is "clear the members".
            _ => changes.push(GroupMemberChange::Remove(ids)),
        }
    }

    Ok(changes)
}

/// The membership changes a group PATCH body asks for.
///
/// `Exposed for tests`, and the counterpart of [`user_attrs_from_body`]: a body
/// whose `Operations` was not recognised arrives here as an empty list, so this is
/// where "the client's operations were read at all" is pinned down.
pub fn group_member_changes_from_body(body: PatchGroupBody) -> AppResult<Vec<GroupMemberChange>> {
    group_member_changes(&body.operations)
}

/// The user ids an operation names, from the `value` array or the `path` filter.
fn member_ids(op: &GroupPatchOp) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = op
        .value
        .iter()
        .filter_map(|m| m.value.as_deref())
        .filter_map(|v| Uuid::parse_str(v.trim()).ok())
        .collect();

    if ids.is_empty() {
        if let Some(from_filter) = op
            .path
            .as_deref()
            .and_then(filter_value)
            .and_then(|v| Uuid::parse_str(v.trim()).ok())
        {
            ids.push(from_filter);
        }
    }

    ids
}

/// The id in a SCIM value filter, as in `members[value eq "3f1b…"]`.
///
/// Okta removes a single member with no `value` array on the operation at all, so
/// without reading the filter a removal is indistinguishable from "remove
/// everyone" — the difference between dropping one member and dropping the group's
/// entire membership.
fn filter_value(path: &str) -> Option<String> {
    const NEEDLE: &str = "value eq";

    let at = path.to_ascii_lowercase().find(NEEDLE)?;
    let rest = path[at + NEEDLE.len()..].trim_start();
    // Both quote styles appear in the wild; SCIM's examples use `"`.
    let quote = rest.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let rest = &rest[quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

async fn patch_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<PatchGroupBody>,
) -> AppResult<Json<Value>> {
    authorize(&state, &headers).await?;
    let group = find_group(&state, &id).await?;

    for change in group_member_changes_from_body(body)? {
        match change {
            GroupMemberChange::Add(ids) => {
                for user_id in ids {
                    add_group_to_user(&state, user_id, &group.display_name).await?;
                }
            }
            GroupMemberChange::Remove(ids) if ids.is_empty() => {
                clear_group(&state, &group.display_name).await?;
            }
            GroupMemberChange::Remove(ids) => {
                for user_id in ids {
                    remove_group_from_user(&state, user_id, &group.display_name).await?;
                }
            }
            GroupMemberChange::Replace(ids) => {
                clear_group(&state, &group.display_name).await?;
                for user_id in ids {
                    add_group_to_user(&state, user_id, &group.display_name).await?;
                }
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

async fn remove_group_from_user(
    state: &AppState,
    user_id: Uuid,
    group_name: &str,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE users SET groups = array_remove(groups, $2), updated_at = NOW() WHERE id = $1",
    )
    .bind(user_id)
    .bind(group_name)
    .execute(&state.pool)
    .await?;
    Ok(())
}

/// Drops `group_name` from every user that carries it.
async fn clear_group(state: &AppState, group_name: &str) -> AppResult<()> {
    sqlx::query(
        "UPDATE users SET groups = array_remove(groups, $1), updated_at = NOW() WHERE $1 = ANY(groups)",
    )
    .bind(group_name)
    .execute(&state.pool)
    .await?;
    Ok(())
}

async fn delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    authorize(&state, &headers).await?;
    let group = find_group(&state, &id).await?;

    clear_group(&state, &group.display_name).await?;

    sqlx::query("DELETE FROM scim_groups WHERE id = $1")
        .bind(group.id)
        .execute(&state.pool)
        .await?;

    // 204 for the same reason as `delete_user`: RFC 7644 §3.6, and a `200` with
    // an Error schema is a contradiction rather than an answer.
    Ok(StatusCode::NO_CONTENT)
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
