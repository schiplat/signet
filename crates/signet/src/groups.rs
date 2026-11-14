//! Group and department management for the dashboard.
//!
//! Groups live in `scim_groups` (one row per group, tombstoned on delete) and
//! membership lives in `users.groups` as ids. This module owns the dashboard
//! side of that model: the organisational tree, node metadata (`kind`) and
//! local membership. SCIM and directory sync write the same rows; `source`
//! records who owns them so the dashboard cannot rename or delete a group an
//! IdP or directory still controls.
//!
//! Read shape is names, storage is ids: `signet_group_names()` translates on
//! every read (see migration 043), so the API, the OIDC claim and SCIM keep
//! seeing display names while a rename is a single UPDATE.

use crate::admin::{require_admin_user, require_staff_user};
use crate::audit::{record, AuditEvent};
use crate::error::{AppError, AppResult};
use crate::http::extract::AuditIp;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/groups", get(list_groups).post(create_group))
        .route("/admin/groups/{id}", put(update_group).delete(delete_group))
        .route(
            "/admin/groups/{id}/members",
            get(list_members).post(add_members),
        )
        .route(
            "/admin/groups/{id}/members/{user_id}",
            delete(remove_member),
        )
}

const NAME_MAX: usize = 200;

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct AdminGroup {
    pub id: Uuid,
    pub display_name: String,
    pub parent_id: Option<Uuid>,
    pub kind: String,
    pub source: String,
    pub member_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const GROUP_SELECT: &str = r#"
    SELECT g.id, g.display_name, g.parent_id, g.kind, g.source,
           (SELECT COUNT(*) FROM users u WHERE u.groups @> ARRAY[g.id]) AS member_count,
           g.created_at, g.updated_at
    FROM scim_groups g
"#;

fn normalize_name(raw: &str) -> AppResult<String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(AppError::bad_request("name is required"));
    }
    if name.chars().count() > NAME_MAX {
        return Err(AppError::bad_request(format!(
            "name must be at most {NAME_MAX} characters"
        )));
    }
    Ok(name.to_string())
}

fn parse_kind(raw: Option<&str>) -> AppResult<String> {
    match raw {
        None => Ok("group".into()),
        Some("group") => Ok("group".into()),
        Some("department") => Ok("department".into()),
        Some(_) => Err(AppError::bad_request("kind must be group or department")),
    }
}

/// A group that exists and is not tombstoned, or 404.
async fn load_group(state: &AppState, id: Uuid) -> AppResult<AdminGroup> {
    sqlx::query_as::<_, AdminGroup>(&format!(
        "{GROUP_SELECT} WHERE g.id = $1 AND g.deleted_at IS NULL"
    ))
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("group not found".into()))
}

/// Rejects `parent` when it is `group` itself or anywhere in its subtree.
///
/// The tree is an adjacency list; a cycle would make every ancestor/breadcrumb
/// walk non-terminating and would hide the subtree from the root view. The
/// database CHECK only stops the one-node cycle, so the deeper case is checked
/// here, inside the same transaction as the move.
async fn assert_no_cycle(state: &AppState, group: Uuid, parent: Uuid) -> AppResult<()> {
    if group == parent {
        return Err(AppError::bad_request("a group cannot be its own parent"));
    }
    let is_descendant: bool = sqlx::query_scalar(
        r#"
        WITH RECURSIVE down AS (
            SELECT id FROM scim_groups WHERE parent_id = $1 AND deleted_at IS NULL
            UNION ALL
            SELECT g.id FROM scim_groups g
            JOIN down d ON g.parent_id = d.id
            WHERE g.deleted_at IS NULL
        )
        SELECT EXISTS(SELECT 1 FROM down WHERE id = $2)
        "#,
    )
    .bind(group)
    .bind(parent)
    .fetch_one(&state.pool)
    .await?;
    if is_descendant {
        return Err(AppError::bad_request(
            "cannot move a group under its own descendant",
        ));
    }
    Ok(())
}

async fn require_live_parent(state: &AppState, parent: Uuid) -> AppResult<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM scim_groups WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(parent)
    .fetch_one(&state.pool)
    .await?;
    if !exists {
        return Err(AppError::bad_request("parent group not found"));
    }
    Ok(())
}

async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<AdminGroup>>> {
    require_staff_user(&state, &headers).await?;
    let rows = sqlx::query_as::<_, AdminGroup>(&format!(
        "{GROUP_SELECT} WHERE g.deleted_at IS NULL ORDER BY g.display_name"
    ))
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

#[derive(Debug, Deserialize)]
struct CreateGroupBody {
    name: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    parent_id: Option<Uuid>,
}

async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Json(body): Json<CreateGroupBody>,
) -> AppResult<Json<AdminGroup>> {
    let actor = require_staff_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);
    let name = normalize_name(&body.name)?;
    let kind = parse_kind(body.kind.as_deref())?;
    if let Some(parent) = body.parent_id {
        require_live_parent(&state, parent).await?;
    }

    let id = Uuid::new_v4();
    let row = sqlx::query_as::<_, AdminGroup>(
        r#"
        INSERT INTO scim_groups (id, display_name, parent_id, kind, source)
        VALUES ($1, $2, $3, $4, 'local')
        RETURNING id, display_name, parent_id, kind, source,
                  0::bigint AS member_count, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(&name)
    .bind(body.parent_id)
    .bind(&kind)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db)
            if db.constraint() == Some("scim_groups_live_display_name_key") =>
        {
            AppError::conflict("a group with this name already exists")
        }
        other => AppError::from(other),
    })?;

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "group.create",
            resource_type: "group",
            resource_id: Some(row.id.to_string()),
            detail: json!({
                "name": row.display_name,
                "kind": row.kind,
                "parent_id": row.parent_id,
            }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(row))
}

#[derive(Debug, Deserialize)]
struct UpdateGroupBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    /// Move under this parent. Absent means "keep the current parent".
    #[serde(default)]
    parent_id: Option<Uuid>,
    /// Explicitly move to the root; `parent_id: null` cannot express that
    /// because an absent field already means "keep".
    #[serde(default)]
    clear_parent: bool,
}

async fn update_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateGroupBody>,
) -> AppResult<Json<AdminGroup>> {
    let actor = require_staff_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);
    let before = load_group(&state, id).await?;

    let name = match &body.name {
        Some(raw) => {
            let next = normalize_name(raw)?;
            if next != before.display_name && before.source != "local" {
                return Err(AppError::conflict(
                    "this group is owned by SCIM or a directory source; its name cannot be changed here",
                ));
            }
            next
        }
        None => before.display_name.clone(),
    };
    let kind = match &body.kind {
        Some(raw) => parse_kind(Some(raw))?,
        None => before.kind.clone(),
    };
    let parent_id = if body.clear_parent {
        None
    } else if let Some(parent) = body.parent_id {
        require_live_parent(&state, parent).await?;
        assert_no_cycle(&state, id, parent).await?;
        Some(parent)
    } else {
        before.parent_id
    };

    let row = sqlx::query_as::<_, AdminGroup>(
        "UPDATE scim_groups
         SET display_name = $2, kind = $3, parent_id = $4, updated_at = NOW()
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING id, display_name, parent_id, kind, source,
                   0::bigint AS member_count, created_at, updated_at",
    )
    .bind(id)
    .bind(&name)
    .bind(&kind)
    .bind(parent_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db)
            if db.constraint() == Some("scim_groups_live_display_name_key") =>
        {
            AppError::conflict("a group with this name already exists")
        }
        other => AppError::from(other),
    })?
    .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    // member_count from the RETURNING is a placeholder: the row just changed
    // metadata, not membership. Re-read it so the response matches the list.
    let row = load_group(&state, row.id).await?;

    let changed = json!({
        "name": if name != before.display_name { Some(&name) } else { None },
        "kind": if kind != before.kind { Some(&kind) } else { None },
        "parent_id": if parent_id != before.parent_id { Some(parent_id) } else { None::<Option<Uuid>> },
    });
    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "group.update",
            resource_type: "group",
            resource_id: Some(row.id.to_string()),
            detail: json!({
                "before": {
                    "name": before.display_name,
                    "kind": before.kind,
                    "parent_id": before.parent_id,
                },
                "after": {
                    "name": row.display_name,
                    "kind": row.kind,
                    "parent_id": row.parent_id,
                },
                "changed": changed,
            }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(row))
}

async fn delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_admin_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);
    let group = load_group(&state, id).await?;

    // A group the IdP or a directory still owns comes back on the next sync;
    // deleting it here would look like it worked and then reappear.
    if group.source != "local" {
        return Err(AppError::conflict(
            "this group is owned by SCIM or a directory source; remove it there instead",
        ));
    }

    let mut tx = state.pool.begin().await?;
    let members: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE groups @> ARRAY[$1::uuid] ORDER BY email")
            .bind(id)
            .fetch_all(&mut *tx)
            .await?;
    sqlx::query(
        "UPDATE users SET groups = array_remove(groups, $1::uuid), updated_at = NOW() \
                 WHERE groups @> ARRAY[$1::uuid]",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    // Children move up rather than being deleted: the subtree below a group is
    // usually the more valuable half.
    let moved = sqlx::query(
        "UPDATE scim_groups SET parent_id = $2, updated_at = NOW() \
         WHERE parent_id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .bind(group.parent_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    sqlx::query(
        "UPDATE scim_groups SET deleted_at = NOW(), members_at_delete = $2, updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(id)
    .bind(&members)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "group.delete",
            resource_type: "group",
            resource_id: Some(id.to_string()),
            detail: json!({
                "name": group.display_name,
                "kind": group.kind,
                "parent_id": group.parent_id,
                "released_members": members.len(),
                "children_moved_up": moved,
            }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(
        json!({ "ok": true, "released_members": members.len(), "children_moved_up": moved }),
    ))
}

#[derive(Debug, Deserialize)]
struct MemberQuery {
    q: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Serialize)]
struct Member {
    id: Uuid,
    email: String,
    display_name: String,
    status: String,
}

async fn list_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<MemberQuery>,
) -> AppResult<Json<serde_json::Value>> {
    require_staff_user(&state, &headers).await?;
    let group = load_group(&state, id).await?;
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);
    let pattern = match query.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(q) => format!("%{}%", q.replace('%', "\\%").replace('_', "\\_")),
        None => String::new(),
    };

    let members = sqlx::query_as::<_, (Uuid, String, String, String)>(
        "SELECT id, email, display_name, status FROM users \
         WHERE groups @> ARRAY[$1::uuid] \
           AND ($2 = '' OR email ILIKE $2 ESCAPE '\\' OR display_name ILIKE $2 ESCAPE '\\') \
         ORDER BY email LIMIT $3 OFFSET $4",
    )
    .bind(group.id)
    .bind(&pattern)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|(id, email, display_name, status)| Member {
        id,
        email,
        display_name,
        status,
    })
    .collect::<Vec<_>>();

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users \
         WHERE groups @> ARRAY[$1::uuid] \
           AND ($2 = '' OR email ILIKE $2 ESCAPE '\\' OR display_name ILIKE $2 ESCAPE '\\')",
    )
    .bind(group.id)
    .bind(&pattern)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(json!({
        "members": members,
        "total": total,
        "limit": limit,
        "offset": offset,
        "source": group.source,
    })))
}

#[derive(Debug, Deserialize)]
struct AddMembersBody {
    user_ids: Vec<Uuid>,
}

async fn add_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Path(id): Path<Uuid>,
    Json(body): Json<AddMembersBody>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_staff_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);
    let group = load_group(&state, id).await?;
    if group.source != "local" {
        return Err(AppError::conflict(
            "membership of this group is managed by SCIM or a directory source",
        ));
    }
    if body.user_ids.len() > 500 {
        return Err(AppError::bad_request(
            "at most 500 members may be added in one request",
        ));
    }
    let added = if body.user_ids.is_empty() {
        0
    } else {
        sqlx::query(
            "UPDATE users SET groups = ARRAY(SELECT DISTINCT unnest(array_append(groups, $2::uuid))), \
             updated_at = NOW() WHERE id = ANY($1::uuid[])",
        )
        .bind(&body.user_ids)
        .bind(group.id)
        .execute(&state.pool)
        .await?
        .rows_affected()
    };

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "group.member_add",
            resource_type: "group",
            resource_id: Some(group.id.to_string()),
            detail: json!({ "name": group.display_name, "requested": body.user_ids.len(), "updated": added }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    let total = member_total(&state, group.id).await?;
    Ok(Json(
        json!({ "ok": true, "updated": added, "total": total }),
    ))
}

async fn remove_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_staff_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);
    let group = load_group(&state, id).await?;
    if group.source != "local" {
        return Err(AppError::conflict(
            "membership of this group is managed by SCIM or a directory source",
        ));
    }
    let removed = sqlx::query(
        "UPDATE users SET groups = array_remove(groups, $2::uuid), updated_at = NOW() \
         WHERE id = $1 AND groups @> ARRAY[$2::uuid]",
    )
    .bind(user_id)
    .bind(group.id)
    .execute(&state.pool)
    .await?
    .rows_affected();

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "group.member_remove",
            resource_type: "group",
            resource_id: Some(group.id.to_string()),
            detail: json!({ "name": group.display_name, "user_id": user_id, "removed": removed }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    let total = member_total(&state, group.id).await?;
    Ok(Json(
        json!({ "ok": true, "removed": removed, "total": total }),
    ))
}

async fn member_total(state: &AppState, group_id: Uuid) -> AppResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE groups @> ARRAY[$1::uuid]")
            .bind(group_id)
            .fetch_one(&state.pool)
            .await?,
    )
}
