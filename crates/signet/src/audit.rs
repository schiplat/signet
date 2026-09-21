use crate::error::AppResult;
use crate::models::User;
use crate::roles::{require_staff, Role};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/audit-logs", get(list_audit_logs))
        .route("/admin/audit-logs/export", get(export_audit_logs))
        .route("/admin/audit-logs/facets", get(audit_log_facets))
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub actor: Option<User>,
    pub action: &'static str,
    pub resource_type: &'static str,
    pub resource_id: Option<String>,
    pub detail: Value,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    /// OAuth client attribution (TEXT snapshot of `client_apps.client_id`,
    /// intentionally not a UUID FK so attribution survives client deletion).
    /// When `None` and the event targets a client resource, it is derived
    /// from `resource_id`.
    pub client_id: Option<String>,
}

/// Records an audit event and fans it out to webhooks.
///
/// Takes the whole [`AppState`] rather than a bare `&PgPool` because the
/// webhook fan-out needs the application encryptor to decrypt stored secrets.
pub async fn record(state: &AppState, event: AuditEvent) {
    write(state, vec![event]).await;
}

/// Records a batch of events, then fans each one out to webhooks.
///
/// The compliance record is one row per event either way; this changes only how
/// many times the database is asked. A directory sync produces an event per
/// created, disabled, conflicted or unreadable entry, and one `INSERT` — on one
/// pooled connection — per entry is the dominant cost of the run's audit trail
/// once the actor is no longer re-read for each of them.
pub async fn record_many(state: &AppState, events: Vec<AuditEvent>) {
    write(state, events).await;
}

/// An event with everything derived from it already computed.
///
/// Split out because a batch has to be laid out as parallel arrays, and doing
/// that derivation twice (once for the columns, once for the webhook payload)
/// is how the two would drift apart.
struct Prepared {
    id: Uuid,
    action: &'static str,
    resource_type: &'static str,
    resource_id: Option<String>,
    detail: Value,
    ip: Option<String>,
    user_agent: Option<String>,
    actor_id: Option<Uuid>,
    actor_email: Option<String>,
    actor_role: Option<String>,
    browser: Option<String>,
    os: Option<String>,
    client_id: Option<String>,
    now: DateTime<Utc>,
}

fn prepare(event: AuditEvent) -> Prepared {
    let (actor_id, actor_email, actor_role) = match &event.actor {
        Some(u) => (Some(u.id), Some(u.email.clone()), Some(u.role.clone())),
        None => (None, None, None),
    };
    let (browser, os) = match event.user_agent.as_deref() {
        Some(ua) => crate::http::user_agent::parse(ua),
        None => (None, None),
    };
    // Derive client attribution from the resource for client-targeted events
    // (client.create / update / delete / ...) so all existing call sites are
    // attributed without touching them.
    let client_id = event.client_id.clone().or_else(|| {
        if event.resource_type == "client" {
            event.resource_id.clone()
        } else {
            None
        }
    });
    Prepared {
        id: Uuid::new_v4(),
        action: event.action,
        resource_type: event.resource_type,
        resource_id: event.resource_id,
        detail: event.detail,
        ip: event.ip,
        user_agent: event.user_agent,
        actor_id,
        actor_email,
        actor_role,
        browser,
        os,
        client_id,
        now: Utc::now(),
    }
}

async fn write(state: &AppState, events: Vec<AuditEvent>) {
    if events.is_empty() {
        return;
    }
    let prepared: Vec<Prepared> = events.into_iter().map(prepare).collect();

    // One statement for the whole batch. The columns are named once, here, so a
    // new column cannot be added to a single-row path and forgotten in this one.
    //
    // `created_at` is left to its `DEFAULT NOW()`: the timestamp of the
    // compliance record stays the database's clock, as it was before batching.
    // The webhook payload keeps using the application's clock, also as before.
    //
    // `detail` is bound as text and cast in SQL: `jsonb[]` has no encoder for a
    // `Vec<serde_json::Value>` here, and the cast is exact — the text is
    // `serde_json`'s own output.
    let insert = sqlx::query(
        r#"
        INSERT INTO audit_logs (
            id, actor_user_id, actor_email, actor_role,
            action, resource_type, resource_id, detail, ip,
            user_agent, browser, os, client_id
        )
        SELECT
            ids.id, ids.actor_user_id, ids.actor_email, ids.actor_role,
            ids.action, ids.resource_type, ids.resource_id, ids.detail::jsonb,
            ids.ip, ids.user_agent, ids.browser, ids.os, ids.client_id
        FROM UNNEST(
            $1::uuid[], $2::uuid[], $3::text[], $4::text[],
            $5::text[], $6::text[], $7::text[], $8::text[], $9::text[],
            $10::text[], $11::text[], $12::text[], $13::text[]
        ) AS ids(
            id, actor_user_id, actor_email, actor_role,
            action, resource_type, resource_id, detail, ip,
            user_agent, browser, os, client_id
        )
        "#,
    )
    .bind(prepared.iter().map(|p| p.id).collect::<Vec<Uuid>>())
    .bind(prepared.iter().map(|p| p.actor_id).collect::<Vec<_>>())
    .bind(
        prepared
            .iter()
            .map(|p| p.actor_email.clone())
            .collect::<Vec<_>>(),
    )
    .bind(
        prepared
            .iter()
            .map(|p| p.actor_role.clone())
            .collect::<Vec<_>>(),
    )
    .bind(prepared.iter().map(|p| p.action).collect::<Vec<_>>())
    .bind(prepared.iter().map(|p| p.resource_type).collect::<Vec<_>>())
    .bind(
        prepared
            .iter()
            .map(|p| p.resource_id.clone())
            .collect::<Vec<_>>(),
    )
    .bind(
        prepared
            .iter()
            .map(|p| p.detail.to_string())
            .collect::<Vec<String>>(),
    )
    .bind(prepared.iter().map(|p| p.ip.clone()).collect::<Vec<_>>())
    .bind(
        prepared
            .iter()
            .map(|p| p.user_agent.clone())
            .collect::<Vec<_>>(),
    )
    .bind(
        prepared
            .iter()
            .map(|p| p.browser.clone())
            .collect::<Vec<_>>(),
    )
    .bind(prepared.iter().map(|p| p.os.clone()).collect::<Vec<_>>())
    .bind(
        prepared
            .iter()
            .map(|p| p.client_id.clone())
            .collect::<Vec<_>>(),
    );

    if let Err(e) = insert.execute(&state.pool).await {
        // Still named, for the same reason as before: the batch is best-effort.
        tracing::warn!(
            error = %e,
            events = prepared.len(),
            first_action = prepared.first().map(|p| p.action).unwrap_or_default(),
            "failed to write audit log"
        );
        return;
    }

    for p in prepared {
        // Best-effort webhook fan-out (fire-and-forget).
        //
        // Per-entry directory sync events are recorded but not fanned out: with
        // 100k users, one sync would otherwise produce 100k webhook deliveries,
        // with no retry and no aggregation (§11.1). Each run's
        // `directory.sync.finished` event carries the same totals, which is the
        // intended delivery. The audit row above is still written for every
        // event — that is the compliance record, and it is deliberately
        // unaffected.
        if crate::directory::is_summary_only_action(p.action) {
            continue;
        }
        let payload = json!({
            "id": p.id,
            "action": p.action,
            "resource_type": p.resource_type,
            "resource_id": p.resource_id,
            "client_id": p.client_id,
            "actor_user_id": p.actor_id,
            "actor_email": p.actor_email,
            "actor_role": p.actor_role,
            "detail": p.detail,
            "ip": p.ip,
            "browser": p.browser,
            "os": p.os,
            "created_at": p.now.to_rfc3339(),
        });
        crate::webhooks::dispatch(state, p.id, payload);
    }
}

/// Extracts the OAuth `client_id` from a login `return_to` URL of the form
/// `/oauth/authorize?...&client_id=webapp` and validates it against
/// `client_apps` so only known apps are attributed. Returns `None` for
/// absent/malformed input or unknown clients — never blocks the login flow.
pub async fn resolve_audit_client_id(pool: &PgPool, return_to: Option<&str>) -> Option<String> {
    let client_id = resolve_audit_client_id_contract(return_to)?;
    sqlx::query_scalar::<_, i8>("SELECT 1 FROM client_apps WHERE client_id = $1")
        .bind(&client_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|_| client_id)
}

/// Pure parsing half of [`resolve_audit_client_id`]: pulls `client_id` out of
/// a `return_to` query string without any DB validation.
///
/// Exposed for tests (`tests/audit_client_id.rs`); not part of the public API.
pub fn resolve_audit_client_id_contract(return_to: Option<&str>) -> Option<String> {
    let return_to = return_to?.trim();
    let query = return_to.strip_prefix("/oauth/authorize?")?;
    let client_id = query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == "client_id").then(|| v.to_string())
    })?;
    let client_id = urlencoding::decode(&client_id).ok()?.into_owned();
    if client_id.is_empty() {
        None
    } else {
        Some(client_id)
    }
}

#[derive(Debug, sqlx::FromRow, Serialize)]
struct AuditLogRow {
    id: Uuid,
    actor_user_id: Option<Uuid>,
    actor_email: Option<String>,
    actor_role: Option<String>,
    action: String,
    resource_type: String,
    resource_id: Option<String>,
    detail: Value,
    ip: Option<String>,
    user_agent: Option<String>,
    browser: Option<String>,
    os: Option<String>,
    client_id: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    q: Option<String>,
    action: Option<String>,
    client_id: Option<String>,
    browser: Option<String>,
    os: Option<String>,
    page: Option<i64>,
    page_size: Option<i64>,
    sort: Option<String>,
    dir: Option<String>,
}

#[derive(Debug, Serialize)]
struct ListResponse {
    items: Vec<AuditLogRow>,
    total: i64,
    page: i64,
    page_size: i64,
}

const MANAGER_ACTIONS: &[&str] = &[
    "auth.login",
    "auth.login_failed",
    "auth.password_change",
    "me.profile_update",
    "user.create",
    "user.update",
    "user.disable",
    "user.enable",
    "client.create",
    "client.update",
    "client.disable",
    "client.enable",
    "client.rotate_secret",
    "mfa.verify",
    "mfa.enroll",
    "mfa.recovery_use",
    "mfa.recovery_regen",
    "mfa.rebind",
];

async fn list_audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<ListResponse>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_staff(&actor)?;

    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * page_size;

    let sort = match q.sort.as_deref() {
        Some("action") => "action",
        Some("actor_email") => "actor_email",
        Some("ip") => "ip",
        Some("resource_type") => "resource_type",
        Some("resource_id") => "resource_id",
        _ => "created_at",
    };
    let dir = if q.dir.as_deref() == Some("asc") {
        "ASC"
    } else {
        "DESC"
    };

    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let action_filter = q.action.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let client_filter = q
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let browser_filter = q
        .browser
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let os_filter = q.os.as_deref().map(str::trim).filter(|s| !s.is_empty());

    let allowed: Option<Vec<String>> = if actor.role_enum() == Role::Manager {
        Some(MANAGER_ACTIONS.iter().map(|s| (*s).to_string()).collect())
    } else {
        None // admin: all (including user.delete / client.delete)
    };

    if let (Some(allowed), Some(a)) = (&allowed, action_filter) {
        if !allowed.iter().any(|x| x == a) {
            return Ok(Json(ListResponse {
                items: vec![],
                total: 0,
                page,
                page_size,
            }));
        }
    }

    let (total, items) = fetch_logs(
        &state.pool,
        allowed.as_deref(),
        search,
        action_filter,
        client_filter,
        browser_filter,
        os_filter,
        sort,
        dir,
        page_size,
        offset,
    )
    .await?;

    Ok(Json(ListResponse {
        items,
        total,
        page,
        page_size,
    }))
}

#[allow(clippy::too_many_arguments)]
async fn fetch_logs(
    pool: &PgPool,
    allowed_actions: Option<&[String]>,
    search: Option<&str>,
    action_filter: Option<&str>,
    client_filter: Option<&str>,
    browser_filter: Option<&str>,
    os_filter: Option<&str>,
    sort: &str,
    dir: &str,
    limit: i64,
    offset: i64,
) -> AppResult<(i64, Vec<AuditLogRow>)> {
    let order = format!("{sort} {dir}");

    if let Some(allowed) = allowed_actions {
        let total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM audit_logs
            WHERE action = ANY($1)
              AND ($2::text IS NULL OR action = $2)
              AND (
                $3::text IS NULL
                OR actor_email ILIKE '%' || $3 || '%'
                OR action ILIKE '%' || $3 || '%'
                OR resource_type ILIKE '%' || $3 || '%'
                OR COALESCE(resource_id, '') ILIKE '%' || $3 || '%'
                OR COALESCE(ip, '') ILIKE '%' || $3 || '%'
              )
              AND ($4::text IS NULL OR client_id = $4)
              AND ($5::text IS NULL OR browser = $5)
              AND ($6::text IS NULL OR os = $6)
            "#,
        )
        .bind(allowed)
        .bind(action_filter)
        .bind(search)
        .bind(client_filter)
        .bind(browser_filter)
        .bind(os_filter)
        .fetch_one(pool)
        .await?;

        let sql = format!(
            r#"
            SELECT id, actor_user_id, actor_email, actor_role, action, resource_type,
                   resource_id, detail, ip, user_agent, browser, os, client_id, created_at
            FROM audit_logs
            WHERE action = ANY($1)
              AND ($2::text IS NULL OR action = $2)
              AND (
                $3::text IS NULL
                OR actor_email ILIKE '%' || $3 || '%'
                OR action ILIKE '%' || $3 || '%'
                OR resource_type ILIKE '%' || $3 || '%'
                OR COALESCE(resource_id, '') ILIKE '%' || $3 || '%'
                OR COALESCE(ip, '') ILIKE '%' || $3 || '%'
              )
              AND ($4::text IS NULL OR client_id = $4)
              AND ($5::text IS NULL OR browser = $5)
              AND ($6::text IS NULL OR os = $6)
            ORDER BY {order}
            LIMIT $7 OFFSET $8
            "#
        );
        let items = sqlx::query_as::<_, AuditLogRow>(&sql)
            .bind(allowed)
            .bind(action_filter)
            .bind(search)
            .bind(client_filter)
            .bind(browser_filter)
            .bind(os_filter)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?;
        Ok((total, items))
    } else {
        let total: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM audit_logs
            WHERE ($1::text IS NULL OR action = $1)
              AND (
                $2::text IS NULL
                OR actor_email ILIKE '%' || $2 || '%'
                OR action ILIKE '%' || $2 || '%'
                OR resource_type ILIKE '%' || $2 || '%'
                OR COALESCE(resource_id, '') ILIKE '%' || $2 || '%'
                OR COALESCE(ip, '') ILIKE '%' || $2 || '%'
              )
              AND ($3::text IS NULL OR client_id = $3)
              AND ($4::text IS NULL OR browser = $4)
              AND ($5::text IS NULL OR os = $5)
            "#,
        )
        .bind(action_filter)
        .bind(search)
        .bind(client_filter)
        .bind(browser_filter)
        .bind(os_filter)
        .fetch_one(pool)
        .await?;

        let sql = format!(
            r#"
            SELECT id, actor_user_id, actor_email, actor_role, action, resource_type,
                   resource_id, detail, ip, user_agent, browser, os, client_id, created_at
            FROM audit_logs
            WHERE ($1::text IS NULL OR action = $1)
              AND (
                $2::text IS NULL
                OR actor_email ILIKE '%' || $2 || '%'
                OR action ILIKE '%' || $2 || '%'
                OR resource_type ILIKE '%' || $2 || '%'
                OR COALESCE(resource_id, '') ILIKE '%' || $2 || '%'
                OR COALESCE(ip, '') ILIKE '%' || $2 || '%'
              )
              AND ($3::text IS NULL OR client_id = $3)
              AND ($4::text IS NULL OR browser = $4)
              AND ($5::text IS NULL OR os = $5)
            ORDER BY {order}
            LIMIT $6 OFFSET $7
            "#
        );
        let items = sqlx::query_as::<_, AuditLogRow>(&sql)
            .bind(action_filter)
            .bind(search)
            .bind(client_filter)
            .bind(browser_filter)
            .bind(os_filter)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?;
        Ok((total, items))
    }
}

async fn export_audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> AppResult<Response> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_staff(&actor)?;

    let allowed: Option<Vec<String>> = if actor.role_enum() == Role::Manager {
        Some(MANAGER_ACTIONS.iter().map(|s| (*s).to_string()).collect())
    } else {
        None
    };
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let action_filter = q.action.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let client_filter = q
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let browser_filter = q
        .browser
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let os_filter = q.os.as_deref().map(str::trim).filter(|s| !s.is_empty());

    let rows = if let Some(allowed) = &allowed {
        sqlx::query_as::<_, AuditLogRow>(
            r#"
            SELECT id, actor_user_id, actor_email, actor_role, action, resource_type,
                   resource_id, detail, ip, user_agent, browser, os, client_id, created_at
            FROM audit_logs
            WHERE action = ANY($1)
              AND ($2::text IS NULL OR action = $2)
              AND (
                $3::text IS NULL
                OR actor_email ILIKE '%' || $3 || '%'
                OR action ILIKE '%' || $3 || '%'
                OR resource_type ILIKE '%' || $3 || '%'
                OR COALESCE(resource_id, '') ILIKE '%' || $3 || '%'
                OR COALESCE(ip, '') ILIKE '%' || $3 || '%'
              )
              AND ($4::text IS NULL OR client_id = $4)
              AND ($5::text IS NULL OR browser = $5)
              AND ($6::text IS NULL OR os = $6)
            ORDER BY created_at DESC
            "#,
        )
        .bind(allowed)
        .bind(action_filter)
        .bind(search)
        .bind(client_filter)
        .bind(browser_filter)
        .bind(os_filter)
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query_as::<_, AuditLogRow>(
            r#"
            SELECT id, actor_user_id, actor_email, actor_role, action, resource_type,
                   resource_id, detail, ip, user_agent, browser, os, client_id, created_at
            FROM audit_logs
            WHERE ($1::text IS NULL OR action = $1)
              AND (
                $2::text IS NULL
                OR actor_email ILIKE '%' || $2 || '%'
                OR action ILIKE '%' || $2 || '%'
                OR resource_type ILIKE '%' || $2 || '%'
                OR COALESCE(resource_id, '') ILIKE '%' || $2 || '%'
                OR COALESCE(ip, '') ILIKE '%' || $2 || '%'
              )
              AND ($3::text IS NULL OR client_id = $3)
              AND ($4::text IS NULL OR browser = $4)
              AND ($5::text IS NULL OR os = $5)
            ORDER BY created_at DESC
            "#,
        )
        .bind(action_filter)
        .bind(search)
        .bind(client_filter)
        .bind(browser_filter)
        .bind(os_filter)
        .fetch_all(&state.pool)
        .await?
    };

    let csv = to_csv(&rows);
    let body = axum::body::Body::from(csv);
    let mut resp = Response::new(body);
    resp.headers_mut().insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    resp.headers_mut().insert(
        CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_static("attachment; filename=\"signet-audit-logs.csv\""),
    );
    Ok(resp)
}

fn to_csv(rows: &[AuditLogRow]) -> String {
    let mut out = String::with_capacity(rows.len() * 90);
    out.push_str(
        "created_at,actor_email,actor_role,action,resource_type,resource_id,client_id,ip,browser,os,detail\n",
    );
    for r in rows {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{}\n",
            r.created_at.to_rfc3339(),
            csv_escape(r.actor_email.as_deref().unwrap_or("")),
            csv_escape(r.actor_role.as_deref().unwrap_or("")),
            csv_escape(&r.action),
            csv_escape(&r.resource_type),
            csv_escape(r.resource_id.as_deref().unwrap_or("")),
            csv_escape(r.client_id.as_deref().unwrap_or("")),
            csv_escape(r.ip.as_deref().unwrap_or("")),
            csv_escape(r.browser.as_deref().unwrap_or("")),
            csv_escape(r.os.as_deref().unwrap_or("")),
            csv_escape(&r.detail.to_string()),
        ));
    }
    out
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Deletes audit log rows older than the configured retention window.
pub async fn prune_audit_logs(pool: &PgPool, retention_days: i64) -> AppResult<u64> {
    let res = sqlx::query(
        "DELETE FROM audit_logs WHERE created_at < NOW() - ($1::int * INTERVAL '1 day')",
    )
    .bind(retention_days)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

#[derive(Debug, Serialize)]
struct AuditFacetsResponse {
    /// Distinct browsers seen in the last 90 days (ascending).
    browsers: Vec<String>,
    /// Distinct OSes seen in the last 90 days (ascending).
    oses: Vec<String>,
    /// All registered OAuth apps for filter dropdowns.
    clients: Vec<AuditFacetClient>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct AuditFacetClient {
    client_id: String,
    enabled: bool,
}

async fn audit_log_facets(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<AuditFacetsResponse>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_staff(&actor)?;

    let browsers: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT browser FROM audit_logs
        WHERE browser IS NOT NULL
          AND created_at > NOW() - INTERVAL '90 days'
        ORDER BY browser
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let oses: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT os FROM audit_logs
        WHERE os IS NOT NULL
          AND created_at > NOW() - INTERVAL '90 days'
        ORDER BY os
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let clients: Vec<AuditFacetClient> =
        sqlx::query_as("SELECT client_id, enabled FROM client_apps ORDER BY client_id")
            .fetch_all(&state.pool)
            .await?;

    Ok(Json(AuditFacetsResponse {
        browsers,
        oses,
        clients,
    }))
}
