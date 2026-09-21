mod clients;

use crate::audit::{record, AuditEvent};
use crate::auth::current_user;
use crate::auth::password::{
    hash_password_offloaded, record_password_history, set_user_password, validate_password_strength,
};
use crate::auth::session::revoke_all_sessions;
use crate::crypto::util::{random_token, sha256_hex};
use crate::error::{AppError, AppResult};
use crate::models::{
    insert_user, normalize_username, status_from_flags, user_by_id, NewUser, PublicUser, User,
    USER_COLS,
};
use crate::roles::{require_admin_role, require_staff, Role};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/stats", get(stats))
        .route("/admin/users", get(list_users).post(create_user))
        .route("/admin/users/email-check", get(check_email))
        .route("/admin/users/username-check", get(check_username))
        .route("/admin/users/phone-check", get(check_phone))
        .route("/admin/users/batch-disable", post(batch_disable_users))
        .route("/admin/users/{id}", put(update_user).delete(delete_user))
        .route("/admin/users/{id}/disable", post(disable_user))
        .route("/admin/users/{id}/enable", post(enable_user))
        .route(
            "/admin/users/{id}/sessions/revoke",
            post(revoke_user_sessions),
        )
        .route("/admin/integrations", get(integrations))
        .route(
            "/admin/scim/token",
            post(scim_generate_token).delete(scim_revoke_token),
        )
        .merge(clients::router())
}

async fn integrations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let _ = require_admin_user(&state, &headers).await?;
    let scim_configured: bool = scim_token_configured(&state.pool).await?;
    let base = state.config.public_base();
    Ok(Json(json!({
        "scim": {
            "enabled": scim_configured,
            "base_url": format!("{base}/scim/v2"),
            "token_configured": scim_configured,
        },
        "webauthn": {
            "rp_id": state.config.webauthn_rp_id,
            "rp_origin": state.config.webauthn_rp_origin,
        },
    })))
}

async fn scim_token_configured(pool: &sqlx::PgPool) -> AppResult<bool> {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT token_hash FROM scim_config WHERE id = TRUE")
            .fetch_optional(pool)
            .await?
            .flatten();
    Ok(stored.is_some())
}

/// Generate (or rotate) the SCIM bearer token. Plaintext is returned exactly once.
async fn scim_generate_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_admin_user(&state, &headers).await?;
    let plaintext = random_token(32);
    let hash = sha256_hex(&plaintext);

    sqlx::query(
        r#"
        INSERT INTO scim_config (id, token_hash, updated_at) VALUES (TRUE, $1, NOW())
        ON CONFLICT (id) DO UPDATE SET token_hash = EXCLUDED.token_hash, updated_at = NOW()
        "#,
    )
    .bind(&hash)
    .execute(&state.pool)
    .await?;

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "scim.token_rotate",
            resource_type: "scim",
            resource_id: None,
            detail: json!({}),
            ip: None,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "token": plaintext })))
}

/// Revoke the SCIM bearer token (disables the SCIM API until a new one is issued).
async fn scim_revoke_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_admin_user(&state, &headers).await?;

    sqlx::query("UPDATE scim_config SET token_hash = NULL, updated_at = NOW() WHERE id = TRUE")
        .execute(&state.pool)
        .await?;

    // Revoking retires the IdP's authority, so the disable claims it was holding
    // go with it. Left in place they would outlive their author: an admin enable
    // cannot override an upstream claim, so those accounts would have no way
    // back. Rotating the token (`POST` on the same route) keeps a token and
    // deliberately does *not* come through here — the IdP is still pushing.
    let released = crate::authority::release_dead_authority_claims(&state.pool).await?;
    if released > 0 {
        tracing::info!(released, "released disable claims of a revoked authority");
    }

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "scim.token_revoke",
            resource_type: "scim",
            resource_id: None,
            detail: json!({}),
            ip: None,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "ok": true })))
}

pub(crate) async fn require_staff_user(state: &AppState, headers: &HeaderMap) -> AppResult<User> {
    let user = current_user(state, headers).await?;
    require_staff(&user)?;
    Ok(user)
}

pub(crate) async fn require_admin_user(state: &AppState, headers: &HeaderMap) -> AppResult<User> {
    let user = current_user(state, headers).await?;
    require_admin_role(&user)?;
    Ok(user)
}

/// The counters the overview page opens with, read in one round trip.
///
/// Six separate `COUNT(*)` queries used to be issued for `users` and two more
/// for `client_apps`. They are near-free to compute but not free to *ask for*:
/// the dashboard pays the sum of the round trips on every visit, and a remote
/// database makes that tens of milliseconds of nothing.
#[derive(Debug, sqlx::FromRow)]
struct DashboardCounts {
    users_total: i64,
    users_active: i64,
    users_disabled: i64,
    users_admin: i64,
    users_manager: i64,
    clients_total: i64,
    clients_enabled: i64,
}

/// The six login counters, from one scan instead of six.
///
/// The three `COUNT(DISTINCT actor_user_id)` variants are the reason this is
/// worth doing as one query rather than a `try_join!`: they are the expensive
/// part, and six separate queries scan the same 30 days six times over.
#[derive(Debug, sqlx::FromRow)]
struct LoginCounts {
    logins_24h: i64,
    logins_7d: i64,
    logins_30d: i64,
    unique_users_24h: i64,
    unique_users_7d: i64,
    unique_users_30d: i64,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct RecentLogin {
    actor_email: Option<String>,
    ip: Option<String>,
    browser: Option<String>,
    os: Option<String>,
    client_id: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct LoginTrendPoint {
    day: chrono::NaiveDate,
    /// Calendar-day login count (≈ 24h bucket).
    logins_1d: i64,
    /// Rolling sum of the last 7 calendar days ending on `day`.
    logins_7d: i64,
    /// Rolling sum of the last 30 calendar days ending on `day`.
    logins_30d: i64,
}

/// One hourly point of the last 24 hours (`hour` = UTC hour start).
#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct LoginTrendHourPoint {
    hour: chrono::NaiveDateTime,
    logins: i64,
}

#[derive(Debug, serde::Serialize)]
struct AdminStats {
    users_total: i64,
    users_active: i64,
    users_disabled: i64,
    users_admin: i64,
    users_manager: i64,
    clients_total: i64,
    clients_enabled: i64,
    logins_24h: i64,
    logins_7d: i64,
    logins_30d: i64,
    unique_users_24h: i64,
    unique_users_7d: i64,
    unique_users_30d: i64,
    /// Last 30 days; three overlaid series (1d / 7d rolling / 30d rolling).
    login_trend: Vec<LoginTrendPoint>,
    /// Last 24 hours, one point per hour (for the default chart range).
    login_trend_24h: Vec<LoginTrendHourPoint>,
    /// Recent successful logins across all users (7 days).
    recent_logins: Vec<RecentLogin>,
    /// Per-app login aggregates over the last 30 days (Top 10).
    by_client: Vec<ClientUsage>,
    /// Browser distribution of logins over the last 30 days.
    browsers: Vec<NameCount>,
    /// OS distribution of logins over the last 30 days.
    oses: Vec<NameCount>,
    /// Echoes the requested scope so the UI can confirm what was filtered.
    scope: StatsScope,
}

#[derive(Debug, serde::Serialize)]
struct StatsScope {
    /// `None` = global (all apps).
    client_id: Option<String>,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct ClientUsage {
    /// OAuth client identifier; `(direct)` = sign-ins without app context.
    client_id: String,
    logins_24h: i64,
    logins_7d: i64,
    logins_30d: i64,
    unique_users_30d: i64,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct NameCount {
    name: String,
    count: i64,
}

#[derive(Debug, Deserialize)]
struct StatsQuery {
    client_id: Option<String>,
}

async fn stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<StatsQuery>,
) -> AppResult<Json<AdminStats>> {
    require_staff_user(&state, &headers).await?;

    let scope_client = q
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "(direct)")
        .map(str::to_string);
    // "(direct)" filters sign-ins without app attribution.
    let direct_only = q.client_id.as_deref() == Some("(direct)");

    // One round trip for every count on the overview page. The `users` and
    // `client_apps` halves are two scans joined by a cross join, which is
    // cheaper than the eight queries this replaces even before counting the
    // round trips: each `COUNT(*) FILTER` reads the same rows the other
    // filters would have read anyway.
    let counts = sqlx::query_as::<_, DashboardCounts>(
        r#"
        SELECT
            u.total          AS users_total,
            u.active_count   AS users_active,
            u.disabled_count AS users_disabled,
            u.admin_count    AS users_admin,
            u.manager_count  AS users_manager,
            c.total          AS clients_total,
            c.enabled_count  AS clients_enabled
        FROM (
            SELECT
                COUNT(*)                                                  AS total,
                COUNT(*) FILTER (WHERE status = 'active')                  AS active_count,
                COUNT(*) FILTER (WHERE status = 'disabled')                AS disabled_count,
                COUNT(*) FILTER (WHERE role = 'admin' AND status = 'active')   AS admin_count,
                COUNT(*) FILTER (WHERE role = 'manager' AND status = 'active') AS manager_count
            FROM users
        ) u
        CROSS JOIN (
            SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE enabled) AS enabled_count
            FROM client_apps
        ) c
        "#,
    )
    .fetch_one(&state.pool)
    .await?;

    // Login metrics scoped by the optional app filter: `scope_client` adds a
    // `client_id = $N` predicate, `direct_only` selects NULL-client rows.
    let client_pred = |idx: usize| -> String {
        match (&scope_client, direct_only) {
            (Some(_), _) => format!("AND client_id = ${idx}"),
            (None, true) => "AND client_id IS NULL".to_string(),
            (None, false) => String::new(),
        }
    };

    // The six login counters from one scan of one 30-day window. Every window
    // is contained in that one, so the counts are identical to what six
    // separate queries would return; the `FILTER` clauses only decide which
    // rows of the single scan they count. Bounding the scan by 30 days is what
    // keeps this off the full history.
    let logins = sqlx::query_as::<_, LoginCounts>(&format!(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours')::bigint AS logins_24h,
            COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days')::bigint   AS logins_7d,
            COUNT(*)::bigint                                                         AS logins_30d,
            COUNT(DISTINCT actor_user_id) FILTER (
                WHERE created_at > NOW() - INTERVAL '24 hours' AND actor_user_id IS NOT NULL
            )::bigint AS unique_users_24h,
            COUNT(DISTINCT actor_user_id) FILTER (
                WHERE created_at > NOW() - INTERVAL '7 days' AND actor_user_id IS NOT NULL
            )::bigint AS unique_users_7d,
            COUNT(DISTINCT actor_user_id) FILTER (
                WHERE actor_user_id IS NOT NULL
            )::bigint AS unique_users_30d
        FROM audit_logs
        WHERE action = 'auth.login'
          AND created_at > NOW() - INTERVAL '30 days'
          {}
        "#,
        client_pred(1)
    ))
    .bind(&scope_client)
    .fetch_one(&state.pool)
    .await?;

    // The remaining reads are independent of one another and of the counters
    // above, so they go out together: the page's latency is the slowest of them
    // rather than their sum.
    // Every statement below is bound to a local first. `try_join!` holds all of
    // the futures across one await, so a `&format!` temporary would be dropped
    // while the macro's expansion still borrows it.
    let sql_trend = format!(
        r#"
        WITH daily AS (
            SELECT (created_at AT TIME ZONE 'UTC')::date AS day,
                   COUNT(*)::bigint AS logins
            FROM audit_logs
            WHERE action = 'auth.login'
              AND created_at >= ((CURRENT_DATE - INTERVAL '59 days')::timestamp AT TIME ZONE 'UTC')
              {client}
            GROUP BY 1
        ),
        history AS (
            SELECT
                gs::date AS day,
                COALESCE(d.logins, 0)::bigint AS logins_1d
            FROM generate_series(
                (CURRENT_DATE - INTERVAL '59 days')::date,
                CURRENT_DATE,
                '1 day'::interval
            ) AS gs
            LEFT JOIN daily d ON d.day = gs::date
        ),
        rolled AS (
            SELECT
                day,
                logins_1d,
                SUM(logins_1d) OVER (
                    ORDER BY day
                    ROWS BETWEEN 6 PRECEDING AND CURRENT ROW
                )::bigint AS logins_7d,
                SUM(logins_1d) OVER (
                    ORDER BY day
                    ROWS BETWEEN 29 PRECEDING AND CURRENT ROW
                )::bigint AS logins_30d
            FROM history
        )
        SELECT day, logins_1d, logins_7d, logins_30d
        FROM rolled
        WHERE day >= (CURRENT_DATE - INTERVAL '29 days')::date
        ORDER BY day
        "#,
        client = client_pred(1)
    );

    // Hourly grain for the default 24h range: dense hourly buckets so the
    // x-axis is time-of-day, not dates.
    let sql_trend_24h = format!(
        r#"
        WITH buckets AS (
            SELECT
                date_trunc('hour', gs) AS hour,
                0::bigint AS logins
            FROM generate_series(
                date_trunc('hour', NOW() AT TIME ZONE 'UTC') - INTERVAL '23 hours',
                date_trunc('hour', NOW() AT TIME ZONE 'UTC'),
                '1 hour'::interval
            ) AS gs
        ),
        counts AS (
            SELECT
                date_trunc('hour', created_at AT TIME ZONE 'UTC') AS hour,
                COUNT(*)::bigint AS logins
            FROM audit_logs
            WHERE action = 'auth.login'
              AND created_at >= date_trunc('hour', NOW()) - INTERVAL '23 hours'
              {client}
            GROUP BY 1
        )
        SELECT b.hour AS hour, COALESCE(c.logins, 0) AS logins
        FROM buckets b
        LEFT JOIN counts c ON c.hour = b.hour
        ORDER BY b.hour
        "#,
        client = client_pred(1)
    );

    let sql_recent = format!(
        r#"
        SELECT actor_email, ip, browser, os, client_id, created_at
        FROM audit_logs
        WHERE action = 'auth.login'
          AND created_at > NOW() - INTERVAL '7 days'
          {client}
        ORDER BY created_at DESC
        LIMIT 10
        "#,
        client = client_pred(1)
    );

    // Browser / OS distribution over the last 30 days (login events).
    let sql_browsers = format!(
        r#"
        SELECT COALESCE(browser, 'Unknown') AS name, COUNT(*)::bigint AS count
        FROM audit_logs
        WHERE action = 'auth.login'
          AND created_at >= NOW() - INTERVAL '30 days'
          {client}
        GROUP BY 1
        ORDER BY count DESC
        "#,
        client = client_pred(1)
    );

    let sql_oses = format!(
        r#"
        SELECT COALESCE(os, 'Unknown') AS name, COUNT(*)::bigint AS count
        FROM audit_logs
        WHERE action = 'auth.login'
          AND created_at >= NOW() - INTERVAL '30 days'
          {client}
        GROUP BY 1
        ORDER BY count DESC
        "#,
        client = client_pred(1)
    );

    // The remaining reads are independent of one another and of the counters
    // above, so they go out together: the page's latency is the slowest of them
    // rather than their sum.
    let (login_trend, login_trend_24h, recent_logins, by_client, browsers, oses) = tokio::try_join!(
        sqlx::query_as::<_, LoginTrendPoint>(&sql_trend)
            .bind(&scope_client)
            .fetch_all(&state.pool),
        sqlx::query_as::<_, LoginTrendHourPoint>(&sql_trend_24h)
            .bind(&scope_client)
            .fetch_all(&state.pool),
        sqlx::query_as::<_, RecentLogin>(&sql_recent)
            .bind(&scope_client)
            .fetch_all(&state.pool),
        // Per-app aggregates over the last 30 days (global view only; when
        // scoped to one app the front end already knows the single row).
        sqlx::query_as::<_, ClientUsage>(
            r#"
            SELECT COALESCE(client_id, '(direct)')                AS client_id,
                   COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours')::bigint AS logins_24h,
                   COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days')::bigint  AS logins_7d,
                   COUNT(*)::bigint                               AS logins_30d,
                   COUNT(DISTINCT actor_user_id)::bigint          AS unique_users_30d
            FROM audit_logs
            WHERE action = 'auth.login'
              AND created_at >= NOW() - INTERVAL '30 days'
            GROUP BY 1
            ORDER BY logins_30d DESC
            LIMIT 10
            "#,
        )
        .fetch_all(&state.pool),
        sqlx::query_as::<_, NameCount>(&sql_browsers)
            .bind(&scope_client)
            .fetch_all(&state.pool),
        sqlx::query_as::<_, NameCount>(&sql_oses)
            .bind(&scope_client)
            .fetch_all(&state.pool),
    )?;

    Ok(Json(AdminStats {
        users_total: counts.users_total,
        users_active: counts.users_active,
        users_disabled: counts.users_disabled,
        users_admin: counts.users_admin,
        users_manager: counts.users_manager,
        clients_total: counts.clients_total,
        clients_enabled: counts.clients_enabled,
        logins_24h: logins.logins_24h,
        logins_7d: logins.logins_7d,
        logins_30d: logins.logins_30d,
        unique_users_24h: logins.unique_users_24h,
        unique_users_7d: logins.unique_users_7d,
        unique_users_30d: logins.unique_users_30d,
        login_trend,
        login_trend_24h,
        recent_logins,
        by_client,
        browsers,
        oses,
        scope: StatsScope {
            client_id: q.client_id,
        },
    }))
}

/// Page size for the users list when the client does not ask for one.
///
/// The dashboard's own selector offers 10/20/50/100 and starts at 20.
const USERS_PAGE_DEFAULT: i64 = 20;

/// Ceiling on `limit`.
///
/// The point of the paging is that this endpoint cannot be made to read the
/// whole table, and a client asking for `limit=1000000` would undo that. The
/// dashboard never asks for more than its largest option.
const USERS_PAGE_MAX: i64 = 200;

/// The columns the search box matches, as SQL.
///
/// The dashboard used to filter this in the browser over the full list, so this
/// has to cover the same ground or a search would start missing rows it used to
/// find: the three name fields, the two state columns, the creation source, and
/// the SSO identities behind the `sso` column.
///
/// `$1` is the pattern, or NULL for "no search".
const USER_SEARCH_SQL: &str = r#"
    ($1::text IS NULL
     OR u.email ILIKE $1
     OR COALESCE(u.username, '') ILIKE $1
     OR u.display_name ILIKE $1
     OR u.status ILIKE $1
     OR u.role ILIKE $1
     OR COALESCE(u.provisioned_via, '') ILIKE $1
     OR EXISTS (
         SELECT 1 FROM user_identities ui
         JOIN upstream_providers p ON p.code = ui.provider_code
         WHERE ui.user_id = u.id
           AND (p.display_name ILIKE $1
                OR ui.provider_code ILIKE $1
                OR p.provider_type ILIKE $1)
     ))
"#;

/// The sortable columns, as SQL.
///
/// A whitelist, not interpolation: the value is concatenated into the statement
/// text, and the client's choice of column is not something to take on trust.
/// An unknown key sorts by `created_at`, which is what the dashboard did when
/// its `getValue` had no case for the key.
fn user_sort_column(key: &str) -> &'static str {
    match key {
        "email" => "u.email",
        "display_name" => "u.display_name",
        "role" => "u.role",
        "status" => "u.status",
        _ => "u.created_at",
    }
}

/// Wraps `needle` in `%` for `ILIKE`, escaping the wildcards it contains.
///
/// The browser filtered with `String.prototype.includes`, so a search for `a_b`
/// matched those three literal characters. Passing it to `ILIKE` unescaped would
/// read `_` as "any single character" and return rows the operator did not ask
/// for — the same query meaning two different things before and after the move
/// to the server.
fn like_pattern(needle: &str) -> String {
    let escaped = needle
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

#[derive(Debug, Deserialize)]
struct ListUsersQuery {
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

#[derive(Debug, serde::Serialize)]
struct AdminUserList {
    users: Vec<AdminUserListItem>,
    /// Rows matching the search, not rows in this page.
    total: i64,
    limit: i64,
    offset: i64,
}

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListUsersQuery>,
) -> AppResult<Json<AdminUserList>> {
    require_staff_user(&state, &headers).await?;

    let limit = q
        .limit
        .unwrap_or(USERS_PAGE_DEFAULT)
        .clamp(1, USERS_PAGE_MAX);
    let offset = q.offset.unwrap_or(0).max(0);
    let column = user_sort_column(q.sort.as_deref().unwrap_or("created_at"));
    let direction = if q.dir.as_deref() == Some("asc") {
        "ASC"
    } else {
        "DESC"
    };
    let pattern =
        q.q.as_deref()
            .map(str::trim)
            .filter(|needle| !needle.is_empty())
            .map(like_pattern);

    // `u.id` breaks ties. Without it the order of rows sharing a sort key is
    // whatever the plan happens to produce, which differs between the page
    // queries — a directory import stamps hundreds of users with the same
    // `created_at`, and those are exactly the rows a page boundary can drop or
    // repeat.
    let page_sql = format!(
        "SELECT {USER_COLS} FROM users u WHERE {USER_SEARCH_SQL} \
         ORDER BY {column} {direction}, u.id ASC LIMIT $2 OFFSET $3"
    );
    let count_sql = format!("SELECT COUNT(*) FROM users u WHERE {USER_SEARCH_SQL}");

    let (users, total) = tokio::try_join!(
        sqlx::query_as::<_, User>(&page_sql)
            .bind(&pattern)
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.pool),
        sqlx::query_scalar::<_, i64>(&count_sql)
            .bind(&pattern)
            .fetch_one(&state.pool),
    )?;

    #[derive(sqlx::FromRow)]
    struct IdentRow {
        user_id: Uuid,
        provider_code: String,
        display_name: String,
        provider_type: String,
    }

    // Scoped to the page. Both of these used to read every row of their table on
    // every request — a full scan of `user_identities` and a sort of the whole
    // `directory_entries` link table — to decorate two dozen users.
    let ids: Vec<Uuid> = users.iter().map(|u| u.id).collect();

    let idents = sqlx::query_as::<_, IdentRow>(
        r#"
        SELECT ui.user_id, ui.provider_code, p.display_name, p.provider_type
        FROM user_identities ui
        JOIN upstream_providers p ON p.code = ui.provider_code
        WHERE ui.user_id = ANY($1::uuid[])
        ORDER BY ui.linked_at ASC
        "#,
    )
    .bind(&ids)
    .fetch_all(&state.pool)
    .await?;

    #[derive(sqlx::FromRow)]
    struct ManagedRow {
        user_id: Uuid,
        code: String,
    }

    // Same precedence order as `directory::managing_source`, batched for the
    // whole page rather than one query per row.
    let managed = sqlx::query_as::<_, ManagedRow>(
        r#"
        SELECT e.user_id, s.code
        FROM directory_entries e
        JOIN directory_sources s ON s.id = e.source_id
        WHERE e.user_id = ANY($1::uuid[])
        ORDER BY s.priority ASC, s.code ASC
        "#,
    )
    .bind(&ids)
    .fetch_all(&state.pool)
    .await?;

    let mut by_user: std::collections::HashMap<Uuid, Vec<SsoIdentityBrief>> =
        std::collections::HashMap::new();
    for row in idents {
        by_user
            .entry(row.user_id)
            .or_default()
            .push(SsoIdentityBrief {
                provider_code: row.provider_code,
                display_name: row.display_name,
                provider_type: row.provider_type,
            });
    }

    let mut managed_by_user: std::collections::HashMap<Uuid, Vec<String>> =
        std::collections::HashMap::new();
    for row in managed {
        managed_by_user
            .entry(row.user_id)
            .or_default()
            .push(row.code);
    }

    let users = users
        .into_iter()
        .map(|u| {
            let has_password = !u.password_hash.is_empty();
            let sso_identities = by_user.remove(&u.id).unwrap_or_default();
            let directory_sources = managed_by_user.remove(&u.id).unwrap_or_default();
            let scim_managed = u.scim_managed;
            AdminUserListItem {
                user: PublicUser::from(u),
                has_password,
                sso_identities,
                directory_sources,
                scim_managed,
            }
        })
        .collect();
    Ok(Json(AdminUserList {
        users,
        total,
        limit,
        offset,
    }))
}

#[derive(Debug, serde::Serialize)]
struct SsoIdentityBrief {
    provider_code: String,
    display_name: String,
    provider_type: String,
}

#[derive(Debug, serde::Serialize)]
struct AdminUserListItem {
    #[serde(flatten)]
    user: PublicUser,
    has_password: bool,
    sso_identities: Vec<SsoIdentityBrief>,
    /// Directory sources owning this user's managed attributes, highest
    /// precedence first. Empty = not directory-managed, i.e. locally editable.
    directory_sources: Vec<String>,
    /// True when the SCIM client owns this user's managed attributes. A separate
    /// field from `directory_sources` rather than another entry in it, because a
    /// source code is operator-chosen and `"scim"` is a valid code — one list
    /// could not tell them apart.
    scim_managed: bool,
}

#[derive(Debug, Deserialize)]
struct EmailCheckQuery {
    email: String,
}

async fn check_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<EmailCheckQuery>,
) -> AppResult<Json<serde_json::Value>> {
    require_staff_user(&state, &headers).await?;
    let email = q.email.trim().to_lowercase();
    let exists = if email.is_empty() {
        false
    } else {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
            .bind(&email)
            .fetch_one(&state.pool)
            .await?;
        n > 0
    };
    Ok(Json(json!({ "exists": exists })))
}

#[derive(Debug, Deserialize)]
struct UsernameCheckQuery {
    username: String,
}

async fn check_username(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<UsernameCheckQuery>,
) -> AppResult<Json<serde_json::Value>> {
    require_staff_user(&state, &headers).await?;
    let username = q.username.trim().to_lowercase();
    let exists = if username.is_empty() {
        false
    } else {
        let n: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = $1 OR email = $1")
                .bind(&username)
                .fetch_one(&state.pool)
                .await?;
        n > 0
    };
    Ok(Json(json!({ "exists": exists })))
}

#[derive(Debug, Deserialize)]
struct PhoneCheckQuery {
    phone: String,
    exclude_id: Option<Uuid>,
}

async fn check_phone(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PhoneCheckQuery>,
) -> AppResult<Json<serde_json::Value>> {
    require_staff_user(&state, &headers).await?;
    let phone = q.phone.trim().to_string();
    let exists = if phone.is_empty() {
        false
    } else {
        phone_exists(&state.pool, &phone, q.exclude_id).await?
    };
    Ok(Json(json!({ "exists": exists })))
}

/// Returns true when a non-null `phone` already belongs to another user.
pub(crate) async fn phone_exists(
    pool: &sqlx::PgPool,
    phone: &str,
    exclude_id: Option<Uuid>,
) -> AppResult<bool> {
    let n: i64 = match exclude_id {
        Some(id) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE phone = $1 AND id <> $2")
                .bind(phone)
                .bind(id)
                .fetch_one(pool)
                .await?
        }
        None => {
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE phone = $1")
                .bind(phone)
                .fetch_one(pool)
                .await?
        }
    };
    Ok(n > 0)
}

pub(crate) fn normalize_phone(raw: Option<String>) -> AppResult<Option<String>> {
    let Some(raw) = raw else { return Ok(None) };
    let t = raw.trim().to_string();
    if t.is_empty() {
        return Ok(None);
    }
    let valid = t
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | ' ' | '(' | ')'));
    if !valid || t.len() < 6 || t.len() > 20 {
        return Err(AppError::bad_request("invalid phone number"));
    }
    Ok(Some(t))
}

#[derive(Debug, Deserialize)]
struct CreateUserBody {
    email: String,
    password: String,
    username: Option<String>,
    display_name: Option<String>,
    role: Option<String>,
    groups: Option<Vec<String>>,
    phone: Option<String>,
    must_change_password: Option<bool>,
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateUserBody>,
) -> AppResult<Json<PublicUser>> {
    let actor = require_staff_user(&state, &headers).await?;

    let email = body.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(AppError::bad_request("invalid email"));
    }
    // Before the uniqueness checks: an address outside the allowlist is not a
    // duplicate problem, and reporting it as one would send the caller looking
    // for an account that does not exist.
    crate::admission::ensure_provision_allowed(
        &state,
        &email,
        crate::admission::via::ADMIN,
        crate::http::extract::user_agent(&headers),
    )
    .await?;
    let email_exists: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1 OR username = $1")
            .bind(&email)
            .fetch_one(&state.pool)
            .await?;
    if email_exists > 0 {
        return Err(AppError::bad_request("email already exists"));
    }

    let username = normalize_username(body.username.as_deref());
    if let Some(u) = &username {
        let username_exists: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = $1 OR email = $1")
                .bind(u)
                .fetch_one(&state.pool)
                .await?;
        if username_exists > 0 {
            return Err(AppError::bad_request("username already exists"));
        }
    }
    validate_password_strength(&body.password, state.config.password_min_length)
        .map_err(|e| AppError::bad_request(e.to_string()))?;

    let role = Role::parse(body.role.as_deref().unwrap_or("member"))?;
    if !actor.can_assign_role(role) {
        return Err(AppError::forbidden("cannot assign this role"));
    }

    let display_name = body
        .display_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| email.split('@').next().unwrap_or("user").to_string());
    let id = Uuid::new_v4();
    let sub = id.to_string();
    let password_hash = hash_password_offloaded(&body.password).await?;
    let groups = body.groups.unwrap_or_default();
    let phone = normalize_phone(body.phone)?;
    if let Some(p) = &phone {
        if phone_exists(&state.pool, p, None).await? {
            return Err(AppError::bad_request("phone already exists"));
        }
    }

    let mut new_user = NewUser::new(id, &sub, &email, &display_name, &password_hash);
    new_user.role = role.as_str();
    new_user.username = username.as_deref();
    new_user.groups = &groups;
    new_user.phone = phone.as_deref();
    new_user.must_change_password = body.must_change_password.unwrap_or(false);

    let user = insert_user(&state.pool, &new_user)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db) if db.constraint() == Some("users_email_key") => {
                AppError::bad_request("email already exists")
            }
            sqlx::Error::Database(db) if db.constraint() == Some("users_phone_key") => {
                AppError::bad_request("phone already exists")
            }
            other => AppError::from(other),
        })?;

    record_password_history(&state.pool, user.id, &user.password_hash).await?;

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "user.create",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "email": user.email, "role": user.role }),
            ip: None,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(PublicUser::from(user)))
}

#[derive(Debug, Deserialize)]
struct UpdateUserBody {
    email: Option<String>,
    username: Option<String>,
    display_name: Option<String>,
    role: Option<String>,
    password: Option<String>,
    status: Option<String>,
    mfa_required: Option<bool>,
    must_change_password: Option<bool>,
    groups: Option<Vec<String>>,
    phone: Option<String>,
}

async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateUserBody>,
) -> AppResult<Json<PublicUser>> {
    let actor = require_staff_user(&state, &headers).await?;
    let target = user_by_id(&state.pool, id).await?;
    if !actor.can_mutate_user(&target) {
        return Err(AppError::forbidden("cannot modify this user"));
    }

    // Directory-owned attributes are read-only locally (§5). Checked here —
    // before any side effect such as password history or session revocation —
    // and against the *normalized* incoming value, so re-sending the current
    // value is not treated as a write.
    if let Some(authority) = crate::authority::managing_authority(&state.pool, id).await? {
        let attempts = [
            (
                "email",
                body.email
                    .as_deref()
                    .map(|e| e.trim().to_lowercase())
                    .is_some_and(|e| e != target.email),
            ),
            (
                "username",
                body.username.as_ref().is_some_and(|_| {
                    normalize_username(body.username.as_deref()) != target.username
                }),
            ),
            (
                "display_name",
                body.display_name
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|d| !d.is_empty() && d != target.display_name),
            ),
        ];
        for (field, changed) in attempts {
            if !changed {
                continue;
            }
            if let Some(msg) = authority.write_error(field) {
                audit_managed_write_blocked(&state, &headers, &actor, id, &authority, field).await;
                return Err(AppError::forbidden(msg));
            }
        }
    }

    let email = if let Some(e) = body.email {
        let e = e.trim().to_lowercase();
        if e.is_empty() || !e.contains('@') {
            return Err(AppError::bad_request("invalid email"));
        }
        e
    } else {
        target.email.clone()
    };

    if email != target.email {
        // Moving an account onto a domain the allowlist excludes is the same act
        // as creating one there, and has to be refused the same way — otherwise
        // the list could be walked around with one `PUT` on an existing account,
        // which is the shape of a hole rather than of a policy.
        crate::admission::ensure_provision_allowed(
            &state,
            &email,
            crate::admission::via::ADMIN,
            crate::http::extract::user_agent(&headers),
        )
        .await?;
        let email_exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE (email = $1 OR username = $1) AND id <> $2",
        )
        .bind(&email)
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
        if email_exists > 0 {
            return Err(AppError::bad_request("email already exists"));
        }
    }

    let username = if body.username.is_some() {
        normalize_username(body.username.as_deref())
    } else {
        target.username.clone()
    };
    if let Some(u) = &username {
        if target.username.as_deref() != Some(u.as_str()) {
            let username_exists: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM users WHERE (username = $1 OR email = $1) AND id <> $2",
            )
            .bind(u)
            .bind(id)
            .fetch_one(&state.pool)
            .await?;
            if username_exists > 0 {
                return Err(AppError::bad_request("username already exists"));
            }
        }
    }

    let display_name = body
        .display_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| target.display_name.clone());

    let role = if let Some(r) = body.role {
        let role = Role::parse(&r)?;
        if !actor.can_assign_role(role) {
            return Err(AppError::forbidden("cannot assign this role"));
        }
        // Managers cannot demote/promote involving admins (already blocked by can_mutate)
        role.as_str().to_string()
    } else {
        target.role.clone()
    };

    // One parse feeds the local intent, so an explicit `status` in the body
    // states it and an absent one leaves it as the target already has it.
    let requested_access = match body.status.as_deref() {
        None => None,
        Some("active") => Some(UserAccess::Enabled),
        Some("disabled") => Some(UserAccess::Disabled),
        Some(_) => return Err(AppError::bad_request("invalid status")),
    };
    let local_disabled = requested_access.map_or(target.local_disabled, UserAccess::local_disabled);
    // The state this request leaves behind: the admin states its own intent, the
    // upstream flags are untouched, and `status` is the answer from all three.
    // Used for the guards below; the UPDATE derives the same value in SQL.
    let status = status_from_flags(
        local_disabled,
        target.directory_disabled,
        target.scim_disabled,
    );

    if status == "disabled" && actor.id == id {
        return Err(AppError::bad_request("cannot disable yourself"));
    }

    let mfa_required = body.mfa_required.unwrap_or(target.mfa_required);
    let must_change_password = body
        .must_change_password
        .unwrap_or(target.must_change_password);
    let groups = body.groups.clone().unwrap_or_else(|| target.groups.clone());
    let phone = if body.phone.is_some() {
        normalize_phone(body.phone)?
    } else {
        target.phone.clone()
    };
    if let Some(p) = &phone {
        if target.phone.as_deref() != Some(p.as_str())
            && phone_exists(&state.pool, p, Some(id)).await?
        {
            return Err(AppError::bad_request("phone already exists"));
        }
    }

    // `local_disabled` was derived above from the same parse as `status`.

    // If a new password is provided, validate strength + history before persisting.
    if let Some(pw) = body.password.as_deref() {
        if !pw.is_empty() {
            set_user_password(
                &state.pool,
                id,
                pw,
                state.config.password_min_length,
                state.config.password_history_size,
            )
            .await?;
        }
    }

    let user = sqlx::query_as::<_, User>(&format!(
        r#"
        UPDATE users
        SET email = $2, display_name = $3, role = $4,
            mfa_required = $5, must_change_password = $6, groups = $7, phone = $8,
            username = $9, local_disabled = $10,
            status = CASE WHEN $10 OR directory_disabled OR scim_disabled
                          THEN 'disabled' ELSE 'active' END,
            updated_at = NOW()
        WHERE id = $1
        RETURNING {USER_COLS}
        "#
    ))
    .bind(id)
    .bind(&email)
    .bind(&display_name)
    .bind(&role)
    .bind(mfa_required)
    .bind(must_change_password)
    .bind(groups)
    .bind(phone)
    .bind(&username)
    .bind(local_disabled)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("users_email_key") => {
            AppError::bad_request("email already exists")
        }
        sqlx::Error::Database(db) if db.constraint() == Some("users_phone_key") => {
            AppError::bad_request("phone already exists")
        }
        sqlx::Error::Database(db) if db.constraint() == Some("users_username_key") => {
            AppError::bad_request("username already exists")
        }
        other => AppError::from(other),
    })?;

    if status == "disabled" {
        revoke_all_sessions(&state.pool, id).await?;
    }

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "user.update",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({
                "email": user.email,
                "role": user.role,
                "status": user.status,
                "mfa_required": user.mfa_required,
                "must_change_password": user.must_change_password,
            }),
            ip: None,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(PublicUser::from(user)))
}

async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_admin_user(&state, &headers).await?;
    if actor.id == id {
        return Err(AppError::bad_request("cannot delete yourself"));
    }
    let target = user_by_id(&state.pool, id).await?;
    // Upstream deletions only disable (D3) and the same rule holds locally, so a
    // managed user is never hard-deleted — use the local disable intent instead.
    if let Some(authority) = crate::authority::managing_authority(&state.pool, id).await? {
        audit_managed_write_blocked(&state, &headers, &actor, id, &authority, "delete").await;
        return Err(AppError::forbidden(authority.delete_error()));
    }
    let res = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("user not found".into()));
    }
    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "user.delete",
            resource_type: "user",
            resource_id: Some(id.to_string()),
            detail: json!({ "email": target.email, "role": target.role }),
            ip: None,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn disable_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<PublicUser>> {
    let actor = require_staff_user(&state, &headers).await?;
    if actor.id == id {
        return Err(AppError::bad_request("cannot disable yourself"));
    }
    let target = user_by_id(&state.pool, id).await?;
    if !actor.can_mutate_user(&target) {
        return Err(AppError::forbidden("cannot modify this user"));
    }
    let user = set_user_access(&state, id, UserAccess::Disabled).await?;
    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "user.disable",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "email": user.email }),
            ip: None,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;
    Ok(Json(PublicUser::from(user)))
}

async fn enable_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<PublicUser>> {
    let actor = require_staff_user(&state, &headers).await?;
    let target = user_by_id(&state.pool, id).await?;
    if !actor.can_mutate_user(&target) {
        return Err(AppError::forbidden("cannot modify this user"));
    }
    let user = set_user_access(&state, id, UserAccess::Enabled).await?;
    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "user.enable",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "email": user.email }),
            ip: None,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;
    Ok(Json(PublicUser::from(user)))
}

#[derive(Debug, Deserialize)]
struct BatchDisableBody {
    ids: Vec<Uuid>,
}

async fn batch_disable_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BatchDisableBody>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_staff_user(&state, &headers).await?;
    if body.ids.is_empty() {
        return Err(AppError::bad_request("ids required"));
    }
    if body.ids.contains(&actor.id) {
        return Err(AppError::bad_request("cannot disable yourself"));
    }

    // Which of the ids exist and which the actor may touch, in one query. The
    // per-user version was a `user_by_id` each, and a `set_user_access` and a
    // session delete after that.
    let targets: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, role FROM users WHERE id = ANY($1::uuid[])")
            .bind(&body.ids)
            .fetch_all(&state.pool)
            .await?;

    let allowed: Vec<Uuid> = targets
        .into_iter()
        .filter(|(_, role)| actor.can_mutate_role(role))
        .map(|(id, _)| id)
        .collect();

    // Read back rather than counted: a user deleted between the two statements
    // is not disabled, which is what the loop's `NotFound` arm did too.
    let disabled = disable_users(&state, &allowed).await?;

    // The single-user endpoint records one event per disable; this one recorded
    // none at all, so a bulk disable left no trace of who was affected.
    let events: Vec<AuditEvent> = disabled
        .iter()
        .map(|(id, email)| AuditEvent {
            actor: Some(actor.clone()),
            action: "user.disable",
            resource_type: "user",
            resource_id: Some(id.to_string()),
            detail: json!({ "email": email, "bulk": true }),
            ip: None,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        })
        .collect();
    let count = events.len() as i64;
    crate::audit::record_many(&state, events).await;

    Ok(Json(serde_json::json!({ "disabled": count })))
}

async fn revoke_user_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_staff_user(&state, &headers).await?;
    let target = user_by_id(&state.pool, id).await?;
    if !actor.can_mutate_user(&target) {
        return Err(AppError::forbidden("cannot modify this user"));
    }
    let revoked = revoke_all_sessions(&state.pool, id).await?;
    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "user.sessions_revoked",
            resource_type: "user",
            resource_id: Some(id.to_string()),
            detail: json!({ "email": target.email, "revoked": revoked }),
            ip: None,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;
    Ok(Json(json!({ "revoked": revoked })))
}

/// The two states an admin can put an account in.
///
/// A single value rather than a `status` string plus a `local_disabled` bool,
/// because those two are not independent: an explicit local change must record
/// the disable intent, or the next directory sync sees the account as simply
/// "upstream active" and silently re-enables it (migration `024`).
///
/// The value states the *local* intent only. It no longer implies a `status`:
/// since migration `026` an account is disabled when any authority says so, so
/// the admin's enable cannot release a claim the directory or the IdP still
/// holds. `status` is derived from all three flags, never set from here.
///
/// Deliberately not used by SCIM: deactivating a user upstream is not a local
/// admin's disable intent, so SCIM must not set `local_disabled`. Keeping this
/// in the admin module rather than a general entity layer is what stops it
/// being picked up for that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAccess {
    Enabled,
    Disabled,
}

impl UserAccess {
    /// The `users.local_disabled` value: the local intent that must survive the
    /// next sync.
    pub fn local_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }
}

/// Puts an account into a local access state and revokes its sessions if that
/// state is disabled.
///
/// Writes only `local_disabled` — the admin's own intent — and re-derives
/// `status` from it plus the upstream flags. A local enable therefore cannot
/// release an account the directory or the IdP is still holding disabled, which
/// is the point: no authority can override another (migration `026`).
///
/// One operation instead of a status write plus a paired flag, so the
/// `status`/`local_disabled` pairing cannot be got wrong, and so disabling
/// cannot leave live sessions behind: a disabled account is already refused by
/// `user_from_session_token`'s status filter, but the rows should not linger.
///
/// `Exposed for tests` — `crates/signet/tests/user_access.rs` pins the pairing
/// and the revocation, which no HTTP-level test would reach.
pub async fn set_user_access(state: &AppState, id: Uuid, access: UserAccess) -> AppResult<User> {
    let user = sqlx::query_as::<_, User>(&format!(
        r#"
        UPDATE users SET
            local_disabled = $2,
            status = CASE WHEN $2 OR directory_disabled OR scim_disabled
                          THEN 'disabled' ELSE 'active' END,
            updated_at = NOW()
        WHERE id = $1
        RETURNING {USER_COLS}
        "#
    ))
    .bind(id)
    .bind(access.local_disabled())
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("user not found"))?;

    if access == UserAccess::Disabled {
        revoke_all_sessions(&state.pool, id).await?;
    }
    Ok(user)
}

/// Disables every existing user in `ids` in one statement, returning the
/// `(id, email)` of the rows that changed.
///
/// The batch sibling of [`set_user_access`] for [`UserAccess::Disabled`]. That
/// path is two statements per user plus a session delete, so the "disable
/// selected" button on the users list was 3+N round trips for N accounts.
///
/// `status = 'disabled'` is written literally rather than derived from the
/// three flags the way [`set_user_access`] does it, because `local_disabled`
/// is being set: the migration `026` CHECK makes 'disabled' the only status
/// consistent with that, so a row written here cannot disagree with a row
/// written there.
pub async fn disable_users(state: &AppState, ids: &[Uuid]) -> AppResult<Vec<(Uuid, String)>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let disabled: Vec<(Uuid, String)> = sqlx::query_as(
        "UPDATE users SET local_disabled = TRUE, status = 'disabled', updated_at = NOW() \
         WHERE id = ANY($1::uuid[]) \
         RETURNING id, email",
    )
    .bind(ids)
    .fetch_all(&state.pool)
    .await?;
    crate::auth::session::revoke_sessions_for(
        &state.pool,
        &disabled.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
    )
    .await?;
    Ok(disabled)
}

/// Records a refused local write to a directory-owned attribute.
///
/// The refusal itself is visible in the API response; the audit entry keeps the
/// attempt on record even though nothing changed.
async fn audit_managed_write_blocked(
    state: &AppState,
    headers: &HeaderMap,
    actor: &User,
    user_id: Uuid,
    authority: &crate::authority::Authority,
    field: &str,
) {
    record(
        state,
        AuditEvent {
            actor: Some(actor.clone()),
            action: crate::directory::AUDIT_MANAGED_WRITE_BLOCKED,
            resource_type: "user",
            resource_id: Some(user_id.to_string()),
            detail: json!({ "source": authority.code(), "field": field }),
            ip: None,
            user_agent: crate::http::extract::user_agent(headers),
            client_id: None,
        },
    )
    .await;
}
