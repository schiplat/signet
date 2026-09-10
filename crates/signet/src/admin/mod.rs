mod clients;

use crate::audit::{record, AuditEvent};
use crate::auth::current_user;
use crate::auth::session::revoke_all_sessions;
use crate::crypto_util::{random_token, sha256_hex};
use crate::error::{AppError, AppResult};
use crate::models::{normalize_username, PublicUser, User, USER_COLS};
use crate::password::{
    hash_password, record_password_history, set_user_password, validate_password_strength,
};
use crate::roles::{require_admin_role, require_staff, Role};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::Utc;
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
    let issuer = state.config.issuer.trim_end_matches('/');
    Ok(Json(json!({
        "scim": {
            "enabled": scim_configured,
            "base_url": format!("{issuer}/scim/v2"),
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
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "scim.token_rotate",
            resource_type: "scim",
            resource_id: None,
            detail: json!({}),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
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

    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "scim.token_revoke",
            resource_type: "scim",
            resource_id: None,
            detail: json!({}),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
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

    let users_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.pool)
        .await?;
    let users_active: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE status = 'active'")
            .fetch_one(&state.pool)
            .await?;
    let users_disabled: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE status = 'disabled'")
            .fetch_one(&state.pool)
            .await?;
    let users_admin: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'")
            .fetch_one(&state.pool)
            .await?;
    let users_manager: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE role = 'manager' AND status = 'active'",
    )
    .fetch_one(&state.pool)
    .await?;
    let clients_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM client_apps")
        .fetch_one(&state.pool)
        .await?;
    let clients_enabled: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM client_apps WHERE enabled = TRUE")
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

    let logins_24h: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'auth.login' AND created_at > NOW() - INTERVAL '24 hours' {}",
        client_pred(1)
    ))
    .bind(&scope_client)
    .fetch_one(&state.pool)
    .await?;
    let logins_7d: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'auth.login' AND created_at > NOW() - INTERVAL '7 days' {}",
        client_pred(1)
    ))
    .bind(&scope_client)
    .fetch_one(&state.pool)
    .await?;
    let logins_30d: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'auth.login' AND created_at > NOW() - INTERVAL '30 days' {}",
        client_pred(1)
    ))
    .bind(&scope_client)
    .fetch_one(&state.pool)
    .await?;
    let unique_users_24h: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(DISTINCT actor_user_id) FROM audit_logs WHERE action = 'auth.login' AND created_at > NOW() - INTERVAL '24 hours' AND actor_user_id IS NOT NULL {}",
        client_pred(1)
    ))
    .bind(&scope_client)
    .fetch_one(&state.pool)
    .await?;
    let unique_users_7d: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(DISTINCT actor_user_id) FROM audit_logs WHERE action = 'auth.login' AND created_at > NOW() - INTERVAL '7 days' AND actor_user_id IS NOT NULL {}",
        client_pred(1)
    ))
    .bind(&scope_client)
    .fetch_one(&state.pool)
    .await?;
    let unique_users_30d: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(DISTINCT actor_user_id) FROM audit_logs WHERE action = 'auth.login' AND created_at > NOW() - INTERVAL '30 days' AND actor_user_id IS NOT NULL {}",
        client_pred(1)
    ))
    .bind(&scope_client)
    .fetch_one(&state.pool)
    .await?;

    let login_trend = sqlx::query_as::<_, LoginTrendPoint>(
        &format!(
            r#"
            WITH daily AS (
                SELECT (created_at AT TIME ZONE 'UTC')::date AS day,
                       COUNT(*)::bigint AS logins
                FROM audit_logs
                WHERE action = 'auth.login'
                  AND created_at >= ((CURRENT_DATE - INTERVAL '59 days')::timestamp AT TIME ZONE 'UTC')
                  {}
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
            client_pred(1)
        )
    )
    .bind(&scope_client)
    .fetch_all(&state.pool)
    .await?;

    // Hourly grain for the default 24h range: dense hourly buckets so the
    // x-axis is time-of-day, not dates.
    let login_trend_24h = sqlx::query_as::<_, LoginTrendHourPoint>(&format!(
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
                  {}
                GROUP BY 1
            )
            SELECT b.hour AS hour, COALESCE(c.logins, 0) AS logins
            FROM buckets b
            LEFT JOIN counts c ON c.hour = b.hour
            ORDER BY b.hour
            "#,
        client_pred(1)
    ))
    .bind(&scope_client)
    .fetch_all(&state.pool)
    .await?;

    let recent_logins = sqlx::query_as::<_, RecentLogin>(&format!(
        r#"
            SELECT actor_email, ip, browser, os, client_id, created_at
            FROM audit_logs
            WHERE action = 'auth.login'
              AND created_at > NOW() - INTERVAL '7 days'
              {}
            ORDER BY created_at DESC
            LIMIT 10
            "#,
        client_pred(1)
    ))
    .bind(&scope_client)
    .fetch_all(&state.pool)
    .await?;

    // Per-app aggregates over the last 30 days (global view only; when
    // scoped to one app the front end already knows the single row).
    let by_client: Vec<ClientUsage> = sqlx::query_as::<_, ClientUsage>(
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
    .fetch_all(&state.pool)
    .await?;

    // Browser / OS distribution over the last 30 days (login events).
    let browsers: Vec<NameCount> = sqlx::query_as::<_, NameCount>(&format!(
        r#"
            SELECT COALESCE(browser, 'Unknown') AS name, COUNT(*)::bigint AS count
            FROM audit_logs
            WHERE action = 'auth.login'
              AND created_at >= NOW() - INTERVAL '30 days'
              {}
            GROUP BY 1
            ORDER BY count DESC
            "#,
        client_pred(1)
    ))
    .bind(&scope_client)
    .fetch_all(&state.pool)
    .await?;

    let oses: Vec<NameCount> = sqlx::query_as::<_, NameCount>(&format!(
        r#"
            SELECT COALESCE(os, 'Unknown') AS name, COUNT(*)::bigint AS count
            FROM audit_logs
            WHERE action = 'auth.login'
              AND created_at >= NOW() - INTERVAL '30 days'
              {}
            GROUP BY 1
            ORDER BY count DESC
            "#,
        client_pred(1)
    ))
    .bind(&scope_client)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(AdminStats {
        users_total,
        users_active,
        users_disabled,
        users_admin,
        users_manager,
        clients_total,
        clients_enabled,
        logins_24h,
        logins_7d,
        logins_30d,
        unique_users_24h,
        unique_users_7d,
        unique_users_30d,
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

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<PublicUser>>> {
    require_staff_user(&state, &headers).await?;
    let users = sqlx::query_as::<_, User>(&format!(
        "SELECT {USER_COLS} FROM users ORDER BY created_at DESC"
    ))
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(users.into_iter().map(PublicUser::from).collect()))
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
    let password_hash = hash_password(&body.password)?;
    let now = Utc::now();
    let groups = body.groups.unwrap_or_default();
    let phone = normalize_phone(body.phone)?;
    if let Some(p) = &phone {
        if phone_exists(&state.pool, p, None).await? {
            return Err(AppError::bad_request("phone already exists"));
        }
    }
    let must_change_password = body.must_change_password.unwrap_or(false);

    let user = sqlx::query_as::<_, User>(&format!(
        r#"
        INSERT INTO users (id, sub, email, username, display_name, password_hash, status, role, groups, phone, must_change_password, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $8, $9, $10, $11, $11)
        RETURNING {USER_COLS}
        "#
    ))
    .bind(id)
    .bind(&sub)
    .bind(&email)
    .bind(&username)
    .bind(&display_name)
    .bind(password_hash)
    .bind(role.as_str())
    .bind(groups)
    .bind(phone)
    .bind(must_change_password)
    .bind(now)
    .fetch_one(&state.pool)
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
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "user.create",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "email": user.email, "role": user.role }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
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
    let target = load_user(&state, id).await?;
    if !actor.can_mutate_user(&target) {
        return Err(AppError::forbidden("cannot modify this user"));
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

    let status = if let Some(s) = body.status {
        match s.as_str() {
            "active" | "disabled" => s,
            _ => return Err(AppError::bad_request("invalid status")),
        }
    } else {
        target.status.clone()
    };

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
        SET email = $2, display_name = $3, role = $4, status = $5,
            mfa_required = $6, must_change_password = $7, groups = $8, phone = $9,
            username = $10, updated_at = NOW()
        WHERE id = $1
        RETURNING {USER_COLS}
        "#
    ))
    .bind(id)
    .bind(&email)
    .bind(&display_name)
    .bind(&role)
    .bind(&status)
    .bind(mfa_required)
    .bind(must_change_password)
    .bind(groups)
    .bind(phone)
    .bind(&username)
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
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id)
            .execute(&state.pool)
            .await?;
    }

    record(
        &state.pool,
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
            user_agent: crate::http_util::user_agent(&headers),
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
    let target = load_user(&state, id).await?;
    let res = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("user not found".into()));
    }
    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "user.delete",
            resource_type: "user",
            resource_id: Some(id.to_string()),
            detail: json!({ "email": target.email, "role": target.role }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
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
    let target = load_user(&state, id).await?;
    if !actor.can_mutate_user(&target) {
        return Err(AppError::forbidden("cannot modify this user"));
    }
    let user = set_status(&state, id, "disabled").await?;
    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "user.disable",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "email": user.email }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
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
    let target = load_user(&state, id).await?;
    if !actor.can_mutate_user(&target) {
        return Err(AppError::forbidden("cannot modify this user"));
    }
    let user = set_status(&state, id, "active").await?;
    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "user.enable",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "email": user.email }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
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

    let mut disabled = 0i64;
    for id in &body.ids {
        let Ok(target) = load_user(&state, *id).await else {
            continue;
        };
        if !actor.can_mutate_user(&target) {
            continue;
        }
        match set_status(&state, *id, "disabled").await {
            Ok(_) => disabled += 1,
            Err(AppError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }

    Ok(Json(serde_json::json!({ "disabled": disabled })))
}

async fn load_user(state: &AppState, id: Uuid) -> AppResult<User> {
    sqlx::query_as::<_, User>(&format!("SELECT {USER_COLS} FROM users WHERE id = $1"))
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::NotFound("user not found".into()))
}

async fn revoke_user_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let actor = require_staff_user(&state, &headers).await?;
    let target = load_user(&state, id).await?;
    if !actor.can_mutate_user(&target) {
        return Err(AppError::forbidden("cannot modify this user"));
    }
    let revoked = revoke_all_sessions(&state.pool, id).await?;
    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "user.sessions_revoked",
            resource_type: "user",
            resource_id: Some(id.to_string()),
            detail: json!({ "email": target.email, "revoked": revoked }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;
    Ok(Json(json!({ "revoked": revoked })))
}

async fn set_status(state: &AppState, id: Uuid, status: &str) -> AppResult<User> {
    let user = sqlx::query_as::<_, User>(&format!(
        r#"
        UPDATE users SET status = $2, updated_at = NOW()
        WHERE id = $1
        RETURNING {USER_COLS}
        "#
    ))
    .bind(id)
    .bind(status)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("user not found".into()))?;

    if status == "disabled" {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id)
            .execute(&state.pool)
            .await?;
    }
    Ok(user)
}
