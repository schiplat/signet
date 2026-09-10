use crate::crypto_util::{random_token, sha256_hex};
use crate::error::{AppError, AppResult};
use crate::models::User;
use crate::state::AppState;
use axum::http::HeaderMap;
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::PgPool;
use time::Duration as TimeDuration;
use uuid::Uuid;

pub const SESSION_COOKIE: &str = "signet_session";

pub async fn create_session(
    pool: &PgPool,
    user_id: Uuid,
    ttl_hours: i64,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> AppResult<String> {
    let token = random_token(32);
    let token_hash = sha256_hex(&token);
    let id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::hours(ttl_hours);

    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, token_hash, expires_at, ip, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(ip)
    .bind(user_agent)
    .execute(pool)
    .await?;

    Ok(token)
}

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct SessionInfo {
    pub id: Uuid,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub async fn list_sessions(pool: &PgPool, user_id: Uuid) -> AppResult<Vec<SessionInfo>> {
    sqlx::query_as::<_, SessionInfo>(
        r#"
        SELECT id, ip, user_agent, created_at, last_seen_at, expires_at
        FROM sessions
        WHERE user_id = $1 AND expires_at > NOW()
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)
}

pub async fn session_id_for_token(pool: &PgPool, token: &str) -> AppResult<Option<Uuid>> {
    let token_hash = sha256_hex(token);
    let id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM sessions WHERE token_hash = $1")
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;
    Ok(id)
}

pub async fn revoke_session_by_id(pool: &PgPool, user_id: Uuid, id: Uuid) -> AppResult<bool> {
    let res = sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn revoke_all_sessions(pool: &PgPool, user_id: Uuid) -> AppResult<u64> {
    let res = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

pub async fn destroy_session(pool: &PgPool, token: &str) -> AppResult<()> {
    let token_hash = sha256_hex(token);
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn user_from_session_token(pool: &PgPool, token: &str) -> AppResult<Option<User>> {
    let token_hash = sha256_hex(token);
    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT u.id, u.sub, u.email, u.username, u.display_name, u.password_hash, u.status, u.role,
               u.mfa_required, u.must_change_password, u.totp_enabled, u.totp_secret,
               u.groups, u.phone, u.provisioned_via, u.created_at, u.updated_at
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = $1
          AND s.expires_at > NOW()
          AND u.status = 'active'
        "#,
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

pub fn session_cookie(token: &str, secure: bool, ttl_hours: i64) -> Cookie<'static> {
    let mut cookie = Cookie::build((SESSION_COOKIE, token.to_string()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(TimeDuration::hours(ttl_hours))
        .build();
    if secure {
        cookie.set_secure(true);
    }
    cookie
}

pub fn clear_session_cookie(secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(TimeDuration::seconds(0))
        .build();
    if secure {
        cookie.set_secure(true);
    }
    cookie
}

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k == name {
                return Some(v.to_string());
            }
        }
    }
    None
}

pub async fn current_user(state: &AppState, headers: &HeaderMap) -> AppResult<User> {
    let token = cookie_value(headers, SESSION_COOKIE)
        .ok_or_else(|| AppError::unauthorized("not authenticated"))?;
    user_from_session_token(&state.pool, &token)
        .await?
        .ok_or_else(|| AppError::unauthorized("session expired or invalid"))
}
