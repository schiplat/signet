use crate::audit::{record, AuditEvent};
use crate::auth::session::{
    clear_session_cookie, cookie_value, current_user, destroy_session, list_sessions,
    revoke_all_sessions, revoke_session_by_id, session_id_for_token, SESSION_COOKIE,
};
use crate::error::{AppError, AppResult};
use crate::http_util::client_ip;
use crate::mfa::{begin_login_mfa_flow, force_password_change};
use crate::models::{PublicUser, User, USER_COLS};
use crate::password::{set_user_password, verify_password};
use crate::state::AppState;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use uuid::Uuid;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/login/password-change", post(force_password_change))
        .route("/logout", post(logout))
        .route("/me", get(me).patch(update_me))
        .route("/me/password", post(change_password))
        .route(
            "/me/sessions",
            get(list_my_sessions).post(revoke_other_sessions),
        )
        .route("/me/sessions/{id}", delete(revoke_my_session))
        .route("/me/consents", get(list_my_consents))
        .route("/me/consents/{client_id}", delete(revoke_my_consent))
        .route("/me/activity", get(my_activity))
}

#[derive(Debug, Deserialize)]
struct LoginBody {
    email: String,
    password: String,
    /// Optional `/oauth/authorize?...` return URL; used to attribute the
    /// login (and its audit trail) to the initiating OAuth app.
    #[serde(default)]
    return_to: Option<String>,
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<LoginBody>,
) -> AppResult<impl IntoResponse> {
    let email = body.email.trim().to_lowercase();
    let client_id =
        crate::audit::resolve_audit_client_id(&state.pool, body.return_to.as_deref()).await;
    let user = sqlx::query_as::<_, User>(&format!(
        "SELECT {USER_COLS} FROM users WHERE email = $1 OR username = $1"
    ))
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("invalid email/username or password"))?;

    if user.status != "active" {
        return Err(AppError::unauthorized("account disabled"));
    }

    let ip = client_ip(&headers, Some(addr));

    let lock: (i32, Option<DateTime<Utc>>) =
        sqlx::query_as("SELECT failed_login_attempts, locked_until FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(&state.pool)
            .await?;
    if let Some(locked_until) = lock.1 {
        if locked_until > Utc::now() {
            let secs = (locked_until - Utc::now()).num_seconds().max(1);
            let mins = (secs as f64 / 60.0).ceil() as i64;
            return Err(AppError::unauthorized(format!(
                "account locked, try again in ~{mins} minute(s)"
            )));
        }
    }

    if !verify_password(&body.password, &user.password_hash)? {
        crate::metrics::inc_login_failures();
        record_login_failure(
            &state,
            &user,
            ip.clone(),
            crate::http_util::user_agent(&headers),
            client_id.clone(),
        )
        .await?;
        let attempts = lock.0 + 1;
        if (attempts as i64) >= state.config.max_login_attempts {
            let until = Utc::now() + Duration::minutes(state.config.lockout_minutes);
            sqlx::query(
                "UPDATE users SET failed_login_attempts = 0, locked_until = $2, updated_at = NOW() WHERE id = $1",
            )
            .bind(user.id)
            .bind(until)
            .execute(&state.pool)
            .await?;
            return Err(AppError::unauthorized(
                "too many failed attempts, account locked",
            ));
        }
        sqlx::query("UPDATE users SET failed_login_attempts = $2 WHERE id = $1")
            .bind(user.id)
            .bind(attempts)
            .execute(&state.pool)
            .await?;
        return Err(AppError::unauthorized("invalid email or password"));
    }

    sqlx::query("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1")
        .bind(user.id)
        .execute(&state.pool)
        .await?;

    begin_login_mfa_flow(
        &state,
        jar,
        user,
        ip,
        crate::http_util::user_agent(&headers),
        client_id,
    )
    .await
}

async fn record_login_failure(
    state: &AppState,
    user: &User,
    ip: Option<String>,
    user_agent: Option<String>,
    client_id: Option<String>,
) -> AppResult<()> {
    record(
        &state.pool,
        AuditEvent {
            actor: Some(user.clone()),
            action: "auth.login_failed",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({}),
            ip,
            user_agent,
            client_id,
        },
    )
    .await;
    Ok(())
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> AppResult<impl IntoResponse> {
    if let Some(token) = cookie_value(&headers, SESSION_COOKIE) {
        destroy_session(&state.pool, &token).await?;
    }
    let jar = jar.add(clear_session_cookie(state.config.cookie_secure));
    Ok((jar, Json(json!({ "ok": true }))))
}

async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let user = current_user(&state, &headers).await?;
    Ok(Json(json!({ "user": PublicUser::from(user) })))
}

async fn list_my_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    let sessions = list_sessions(&state.pool, user.id).await?;
    let current_id = match cookie_value(&headers, SESSION_COOKIE) {
        Some(t) => session_id_for_token(&state.pool, &t).await?,
        None => None,
    };
    Ok(Json(json!({
        "sessions": sessions,
        "current_session_id": current_id,
    })))
}

async fn revoke_my_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    let current_id = match cookie_value(&headers, SESSION_COOKIE) {
        Some(t) => session_id_for_token(&state.pool, &t).await?,
        None => None,
    };
    if Some(id) == current_id {
        return Err(AppError::bad_request(
            "cannot revoke your current session; use log out instead",
        ));
    }
    if !revoke_session_by_id(&state.pool, user.id, id).await? {
        return Err(AppError::NotFound("session not found".into()));
    }
    Ok(Json(json!({ "ok": true })))
}

async fn revoke_other_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    match cookie_value(&headers, SESSION_COOKIE) {
        Some(t) => {
            if let Some(current_id) = session_id_for_token(&state.pool, &t).await? {
                sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id <> $2")
                    .bind(user.id)
                    .bind(current_id)
                    .execute(&state.pool)
                    .await?;
            }
        }
        None => {
            revoke_all_sessions(&state.pool, user.id).await?;
        }
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, sqlx::FromRow)]
struct MyConsent {
    client_id: String,
    scopes: String,
    granted_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct MyActivityRow {
    id: Uuid,
    action: String,
    resource_type: String,
    resource_id: Option<String>,
    detail: Value,
    ip: Option<String>,
    browser: Option<String>,
    os: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, serde::Deserialize)]
struct ActivityQuery {
    page: Option<i64>,
    page_size: Option<i64>,
}

/// Current user's own audit trail — login history plus account/security actions.
/// Available to every authenticated role (self-service, not staff-scoped).
async fn my_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ActivityQuery>,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;

    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * page_size;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE actor_user_id = $1")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await?;

    let items = sqlx::query_as::<_, MyActivityRow>(
        r#"
        SELECT id, action, resource_type, resource_id, detail, ip, browser, os, created_at
        FROM audit_logs
        WHERE actor_user_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(user.id)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    // Security summary backing the header cards (self-service, distinct from the
    // global Overview snapshot).
    let last_login = sqlx::query_as::<
        _,
        (
            Option<String>,
            Option<String>,
            Option<String>,
            DateTime<Utc>,
        ),
    >(
        "SELECT ip, browser, os, created_at FROM audit_logs \
         WHERE actor_user_id = $1 AND action = 'auth.login' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user.id)
    .fetch_optional(&state.pool)
    .await?;

    let active_sessions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND expires_at > NOW()",
    )
    .bind(user.id)
    .fetch_one(&state.pool)
    .await?;

    let passkey_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = $1")
            .bind(user.id)
            .fetch_one(&state.pool)
            .await?;

    let consent_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_consents WHERE user_id = $1")
            .bind(user.id)
            .fetch_one(&state.pool)
            .await?;

    Ok(Json(json!({
        "summary": {
            "last_login": last_login.map(|(ip, browser, os, at)| json!({
                "ip": ip,
                "browser": browser,
                "os": os,
                "at": at,
            })),
            "active_sessions": active_sessions,
            "totp_enabled": user.totp_enabled,
            "passkey_count": passkey_count,
            "consent_count": consent_count,
        },
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    })))
}

async fn list_my_consents(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    let rows = sqlx::query_as::<_, MyConsent>(
        r#"
        SELECT client_id, scopes, granted_at
        FROM oauth_consents
        WHERE user_id = $1
        ORDER BY granted_at DESC
        "#,
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;

    let consents: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "client_id": r.client_id,
                "scopes": r.scopes.split_whitespace().collect::<Vec<_>>(),
                "granted_at": r.granted_at,
            })
        })
        .collect();

    Ok(Json(json!({ "consents": consents })))
}

async fn revoke_my_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    let res = sqlx::query("DELETE FROM oauth_consents WHERE user_id = $1 AND client_id = $2")
        .bind(user.id)
        .bind(&client_id)
        .execute(&state.pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("consent not found".into()));
    }

    // Also revoke any outstanding refresh tokens so the client can no longer
    // refresh on the user's behalf once consent is withdrawn.
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = NOW() \
         WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL",
    )
    .bind(user.id)
    .bind(&client_id)
    .execute(&state.pool)
    .await?;

    record(
        &state.pool,
        AuditEvent {
            actor: Some(user),
            action: "oauth.consent_revoke",
            resource_type: "client",
            resource_id: Some(client_id),
            detail: json!({}),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
struct UpdateMeBody {
    display_name: Option<String>,
    phone: Option<String>,
}

async fn update_me(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpdateMeBody>,
) -> AppResult<Json<serde_json::Value>> {
    let user = current_user(&state, &headers).await?;
    let display_name = body
        .display_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::bad_request("display_name required"))?;

    let phone = if body.phone.is_some() {
        crate::admin::normalize_phone(body.phone)?
    } else {
        user.phone.clone()
    };
    if let Some(p) = &phone {
        if user.phone.as_deref() != Some(p.as_str())
            && crate::admin::phone_exists(&state.pool, p, Some(user.id)).await?
        {
            return Err(AppError::bad_request("phone already exists"));
        }
    }

    let updated = sqlx::query_as::<_, crate::models::User>(&format!(
        r#"
        UPDATE users SET display_name = $2, phone = $3, updated_at = NOW()
        WHERE id = $1
        RETURNING {USER_COLS}
        "#
    ))
    .bind(user.id)
    .bind(&display_name)
    .bind(&phone)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("users_phone_key") => {
            AppError::bad_request("phone already exists")
        }
        other => AppError::from(other),
    })?;

    record(
        &state.pool,
        AuditEvent {
            actor: Some(user),
            action: "me.profile_update",
            resource_type: "user",
            resource_id: Some(updated.id.to_string()),
            detail: json!({ "display_name": display_name }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "user": PublicUser::from(updated) })))
}

#[derive(Debug, Deserialize)]
struct ChangePasswordBody {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordBody>,
) -> AppResult<Json<serde_json::Value>> {
    let user = current_user(&state, &headers).await?;
    if !verify_password(&body.current_password, &user.password_hash)? {
        return Err(AppError::unauthorized("current password is incorrect"));
    }
    set_user_password(
        &state.pool,
        user.id,
        &body.new_password,
        state.config.password_min_length,
        state.config.password_history_size,
    )
    .await?;

    record(
        &state.pool,
        AuditEvent {
            actor: Some(user.clone()),
            action: "auth.password_change",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({}),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "ok": true })))
}
