use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use uuid::Uuid;

use crate::audit::{record, AuditEvent};
use crate::auth::session::{create_session, session_cookie};
use crate::bootstrap::admin_exists;
use crate::error::{AppError, AppResult};
use crate::http_util::{client_ip, user_agent};
use crate::models::{PublicUser, User, USER_COLS};
use crate::password::{hash_password, record_password_history, validate_password_strength};
use crate::state::AppState;

/// Advisory lock key serializing concurrent first-run setups (hex for "Signet").
const SETUP_LOCK_KEY: i64 = 0x5369_676E_6574;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/setup/status", get(setup_status))
        .route("/setup", post(setup_admin))
}

#[derive(Debug, Deserialize)]
struct SetupBody {
    email: String,
    password: String,
    display_name: Option<String>,
}

/// Public probe: whether the instance still needs a first admin.
async fn setup_status(State(state): State<AppState>) -> AppResult<Json<serde_json::Value>> {
    let needs_setup = !admin_exists(&state.pool).await?;
    Ok(Json(json!({ "needs_setup": needs_setup })))
}

/// Creates the first admin and signs them in. Rejects once an admin exists.
async fn setup_admin(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<SetupBody>,
) -> AppResult<impl IntoResponse> {
    let email = body.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(AppError::bad_request("invalid email"));
    }
    validate_password_strength(&body.password, state.config.password_min_length)
        .map_err(|e| AppError::bad_request(e.to_string()))?;

    let ip = client_ip(&headers, Some(addr));
    let user_agent = user_agent(&headers);

    let display_name = body
        .display_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| email.split('@').next().unwrap_or("admin").to_string());

    let id = Uuid::new_v4();
    let sub = id.to_string();
    let password_hash = hash_password(&body.password)?;

    // Serialize concurrent setups and re-check inside the lock so only one
    // admin can be created even under a race.
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(SETUP_LOCK_KEY)
        .execute(&mut *tx)
        .await?;

    if admin_exists(&mut *tx).await? {
        return Err(AppError::conflict("already configured"));
    }

    let user = sqlx::query_as::<_, User>(&format!(
        r#"
        INSERT INTO users (id, sub, email, display_name, password_hash, status, role, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, 'active', 'admin', NOW(), NOW())
        RETURNING {USER_COLS}
        "#
    ))
    .bind(id)
    .bind(&sub)
    .bind(&email)
    .bind(&display_name)
    .bind(password_hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("users_email_key") => {
            AppError::bad_request("email already exists")
        }
        other => AppError::from(other),
    })?;

    tx.commit().await?;

    record_password_history(&state.pool, user.id, &user.password_hash).await?;

    let token = create_session(
        &state.pool,
        user.id,
        state.config.session_ttl_hours,
        ip.as_deref(),
        user_agent.as_deref(),
    )
    .await?;
    let jar = jar.add(session_cookie(
        &token,
        state.config.cookie_secure,
        state.config.session_ttl_hours,
    ));

    record(
        &state.pool,
        AuditEvent {
            actor: Some(user.clone()),
            action: "setup.complete",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "email": user.email }),
            ip,
            user_agent,
            client_id: None,
        },
    )
    .await;

    tracing::info!(email = %user.email, "first-run admin created via setup");
    Ok((
        jar,
        Json(json!({ "status": "ok", "user": PublicUser::from(user) })),
    ))
}
