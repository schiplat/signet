use crate::crypto_util::{random_token, sha256_hex};
use crate::error::{AppError, AppResult};
use crate::password::set_user_password;
use crate::state::AppState;
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

const RESET_TTL_MINUTES: i64 = 30;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/password-reset/request", post(request_reset))
        .route("/password-reset/confirm", post(confirm_reset))
}

#[derive(Debug, Deserialize)]
struct RequestBody {
    email: String,
}

/// Always returns 200 to avoid leaking whether an account exists.
async fn request_reset(
    State(state): State<AppState>,
    Json(body): Json<RequestBody>,
) -> AppResult<Json<Value>> {
    let email = body.email.trim().to_lowercase();

    if let Some(user) = find_user_by_email(&state, &email).await? {
        // A directory-managed account has no local password to reset (§8.1), so
        // creating a token would send someone a link that cannot work. Staying
        // silent about it preserves the always-200 anti-enumeration behaviour
        // below while skipping the pointless mail.
        if let Some(source) = crate::directory::enabled_managing_source(&state.pool, user.0).await?
        {
            tracing::info!(
                email = %user.1,
                source = %source,
                "password reset requested for a directory-managed account; nothing to reset"
            );
            return Ok(Json(json!({ "ok": true })));
        }

        let token = random_token(32);
        let token_hash = sha256_hex(&token);
        let id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::minutes(RESET_TTL_MINUTES);

        // Invalidate prior outstanding tokens for this user.
        sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = $1")
            .bind(user.0)
            .execute(&state.pool)
            .await?;

        sqlx::query(
            r#"
            INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(id)
        .bind(user.0)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(&state.pool)
        .await?;

        let link = format!(
            "{}/reset-password?token={token}",
            state
                .config
                .public_base_url
                .as_deref()
                .unwrap_or(&state.config.issuer)
        );
        crate::email::send(
            &user.1,
            "Signet password reset",
            &format!(
                "A password reset was requested for {}. Use this link to set a new password:\n\n{link}\n\nThis link expires in 30 minutes.",
                user.1
            ),
        )
        .await;

        // Dev/test convenience: without a real mailer, surface the link once.
        if state.config.smtp_host.is_none() {
            tracing::info!(email = %user.1, link = %link, "password reset link (dev)");
        }
    } else {
        // Still pretend we sent something.
        tracing::info!(email = %email, "password reset requested for unknown email");
    }

    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
struct ConfirmBody {
    token: String,
    new_password: String,
}

async fn confirm_reset(
    State(state): State<AppState>,
    Json(body): Json<ConfirmBody>,
) -> AppResult<Json<Value>> {
    let token_hash = sha256_hex(&body.token);

    let row: (
        Uuid,
        Uuid,
        chrono::DateTime<Utc>,
        Option<chrono::DateTime<Utc>>,
    ) = sqlx::query_as(
        r#"
            SELECT id, user_id, expires_at, consumed_at
            FROM password_reset_tokens
            WHERE token_hash = $1
            "#,
    )
    .bind(&token_hash)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::bad_request("invalid or expired reset token"))?;

    if row.3.is_some() || row.2 < Utc::now() {
        return Err(AppError::bad_request("invalid or expired reset token"));
    }

    let user_id = row.1;

    set_user_password(
        &state.pool,
        user_id,
        &body.new_password,
        state.config.password_min_length,
        state.config.password_history_size,
    )
    .await?;

    // Consume token and force sign-out of all sessions.
    sqlx::query("UPDATE password_reset_tokens SET consumed_at = NOW() WHERE id = $1")
        .bind(row.0)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(&state.pool)
        .await?;

    Ok(Json(json!({ "ok": true })))
}

async fn find_user_by_email(state: &AppState, email: &str) -> AppResult<Option<(Uuid, String)>> {
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, email FROM users WHERE (email = $1 OR username = $1) AND status = 'active'",
    )
    .bind(email)
    .fetch_optional(&state.pool)
    .await?;
    Ok(row)
}
