use crate::auth::password::set_user_password;
use crate::crypto::util::{random_token, sha256_hex};
use crate::error::{AppError, AppResult};
use crate::http::extract::client_ip;
use crate::state::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
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
    /// Required when a CAPTCHA provider is configured — the reset door is the
    /// other unauthenticated entry a spray can work through (token emails are
    /// throttled, but the door itself is not otherwise gated).
    #[serde(default)]
    captcha_token: Option<String>,
}

/// Always returns 200 to avoid leaking whether an account exists.
async fn request_reset(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RequestBody>,
) -> AppResult<Json<Value>> {
    // The CAPTCHA gate before the address lookup: with the gate on, probing
    // "does this account exist" via the always-200 endpoint costs a solved
    // challenge per guess.
    let ip = client_ip(&headers, Some(addr));
    crate::captcha::require(&state, body.captcha_token.as_deref(), ip.as_deref()).await?;
    // Fail before looking at the address: with no transport, every request
    // would generate a token nothing delivers. A uniform 503 keeps the
    // always-200 anti-enumeration property (it says nothing about the account)
    // while refusing to pretend the mail went out.
    if !crate::email::configured(&state).await && !state.config.dev_log_links {
        return Err(AppError::unavailable(
            "password reset by email is not configured on this instance; \
             ask an administrator to set the SMTP relay in Settings",
        ));
    }
    let email = body.email.trim().to_lowercase();

    if let Some(user) = find_user_by_email(&state, &email).await? {
        // An address outside the sign-in allowlist cannot sign in even with a new
        // password, so the link would be a dead end dressed up as help. Silent for
        // the same reason as the directory case below: the endpoint answers 200
        // for everything, so silence here leaks nothing.
        let domains =
            crate::admission::allowed_domains(&state.pool, &state.config.allowed_email_domains)
                .await?;
        if !crate::admission::allows(&domains, &user.1) {
            tracing::info!(
                "password reset requested for an account outside the email domain allowlist;                  nothing to reset"
            );
            return Ok(Json(json!({ "ok": true })));
        }

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
            state.config.public_base()
        );
        // The body carries the live token, so it is logged only behind the dev
        // opt-in — a reset link in a log stream is a working account takeover
        // for anyone who can read the logs.
        // Enqueued, not awaited: the SMTP round trip used to sit inside this
        // request, so a slow relay stalled the one request a locked-out user
        // cannot afford to hang. The outbox worker owns delivery and retries;
        // a transport failure surfaces there, and the token is already valid.
        crate::outbox::enqueue_email(
            &state,
            &user.1,
            "Signet password reset",
            &format!(
                "A password reset was requested for {}. Use this link to set a new password:\n\n{link}\n\nThis link expires in 30 minutes.",
                user.1
            ),
            state.config.dev_log_links,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, email = %user.1, "password reset email enqueue failed");
            AppError::upstream("the reset email could not be queued; try again later")
        })?;

        // Dev/test convenience: without a real mailer, surface the link once —
        // same opt-in as the body above, and loudly absent otherwise so a dev
        // wondering where the link went learns the flag's name.
        if !crate::email::configured(&state).await {
            if state.config.dev_log_links {
                tracing::info!(email = %user.1, link = %link, "password reset link (dev)");
            } else {
                tracing::info!(
                    email = %user.1,
                    "password reset link generated but not logged (set SIGNET_DEV_LOG_LINKS=true in dev to print it)"
                );
            }
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

    // Consume the token atomically before any side effect: two concurrent
    // confirmations must not both change the password. Burning the token first
    // is the safe order — a failure after this leaves the token spent and the
    // user requests a fresh one.
    let consumed = sqlx::query(
        "UPDATE password_reset_tokens SET consumed_at = NOW() \
         WHERE id = $1 AND consumed_at IS NULL AND expires_at > NOW()",
    )
    .bind(row.0)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if consumed == 0 {
        return Err(AppError::bad_request("invalid or expired reset token"));
    }

    set_user_password(
        &state.pool,
        user_id,
        &body.new_password,
        state.rt().password_min_length,
        state.rt().password_history_size,
    )
    .await?;

    // Recovery must end everything the old credential authorized: the sessions
    // (possibly the attacker's) and the refresh tokens delegated to OAuth
    // clients, which outlive passwords unless revoked explicitly.
    crate::auth::session::revoke_all_sessions_notifying(&state, user_id).await?;
    crate::oidc::revoke_refresh_tokens_for_user(&state.pool, user_id).await?;

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
