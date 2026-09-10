mod totp_util;

use crate::audit::{record, AuditEvent};
use crate::auth::session::{cookie_value, create_session, current_user, session_cookie};
use crate::error::{AppError, AppResult};
use crate::models::{PublicUser, User, USER_COLS};
use crate::password::set_user_password;
use crate::roles::require_admin_role;
use crate::state::AppState;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use time::Duration as TimeDuration;
use totp_util::{
    generate_recovery_codes, generate_totp_secret, hash_recovery_code, otpauth_uri,
    verify_recovery_code, verify_totp_code,
};
use uuid::Uuid;

pub const MFA_COOKIE: &str = "signet_mfa";
const MFA_TTL_MINUTES: i64 = 10;
const RECOVERY_CODE_COUNT: usize = 10;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/settings/mfa",
            get(get_mfa_settings).patch(patch_mfa_settings),
        )
        .route("/mfa/verify", post(verify_mfa))
        .route("/mfa/enroll/start", post(enroll_start_challenge))
        .route("/mfa/enroll/confirm", post(enroll_confirm_challenge))
        .route("/me/mfa", get(me_mfa_status))
        .route("/me/mfa/enroll/start", post(enroll_start_session))
        .route("/me/mfa/enroll/confirm", post(enroll_confirm_session))
        .route("/me/mfa/recovery/regenerate", post(regenerate_recovery))
        .route("/me/mfa/disable", post(disable_mfa))
        .route("/me/mfa/rebind/start", post(rebind_start))
        .route("/me/mfa/rebind/confirm", post(rebind_confirm))
        .route("/admin/users/{id}/mfa/reset", post(admin_reset_mfa))
}

// --- settings ---

pub async fn global_mfa_required(pool: &PgPool) -> AppResult<bool> {
    let value: Option<Value> =
        sqlx::query_scalar("SELECT value FROM app_settings WHERE key = 'mfa.required_globally'")
            .fetch_optional(pool)
            .await?;
    Ok(value.and_then(|v| v.as_bool()).unwrap_or(false))
}

async fn set_global_mfa_required(pool: &PgPool, required: bool) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO app_settings (key, value, updated_at)
        VALUES ('mfa.required_globally', $1, NOW())
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
        "#,
    )
    .bind(json!(required))
    .execute(pool)
    .await?;
    Ok(())
}

async fn get_mfa_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let actor = current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let required_globally = global_mfa_required(&state.pool).await?;
    Ok(Json(json!({ "required_globally": required_globally })))
}

#[derive(Debug, Deserialize)]
struct PatchMfaSettings {
    required_globally: bool,
}

async fn patch_mfa_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PatchMfaSettings>,
) -> AppResult<Json<Value>> {
    let actor = current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    set_global_mfa_required(&state.pool, body.required_globally).await?;
    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "settings.mfa_update",
            resource_type: "settings",
            resource_id: Some("mfa.required_globally".into()),
            detail: json!({ "required_globally": body.required_globally }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;
    Ok(Json(json!({ "required_globally": body.required_globally })))
}

// --- challenge helpers ---

#[derive(Debug, sqlx::FromRow)]
struct MfaChallenge {
    id: Uuid,
    user_id: Uuid,
    purpose: String,
    pending_secret: Option<String>,
}

fn mfa_cookie(token: &str, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::build((MFA_COOKIE, token.to_string()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(TimeDuration::minutes(MFA_TTL_MINUTES))
        .build();
    if secure {
        cookie.set_secure(true);
    }
    cookie
}

fn clear_mfa_cookie(secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::build((MFA_COOKIE, ""))
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

async fn create_challenge(
    pool: &PgPool,
    user_id: Uuid,
    purpose: &str,
    pending_secret: Option<&str>,
) -> AppResult<String> {
    let token = crate::crypto_util::random_token(32);
    let token_hash = crate::crypto_util::sha256_hex(&token);
    let id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::minutes(MFA_TTL_MINUTES);
    sqlx::query(
        r#"
        INSERT INTO mfa_challenges (id, user_id, token_hash, purpose, pending_secret, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(token_hash)
    .bind(purpose)
    .bind(pending_secret)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(token)
}

async fn load_challenge(pool: &PgPool, headers: &HeaderMap) -> AppResult<MfaChallenge> {
    let token = cookie_value(headers, MFA_COOKIE)
        .ok_or_else(|| AppError::unauthorized("mfa challenge required"))?;
    let token_hash = crate::crypto_util::sha256_hex(&token);
    sqlx::query_as::<_, MfaChallenge>(
        r#"
        SELECT id, user_id, purpose, pending_secret
        FROM mfa_challenges
        WHERE token_hash = $1 AND expires_at > NOW()
        "#,
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("mfa challenge expired or invalid"))
}

async fn delete_challenge(pool: &PgPool, id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM mfa_challenges WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

async fn load_user(pool: &PgPool, id: Uuid) -> AppResult<User> {
    sqlx::query_as::<_, User>(&format!("SELECT {USER_COLS} FROM users WHERE id = $1"))
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("user not found".into()))
}

/// Encrypts a TOTP secret before persisting it.
fn encrypt_totp_secret(state: &AppState, plaintext: &str) -> String {
    state.encryptor.encrypt(plaintext)
}

/// Decrypts a stored TOTP secret, falling back to plaintext for legacy rows
/// that predate application-layer encryption (so existing users keep working).
fn decrypt_totp_secret(state: &AppState, stored: &str) -> String {
    match state.encryptor.decrypt(stored) {
        Some(plaintext) => plaintext,
        None => stored.to_string(),
    }
}

async fn issue_session(
    state: &AppState,
    jar: CookieJar,
    user: User,
    ip: Option<String>,
    user_agent: Option<String>,
    client_id: Option<String>,
) -> AppResult<impl IntoResponse> {
    let token = create_session(
        &state.pool,
        user.id,
        state.config.session_ttl_hours,
        ip.as_deref(),
        user_agent.as_deref(),
    )
    .await?;
    let jar = jar
        .add(session_cookie(
            &token,
            state.config.cookie_secure,
            state.config.session_ttl_hours,
        ))
        .add(clear_mfa_cookie(state.config.cookie_secure));
    let jar = crate::federation::consume_pending_link(state, jar, &user).await;

    crate::login_alert::track_login(&state.pool, &user, ip.as_deref(), user_agent.as_deref()).await;

    record(
        &state.pool,
        AuditEvent {
            actor: Some(user.clone()),
            action: "auth.login",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "mfa": true }),
            ip,
            user_agent,
            client_id,
        },
    )
    .await;
    crate::metrics::inc_logins();

    Ok((
        jar,
        Json(json!({
            "status": "ok",
            "user": PublicUser::from(user),
        })),
    ))
}

async fn replace_recovery_codes(pool: &PgPool, user_id: Uuid) -> AppResult<Vec<String>> {
    let codes = generate_recovery_codes(RECOVERY_CODE_COUNT);
    sqlx::query("DELETE FROM totp_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    for code in &codes {
        let id = Uuid::new_v4();
        let hash = hash_recovery_code(code)?;
        sqlx::query(
            r#"
            INSERT INTO totp_recovery_codes (id, user_id, code_hash)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(id)
        .bind(user_id)
        .bind(hash)
        .execute(pool)
        .await?;
    }
    Ok(codes)
}

async fn remaining_recovery_codes(pool: &PgPool, user_id: Uuid) -> AppResult<i64> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

async fn clear_user_mfa(pool: &PgPool, user_id: Uuid) -> AppResult<()> {
    sqlx::query(
        r#"
        UPDATE users
        SET totp_enabled = FALSE, totp_secret = NULL, updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    sqlx::query("DELETE FROM totp_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM mfa_challenges WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Issues a single-use forced password-change challenge before a session is
/// established. Called after first-factor authentication succeeds (password or
/// passkey) while `must_change_password` is still set.
pub async fn challenge_password_change(
    state: &AppState,
    jar: CookieJar,
    user: User,
) -> AppResult<(CookieJar, Json<Value>)> {
    let token = create_challenge(&state.pool, user.id, "change_password", None).await?;
    let jar = jar.add(mfa_cookie(&token, state.config.cookie_secure));
    Ok((
        jar,
        Json(json!({
            "status": "password_change_required",
        })),
    ))
}

/// Called from auth login after password OK.
pub async fn begin_login_mfa_flow(
    state: &AppState,
    jar: CookieJar,
    user: User,
    ip: Option<String>,
    user_agent: Option<String>,
    client_id: Option<String>,
) -> AppResult<impl IntoResponse> {
    if user.must_change_password {
        return challenge_password_change(state, jar, user).await;
    }

    let global = global_mfa_required(&state.pool).await?;

    if user.totp_enabled {
        let token = create_challenge(&state.pool, user.id, "login", None).await?;
        let jar = jar.add(mfa_cookie(&token, state.config.cookie_secure));
        return Ok((
            jar,
            Json(json!({
                "status": "mfa_required",
            })),
        ));
    }

    if global || user.mfa_required {
        let token = create_challenge(&state.pool, user.id, "enroll", None).await?;
        let jar = jar.add(mfa_cookie(&token, state.config.cookie_secure));
        return Ok((
            jar,
            Json(json!({
                "status": "enroll_required",
            })),
        ));
    }

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
    let jar = crate::federation::consume_pending_link(state, jar, &user).await;
    crate::login_alert::track_login(&state.pool, &user, ip.as_deref(), user_agent.as_deref()).await;
    record(
        &state.pool,
        AuditEvent {
            actor: Some(user.clone()),
            action: "auth.login",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "mfa": false }),
            ip,
            user_agent,
            client_id,
        },
    )
    .await;
    crate::metrics::inc_logins();
    Ok((
        jar,
        Json(json!({
            "status": "ok",
            "user": PublicUser::from(user),
        })),
    ))
}

// --- forced password change (first login) ---

#[derive(Debug, Deserialize)]
pub(crate) struct ForcePasswordChangeBody {
    new_password: String,
}

/// Completes the "change password on first login" challenge. The challenge is
/// issued by `begin_login_mfa_flow` right after password verification, so the
/// new password can be set without re-entering the current one. After the
/// change the user continues through the normal MFA/session flow.
pub(crate) async fn force_password_change(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<ForcePasswordChangeBody>,
) -> AppResult<impl IntoResponse> {
    let ip = crate::http_util::client_ip(&headers, Some(addr));
    let user_agent = crate::http_util::user_agent(&headers);

    let challenge = load_challenge(&state.pool, &headers).await?;
    if challenge.purpose != "change_password" {
        return Err(AppError::bad_request("password change challenge required"));
    }
    let user = load_user(&state.pool, challenge.user_id).await?;
    if user.status != "active" {
        return Err(AppError::unauthorized("account disabled"));
    }
    if !user.must_change_password {
        return Err(AppError::bad_request("password change not required"));
    }

    set_user_password(
        &state.pool,
        user.id,
        &body.new_password,
        state.config.password_min_length,
        state.config.password_history_size,
    )
    .await?;

    sqlx::query("UPDATE users SET must_change_password = FALSE, updated_at = NOW() WHERE id = $1")
        .bind(user.id)
        .execute(&state.pool)
        .await?;

    delete_challenge(&state.pool, challenge.id).await?;

    record(
        &state.pool,
        AuditEvent {
            actor: Some(user.clone()),
            action: "auth.password_change",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "forced": true }),
            ip: ip.clone(),
            user_agent: user_agent.clone(),
            client_id: None,
        },
    )
    .await;

    let user = load_user(&state.pool, user.id).await?;
    begin_login_mfa_flow(&state, jar, user, ip, user_agent, None).await
}

// --- verify ---

#[derive(Debug, Deserialize)]
struct VerifyBody {
    code: String,
    #[serde(default = "default_method")]
    method: String,
    /// Optional `/oauth/authorize?...` return URL carried through from the
    /// login step, used to attribute the login to the initiating OAuth app.
    #[serde(default)]
    return_to: Option<String>,
}

fn default_method() -> String {
    "totp".into()
}

async fn verify_mfa(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<VerifyBody>,
) -> AppResult<impl IntoResponse> {
    let ip = crate::http_util::client_ip(&headers, Some(addr));
    let challenge = load_challenge(&state.pool, &headers).await?;
    if challenge.purpose != "login" {
        return Err(AppError::bad_request("login challenge required"));
    }
    let user = load_user(&state.pool, challenge.user_id).await?;
    if user.status != "active" {
        return Err(AppError::unauthorized("account disabled"));
    }
    if !user.totp_enabled {
        return Err(AppError::bad_request("totp not enabled"));
    }

    let method = body.method.as_str();
    match method {
        "totp" => {
            let secret = user
                .totp_secret
                .as_deref()
                .ok_or_else(|| AppError::bad_request("totp not configured"))?;
            let secret = decrypt_totp_secret(&state, secret);
            if !verify_totp_code(&secret, &body.code)? {
                crate::metrics::inc_mfa_verify_failure();
                return Err(AppError::unauthorized("invalid code"));
            }
            crate::metrics::inc_mfa_verify();
            record(
                &state.pool,
                AuditEvent {
                    actor: Some(user.clone()),
                    action: "mfa.verify",
                    resource_type: "user",
                    resource_id: Some(user.id.to_string()),
                    detail: json!({ "method": "totp" }),
                    ip: ip.clone(),
                    user_agent: crate::http_util::user_agent(&headers),
                    client_id: None,
                },
            )
            .await;
        }
        "recovery" => {
            let rows: Vec<(Uuid, String)> = sqlx::query_as(
                r#"
                SELECT id, code_hash FROM totp_recovery_codes
                WHERE user_id = $1 AND used_at IS NULL
                "#,
            )
            .bind(user.id)
            .fetch_all(&state.pool)
            .await?;
            let mut matched: Option<Uuid> = None;
            for (id, hash) in rows {
                if verify_recovery_code(&body.code, &hash)? {
                    matched = Some(id);
                    break;
                }
            }
            let Some(code_id) = matched else {
                crate::metrics::inc_mfa_verify_failure();
                return Err(AppError::unauthorized("invalid recovery code"));
            };
            crate::metrics::inc_mfa_verify();
            sqlx::query("UPDATE totp_recovery_codes SET used_at = NOW() WHERE id = $1")
                .bind(code_id)
                .execute(&state.pool)
                .await?;
            record(
                &state.pool,
                AuditEvent {
                    actor: Some(user.clone()),
                    action: "mfa.recovery_use",
                    resource_type: "user",
                    resource_id: Some(user.id.to_string()),
                    detail: json!({}),
                    ip: ip.clone(),
                    user_agent: crate::http_util::user_agent(&headers),
                    client_id: None,
                },
            )
            .await;
        }
        _ => return Err(AppError::bad_request("method must be totp or recovery")),
    }

    delete_challenge(&state.pool, challenge.id).await?;
    let client_id =
        crate::audit::resolve_audit_client_id(&state.pool, body.return_to.as_deref()).await;
    issue_session(
        &state,
        jar,
        user,
        ip,
        crate::http_util::user_agent(&headers),
        client_id,
    )
    .await
}

// --- enroll (challenge / forced) ---

async fn enroll_start_challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> AppResult<impl IntoResponse> {
    let challenge = load_challenge(&state.pool, &headers).await?;
    if challenge.purpose != "enroll" {
        return Err(AppError::bad_request("enroll challenge required"));
    }
    let user = load_user(&state.pool, challenge.user_id).await?;
    if user.totp_enabled {
        return Err(AppError::bad_request("totp already enabled"));
    }

    let secret = generate_totp_secret();
    sqlx::query("UPDATE mfa_challenges SET pending_secret = $2 WHERE id = $1")
        .bind(challenge.id)
        .bind(&secret)
        .execute(&state.pool)
        .await?;

    let issuer = "Signet";
    let uri = otpauth_uri(&secret, issuer, &user.email)?;
    Ok((
        jar,
        Json(json!({
            "secret": secret,
            "otpauth_uri": uri,
        })),
    ))
}

#[derive(Debug, Deserialize)]
struct EnrollConfirmBody {
    code: String,
    /// Optional `/oauth/authorize?...` return URL carried through from the
    /// login step, used to attribute the login to the initiating OAuth app.
    #[serde(default)]
    return_to: Option<String>,
}

async fn enroll_confirm_challenge(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<EnrollConfirmBody>,
) -> AppResult<impl IntoResponse> {
    let ip = crate::http_util::client_ip(&headers, Some(addr));
    let challenge = load_challenge(&state.pool, &headers).await?;
    if challenge.purpose != "enroll" {
        return Err(AppError::bad_request("enroll challenge required"));
    }
    let secret = challenge
        .pending_secret
        .as_deref()
        .ok_or_else(|| AppError::bad_request("call enroll/start first"))?;
    if !verify_totp_code(secret, &body.code)? {
        return Err(AppError::unauthorized("invalid code"));
    }

    let user_id = challenge.user_id;
    sqlx::query(
        r#"
        UPDATE users
        SET totp_enabled = TRUE, totp_secret = $2, updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .bind(encrypt_totp_secret(&state, secret))
    .execute(&state.pool)
    .await?;

    let codes = replace_recovery_codes(&state.pool, user_id).await?;
    delete_challenge(&state.pool, challenge.id).await?;

    let user = load_user(&state.pool, user_id).await?;
    let client_id =
        crate::audit::resolve_audit_client_id(&state.pool, body.return_to.as_deref()).await;
    record(
        &state.pool,
        AuditEvent {
            actor: Some(user.clone()),
            action: "mfa.enroll",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "via": "login" }),
            ip: ip.clone(),
            user_agent: crate::http_util::user_agent(&headers),
            client_id: client_id.clone(),
        },
    )
    .await;

    let token = create_session(
        &state.pool,
        user.id,
        state.config.session_ttl_hours,
        ip.as_deref(),
        crate::http_util::user_agent(&headers).as_deref(),
    )
    .await?;
    let jar = jar
        .add(session_cookie(
            &token,
            state.config.cookie_secure,
            state.config.session_ttl_hours,
        ))
        .add(clear_mfa_cookie(state.config.cookie_secure));
    let jar = crate::federation::consume_pending_link(&state, jar, &user).await;

    crate::login_alert::track_login(
        &state.pool,
        &user,
        ip.as_deref(),
        crate::http_util::user_agent(&headers).as_deref(),
    )
    .await;

    record(
        &state.pool,
        AuditEvent {
            actor: Some(user.clone()),
            action: "auth.login",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "mfa": true, "enrolled": true }),
            ip,
            user_agent: crate::http_util::user_agent(&headers),
            client_id,
        },
    )
    .await;
    crate::metrics::inc_logins();

    Ok((
        jar,
        Json(json!({
            "status": "ok",
            "user": PublicUser::from(user),
            "recovery_codes": codes,
        })),
    ))
}

// --- me mfa ---

async fn me_mfa_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    let global = global_mfa_required(&state.pool).await?;
    let remaining = if user.totp_enabled {
        remaining_recovery_codes(&state.pool, user.id).await?
    } else {
        0
    };
    Ok(Json(json!({
        "totp_enabled": user.totp_enabled,
        "mfa_required": user.mfa_required,
        "policy_required": global || user.mfa_required,
        "required_globally": global,
        "recovery_codes_remaining": remaining,
    })))
}

async fn enroll_start_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> AppResult<impl IntoResponse> {
    let user = current_user(&state, &headers).await?;
    if user.totp_enabled {
        return Err(AppError::bad_request("totp already enabled"));
    }
    let secret = generate_totp_secret();
    // Drop prior enroll challenges for this user
    sqlx::query("DELETE FROM mfa_challenges WHERE user_id = $1 AND purpose = 'enroll'")
        .bind(user.id)
        .execute(&state.pool)
        .await?;
    let token = create_challenge(&state.pool, user.id, "enroll", Some(&secret)).await?;
    let uri = otpauth_uri(&secret, "Signet", &user.email)?;
    let jar = jar.add(mfa_cookie(&token, state.config.cookie_secure));
    Ok((
        jar,
        Json(json!({
            "secret": secret,
            "otpauth_uri": uri,
        })),
    ))
}

async fn enroll_confirm_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<EnrollConfirmBody>,
) -> AppResult<impl IntoResponse> {
    let user = current_user(&state, &headers).await?;
    if user.totp_enabled {
        return Err(AppError::bad_request("totp already enabled"));
    }
    let challenge = load_challenge(&state.pool, &headers).await?;
    if challenge.purpose != "enroll" || challenge.user_id != user.id {
        return Err(AppError::bad_request("enroll challenge required"));
    }
    let secret = challenge
        .pending_secret
        .as_deref()
        .ok_or_else(|| AppError::bad_request("call enroll/start first"))?;
    if !verify_totp_code(secret, &body.code)? {
        return Err(AppError::unauthorized("invalid code"));
    }

    sqlx::query(
        r#"
        UPDATE users
        SET totp_enabled = TRUE, totp_secret = $2, updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(user.id)
    .bind(encrypt_totp_secret(&state, secret))
    .execute(&state.pool)
    .await?;

    let codes = replace_recovery_codes(&state.pool, user.id).await?;
    delete_challenge(&state.pool, challenge.id).await?;
    let user = load_user(&state.pool, user.id).await?;

    record(
        &state.pool,
        AuditEvent {
            actor: Some(user.clone()),
            action: "mfa.enroll",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "via": "session" }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok((
        jar.add(clear_mfa_cookie(state.config.cookie_secure)),
        Json(json!({
            "ok": true,
            "user": PublicUser::from(user),
            "recovery_codes": codes,
        })),
    ))
}

#[derive(Debug, Deserialize)]
struct TotpCodeBody {
    code: String,
}

async fn regenerate_recovery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TotpCodeBody>,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    if !user.totp_enabled {
        return Err(AppError::bad_request("totp not enabled"));
    }
    let secret = user
        .totp_secret
        .as_deref()
        .ok_or_else(|| AppError::bad_request("totp not configured"))?;
    let secret = decrypt_totp_secret(&state, secret);
    if !verify_totp_code(&secret, &body.code)? {
        return Err(AppError::unauthorized("invalid code"));
    }
    let codes = replace_recovery_codes(&state.pool, user.id).await?;
    record(
        &state.pool,
        AuditEvent {
            actor: Some(user),
            action: "mfa.recovery_regen",
            resource_type: "user",
            resource_id: None,
            detail: json!({}),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;
    Ok(Json(json!({ "recovery_codes": codes })))
}

/// User-initiated MFA removal. Only allowed when MFA is not enforced by policy
/// (global or per-user `mfa_required`); requires a valid current TOTP code.
async fn disable_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TotpCodeBody>,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    if !user.totp_enabled {
        return Err(AppError::bad_request("totp not enabled"));
    }
    let global = global_mfa_required(&state.pool).await?;
    if global || user.mfa_required {
        return Err(AppError::bad_request(
            "MFA is required by policy and cannot be disabled",
        ));
    }

    let secret = user
        .totp_secret
        .as_deref()
        .ok_or_else(|| AppError::bad_request("totp not configured"))?;
    let secret = decrypt_totp_secret(&state, secret);
    if !verify_totp_code(&secret, &body.code)? {
        crate::metrics::inc_mfa_verify_failure();
        return Err(AppError::unauthorized("invalid code"));
    }

    clear_user_mfa(&state.pool, user.id).await?;
    let user = load_user(&state.pool, user.id).await?;
    record(
        &state.pool,
        AuditEvent {
            actor: Some(user.clone()),
            action: "mfa.disable",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({}),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;
    Ok(Json(json!({ "ok": true, "user": PublicUser::from(user) })))
}

async fn rebind_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<TotpCodeBody>,
) -> AppResult<impl IntoResponse> {
    let user = current_user(&state, &headers).await?;
    if !user.totp_enabled {
        return Err(AppError::bad_request("totp not enabled"));
    }
    let secret = user
        .totp_secret
        .as_deref()
        .ok_or_else(|| AppError::bad_request("totp not configured"))?;
    let secret = decrypt_totp_secret(&state, secret);
    if !verify_totp_code(&secret, &body.code)? {
        return Err(AppError::unauthorized("invalid code"));
    }

    let new_secret = generate_totp_secret();
    sqlx::query("DELETE FROM mfa_challenges WHERE user_id = $1 AND purpose = 'enroll'")
        .bind(user.id)
        .execute(&state.pool)
        .await?;
    let token = create_challenge(&state.pool, user.id, "enroll", Some(&new_secret)).await?;
    let uri = otpauth_uri(&new_secret, "Signet", &user.email)?;
    Ok((
        jar.add(mfa_cookie(&token, state.config.cookie_secure)),
        Json(json!({
            "secret": new_secret,
            "otpauth_uri": uri,
        })),
    ))
}

async fn rebind_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<EnrollConfirmBody>,
) -> AppResult<impl IntoResponse> {
    let user = current_user(&state, &headers).await?;
    let challenge = load_challenge(&state.pool, &headers).await?;
    if challenge.purpose != "enroll" || challenge.user_id != user.id {
        return Err(AppError::bad_request("rebind challenge required"));
    }
    let secret = challenge
        .pending_secret
        .as_deref()
        .ok_or_else(|| AppError::bad_request("call rebind/start first"))?;
    if !verify_totp_code(secret, &body.code)? {
        return Err(AppError::unauthorized("invalid code"));
    }

    sqlx::query(
        r#"
        UPDATE users
        SET totp_enabled = TRUE, totp_secret = $2, updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(user.id)
    .bind(encrypt_totp_secret(&state, secret))
    .execute(&state.pool)
    .await?;

    let codes = replace_recovery_codes(&state.pool, user.id).await?;
    delete_challenge(&state.pool, challenge.id).await?;
    let user = load_user(&state.pool, user.id).await?;

    record(
        &state.pool,
        AuditEvent {
            actor: Some(user.clone()),
            action: "mfa.rebind",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({}),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok((
        jar.add(clear_mfa_cookie(state.config.cookie_secure)),
        Json(json!({
            "ok": true,
            "user": PublicUser::from(user),
            "recovery_codes": codes,
        })),
    ))
}

async fn admin_reset_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Value>> {
    let actor = current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let target = load_user(&state.pool, id).await?;
    clear_user_mfa(&state.pool, id).await?;
    // Also kill sessions so they re-auth under policy
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?;
    record(
        &state.pool,
        AuditEvent {
            actor: Some(actor),
            action: "mfa.reset",
            resource_type: "user",
            resource_id: Some(id.to_string()),
            detail: json!({ "email": target.email }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}
