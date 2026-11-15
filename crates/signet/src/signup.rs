//! Public self-registration, off by default.
//!
//! Self-service sign-up is a deliberately narrow door: it creates a `member`
//! with no groups and no administrative role, and it does so only after the
//! address has been proven. A request is written to `signup_requests` — never to
//! `users` — so an abandoned or hostile attempt never enters the directory, and
//! nobody can claim an address they cannot receive mail at. Confirmation creates
//! the account and returns to the sign-in page; it never starts a session, so
//! the link in an email cannot log a browser in.
//!
//! The setting itself (`auth.public_signup`) defaults to false and is writable
//! only from the admin settings API. Enabling it is refused unless **both**
//! prerequisites are configured:
//!
//! * an SMTP relay, because the verification link is the only proof of address
//!   ownership — without delivery every sign-up would dead-end;
//! * a CAPTCHA gate, because the endpoint is unauthenticated and would otherwise
//!   be a free account-creation and mail-sending pump.
//!
//! The request handler re-checks both every time and fails closed, so removing
//! either configuration later disables sign-up rather than silently dropping
//! the protection it was enabled under. The public status endpoint reports
//! `enabled: false` in that state.
//!
//! Anti-enumeration: `POST /signup` answers the same `{"status":"ok"}` whether
//! the address was new, already registered, or had a request in flight. An
//! existing account gets a notice email (only its owner can read it) instead of
//! a verification link.
//! The per-IP and per-email attempt counters live in the database, so replicas
//! share one budget; the pending-request row is replaced on a fresh request,
//! which invalidates the older link.

use crate::audit::{record, AuditEvent};
use crate::auth::password::{
    hash_password_offloaded, record_password_history, validate_password_strength,
};
use crate::crypto::util::{random_token, sha256_hex};
use crate::error::{AppError, AppResult};
use crate::http::extract::{audit_ip, user_agent, AuditIp};
use crate::models::NewUser;
use crate::roles::require_admin_role;
use crate::state::AppState;
use axum::extract::{Extension, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// The `app_settings` row. Missing means disabled — there is no environment
/// fallback on purpose: an environment variable must not be able to open a
/// public sign-up page that an administrator believes is off.
pub const SETTING_KEY: &str = "auth.public_signup";

/// Link lifetime. The same 30 minutes the reset and email-change flows use.
const TTL_MINUTES: i64 = 30;

/// Attempt budgets. Deliberately small: a human needs one or two tries, while a
/// script enumerating addresses or triggering mail runs out quickly.
const MAX_PER_IP_HOUR: i64 = 5;
const MAX_PER_IP_DAY: i64 = 20;
const MAX_PER_EMAIL_HOUR: i64 = 3;

/// A repeat request inside this window is answered generically but sends no
/// mail and does not rotate the token, so one address cannot be mail-bombed.
const RESEND_COOLDOWN_SECS: i64 = 60;

const MAX_EMAIL_LEN: usize = 254;
const MAX_DISPLAY_NAME_CHARS: usize = 100;
const MAX_PASSWORD_LEN: usize = 1024;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/signup/status", get(status))
        .route("/signup", post(request))
        .route("/signup/confirm", post(confirm))
        .route(
            "/admin/settings/signup",
            get(get_settings).patch(patch_settings),
        )
}

/// Whether the operator has switched self-registration on.
///
/// Read per request, like the other DB-backed switches: an administrator's
/// change must apply to the next visitor without a restart or a replica
/// convergence window. A missing row is `false`; a malformed row is also
/// `false`, the safe reading of a hand-edited setting.
pub async fn signup_enabled(pool: &PgPool) -> AppResult<bool> {
    let value: Option<Value> = sqlx::query_scalar("SELECT value FROM app_settings WHERE key = $1")
        .bind(SETTING_KEY)
        .fetch_optional(pool)
        .await?;
    Ok(value.and_then(|v| v.as_bool()).unwrap_or(false))
}

async fn set_signup_enabled(pool: &PgPool, enabled: bool) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO app_settings (key, value, updated_at)
        VALUES ($1, $2, NOW())
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
        "#,
    )
    .bind(SETTING_KEY)
    .bind(json!(enabled))
    .execute(pool)
    .await?;
    Ok(())
}

/// What the admin switch must confirm before it may be turned on.
///
/// `problems` are blocking; `warnings` are operational advice (an unrestricted
/// domain list, links pointing at localhost or plain http) that must not stop
/// a local test from enabling the feature. The same struct feeds GET, PATCH and
/// the UI, so the sentence an administrator sees before saving is the sentence
/// the server refuses with.
#[derive(Debug, Serialize)]
struct SignupReadiness {
    smtp_configured: bool,
    captcha_configured: bool,
    ready: bool,
    problems: Vec<String>,
    warnings: Vec<String>,
}

async fn readiness(state: &AppState) -> AppResult<SignupReadiness> {
    // Presence is not enough for the relay: a zero port or a From that is not
    // a mailbox would fail on the first verification mail, after enabling.
    let smtp_problem = crate::email::configuration_problem(state).await;
    let captcha_configured = crate::captcha::resolve(state).await.is_some();

    let mut problems = Vec::new();
    if let Some(problem) = &smtp_problem {
        problems.push(format!("Email relay: {problem}"));
    }
    if !captcha_configured {
        problems.push("CAPTCHA: No provider, site key or secret is configured.".into());
    }

    let mut warnings = Vec::new();
    let domains =
        crate::admission::allowed_domains(&state.pool, &state.config.allowed_email_domains).await?;
    if domains.is_empty() {
        warnings.push("No email-domain allowlist; any domain can register.".into());
    }
    let base = state.public_base();
    if let Ok(url) = url::Url::parse(&base) {
        let host = url.host_str().unwrap_or("");
        let local = matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]");
        if local {
            warnings.push(format!(
                "Verification links point to {base}; only this machine can reach them."
            ));
        } else if url.scheme() == "http" {
            warnings.push("Verification links use http; use https instead.".into());
        }
    }

    Ok(SignupReadiness {
        smtp_configured: smtp_problem.is_none(),
        captcha_configured,
        ready: problems.is_empty(),
        problems,
        warnings,
    })
}

/// Normalizes an address the way the sign-in path does. Deliberately loose: an
/// internal deployment may use a domain without a dot, and the verification
/// mail is what actually proves deliverability.
fn normalize_email(raw: &str) -> AppResult<String> {
    let email = raw.trim().to_lowercase();
    if email.is_empty()
        || email.len() > MAX_EMAIL_LEN
        || email.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(AppError::bad_request("invalid email"));
    }
    let Some((local, domain)) = email.rsplit_once('@') else {
        return Err(AppError::bad_request("invalid email"));
    };
    if local.is_empty() || domain.is_empty() || domain.starts_with('.') || domain.ends_with('.') {
        return Err(AppError::bad_request("invalid email"));
    }
    Ok(email)
}

/// The display name shown in the directory: trimmed, control characters
/// refused, and falling back to the local part of the address. The 100-character
/// cap matches what the admin form accepts.
fn normalize_display_name(raw: Option<&str>, email: &str) -> AppResult<String> {
    let provided = raw.map(str::trim).filter(|s| !s.is_empty());
    if let Some(name) = provided {
        if name.chars().count() > MAX_DISPLAY_NAME_CHARS || name.chars().any(|c| c.is_control()) {
            return Err(AppError::bad_request(
                "display_name must be 1-100 characters without control characters",
            ));
        }
        return Ok(name.to_string());
    }
    Ok(email
        .split('@')
        .next()
        .unwrap_or("user")
        .chars()
        .take(MAX_DISPLAY_NAME_CHARS)
        .collect())
}

/// The address and its fresh token, i.e. everything the verification mail needs.
struct Visit {
    email: String,
    token: String,
}

/// What the public sign-up page needs before rendering the form.
///
/// `enabled` is the *effective* answer: the setting can be on while a
/// prerequisite was removed, and that state must hide the form rather than
/// offer one whose submissions fail. When disabled nothing else is disclosed.
async fn status(State(state): State<AppState>) -> AppResult<Json<Value>> {
    let configured = signup_enabled(&state.pool).await?;
    let captcha_enabled = crate::captcha::resolve(&state).await.is_some();
    let email_ready =
        crate::email::configuration_problem(&state).await.is_none() || state.config.dev_log_links;
    if !(configured && captcha_enabled && email_ready) {
        return Ok(Json(json!({ "enabled": false })));
    }
    let domains =
        crate::admission::allowed_domains(&state.pool, &state.config.allowed_email_domains).await?;
    Ok(Json(json!({
        "enabled": true,
        "captcha_enabled": true,
        "min_password_length": state.rt().password_min_length,
        "allowed_email_domains": domains,
    })))
}

#[derive(Debug, Deserialize)]
struct SignupBody {
    email: String,
    password: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    captcha_token: Option<String>,
}

/// Records one attempt. Committed before the budget check, so the request that
/// crosses the line is itself counted and a burst cannot slip through between
/// a check and its write.
async fn record_attempt(pool: &PgPool, ip: Option<&str>, email: &str) -> AppResult<()> {
    sqlx::query("INSERT INTO signup_attempts (ip, email) VALUES ($1, $2)")
        .bind(ip)
        .bind(email)
        .execute(pool)
        .await?;
    Ok(())
}

async fn count_attempts(pool: &PgPool, sql: &str, value: &str, window: &str) -> AppResult<i64> {
    let query = format!(
        "SELECT COUNT(*) FROM signup_attempts WHERE {sql} = $1 AND created_at > NOW() - INTERVAL '{window}'"
    );
    let count: i64 = sqlx::query_scalar(&query)
        .bind(value)
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Whether this address or client has spent its budget. `ip` is optional only
/// for callers driven without the access-log middleware (tests); in the live
/// app every request has one.
async fn over_budget(pool: &PgPool, ip: Option<&str>, email: &str) -> AppResult<bool> {
    if count_attempts(pool, "email", email, "1 hour").await? > MAX_PER_EMAIL_HOUR {
        return Ok(true);
    }
    if let Some(ip) = ip {
        if count_attempts(pool, "ip", ip, "1 hour").await? > MAX_PER_IP_HOUR
            || count_attempts(pool, "ip", ip, "1 day").await? > MAX_PER_IP_DAY
        {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn recent_attempts(pool: &PgPool, email: &str, window: &str) -> AppResult<i64> {
    let query = format!(
        "SELECT COUNT(*) FROM signup_attempts WHERE email = $1 AND created_at > NOW() - INTERVAL '{window}'"
    );
    let count: i64 = sqlx::query_scalar(&query)
        .bind(email)
        .fetch_one(pool)
        .await?;
    Ok(count)
}

async fn request(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit: Option<Extension<AuditIp>>,
    Json(body): Json<SignupBody>,
) -> AppResult<Json<Value>> {
    let ip = audit_ip(audit);
    request_impl(&state, &headers, ip, body).await
}

#[derive(Debug, Deserialize)]
struct ConfirmBody {
    token: String,
}

/// The admin view, with the switch and the full preflight result together.
fn settings_view(enabled: bool, readiness: &SignupReadiness) -> Value {
    json!({
        "enabled": enabled,
        "smtp_configured": readiness.smtp_configured,
        "captcha_configured": readiness.captcha_configured,
        "ready": readiness.ready,
        "problems": readiness.problems,
        "warnings": readiness.warnings,
    })
}

async fn get_settings(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let enabled = signup_enabled(&state.pool).await?;
    let readiness = readiness(&state).await?;
    Ok(Json(settings_view(enabled, &readiness)))
}

#[derive(Debug, Deserialize)]
struct SignupPatch {
    enabled: bool,
}

/// Enabling is refused while a prerequisite is missing, so the public page can
/// never be advertised without the controls it was designed around.
async fn patch_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit: Option<Extension<AuditIp>>,
    Json(body): Json<SignupPatch>,
) -> AppResult<Json<Value>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let ip = audit_ip(audit);

    // The check runs against the live configuration, not the copy the browser
    // loaded: a prerequisite can disappear between GET and PATCH. Every problem
    // is returned together, so one save attempt tells the administrator
    // everything that still needs fixing.
    let readiness = readiness(&state).await?;
    if body.enabled && !readiness.ready {
        return Err(AppError::conflict(format!(
            "cannot enable public sign-up: {}",
            readiness.problems.join(" ")
        )));
    }

    let before = signup_enabled(&state.pool).await?;
    set_signup_enabled(&state.pool, body.enabled).await?;

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "settings.signup_update",
            resource_type: "settings",
            resource_id: Some(SETTING_KEY.into()),
            detail: json!({
                "before": before,
                "after": body.enabled,
                "ready": readiness.ready,
                "problems": &readiness.problems,
                "warnings": &readiness.warnings,
            }),
            ip,
            user_agent: user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(settings_view(body.enabled, &readiness)))
}

async fn confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit: Option<Extension<AuditIp>>,
    Json(body): Json<ConfirmBody>,
) -> AppResult<Json<Value>> {
    let token = body.token.trim();
    if token.is_empty() || token.len() > 512 {
        return Err(AppError::bad_request("invalid or expired sign-up link"));
    }
    let ip = audit_ip(audit);

    // Consume first and in its own statement: a link is single-use even if a
    // later check refuses, and replaying it must not create a second account.
    // (If this request then fails, the user asks for a fresh link.)
    let pending: Option<(String, String, String)> = sqlx::query_as(
        r#"
        DELETE FROM signup_requests
        WHERE token_hash = $1 AND expires_at > NOW()
        RETURNING email, display_name, password_hash
        "#,
    )
    .bind(sha256_hex(token))
    .fetch_optional(&state.pool)
    .await?;
    let Some((email, display_name, password_hash)) = pending else {
        return Err(AppError::gone(
            "this sign-up link is invalid, expired, or already used",
        ));
    };

    // The allowlist can have narrowed since the request was made; applying it
    // now, before the account exists, keeps the promise that a listed domain is
    // the only way in.
    crate::admission::ensure_provision_allowed(
        &state,
        &email,
        crate::admission::via::SIGNUP,
        user_agent(&headers),
        ip.as_deref(),
    )
    .await?;

    let taken: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1 OR username = $1")
            .bind(&email)
            .fetch_one(&state.pool)
            .await?;
    if taken > 0 {
        return Err(AppError::conflict(
            "an account with this email already exists; sign in instead",
        ));
    }

    let id = Uuid::new_v4();
    let sub = id.to_string();
    let mut new_user = NewUser::new(id, &sub, &email, &display_name, &password_hash);
    // The address was proven by the link, so the account starts verified (the
    // `users.email_verified` default), local, ungrouped and a plain member.
    new_user.provisioned_via = Some("signup");
    let user = crate::models::insert_user(&state.pool, &new_user)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db)
                if matches!(
                    db.constraint(),
                    Some("users_email_key") | Some("users_username_key")
                ) =>
            {
                AppError::conflict("an account with this email already exists; sign in instead")
            }
            other => AppError::from(other),
        })?;

    // History is what later blocks reuse of a temporary password; recording it
    // after the insert matches the admin/reset paths.
    record_password_history(&state.pool, user.id, &user.password_hash).await?;

    record(
        &state,
        AuditEvent {
            actor: Some(user.clone()),
            action: "auth.signup_confirmed",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "email": user.email }),
            ip,
            user_agent: user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "status": "ok" })))
}

// --- shared by the request handler -----------------------------------------

/// Sends the verification mail. A delivery failure is logged, never surfaced:
/// the public answer must stay identical for every address.
async fn send_verification(state: &AppState, visit: &Visit) {
    // The token rides in the fragment, which browsers never send to the server:
    // it then cannot land in the access log or a proxy's request line. The
    // confirmation page reads it from `location.hash`.
    let link = format!(
        "{}/signup/confirm#token={}",
        state.public_base(),
        visit.token
    );
    if let Err(e) = crate::outbox::enqueue_email(
        state,
        &visit.email,
        "Signet account verification",
        &format!(
            "A Signet account was requested for {}. Confirm it here:\n\n{link}\n\n\
             This link expires in {TTL_MINUTES} minutes and works once. If you did not \
             request it, ignore this message.",
            visit.email
        ),
        state.config.dev_log_links,
    )
    .await
    {
        tracing::error!(error = %e, email = %visit.email, "sign-up verification email enqueue failed");
    }
}

async fn send_existing_notice(state: &AppState, email: &str) {
    let link = format!("{}/login", state.public_base());
    if let Err(e) = crate::outbox::enqueue_email(
        state,
        email,
        "Signet account already exists",
        &format!(
            "Someone tried to create a Signet account with this address. An account already \
             exists, so no new one was created.\n\nSign in: {link}\n\n\
             If you forgot your password, use the reset link on the sign-in page. If this \
             was not you, no action is needed."
        ),
        state.config.dev_log_links,
    )
    .await
    {
        tracing::error!(error = %e, %email, "existing-account notice enqueue failed");
    }
}

/// The request handler proper. Split from the route registration only so the
/// public flow reads top to bottom.
async fn request_impl(
    state: &AppState,
    headers: &HeaderMap,
    ip: Option<String>,
    body: SignupBody,
) -> AppResult<Json<Value>> {
    if !signup_enabled(&state.pool).await? {
        return Err(AppError::not_found("sign-up is not enabled"));
    }
    // Fail closed when a prerequisite disappeared after the switch was turned
    // on, rather than serving either a form without a challenge or one whose
    // mail can never arrive.
    let Some(captcha) = crate::captcha::resolve(state).await else {
        return Err(AppError::unavailable(
            "sign-up is temporarily unavailable: CAPTCHA is not configured",
        ));
    };
    if crate::email::configuration_problem(state).await.is_some() && !state.config.dev_log_links {
        return Err(AppError::unavailable(
            "sign-up is temporarily unavailable: email delivery is not configured",
        ));
    }

    let email = normalize_email(&body.email)?;
    // The challenge runs before any address-dependent work, so probing whether
    // an address exists costs a solved challenge per guess.
    crate::captcha::verify_with_gate(&captcha, body.captcha_token.as_deref(), ip.as_deref())
        .await?;

    record_attempt(&state.pool, ip.as_deref(), &email).await?;
    if over_budget(&state.pool, ip.as_deref(), &email).await? {
        record(
            state,
            AuditEvent {
                actor: None,
                action: "auth.signup_blocked",
                resource_type: "user",
                resource_id: None,
                detail: json!({
                    "reason": "rate_limited",
                    "email_domain": crate::admission::domain_of(&email),
                }),
                ip,
                user_agent: user_agent(headers),
                client_id: None,
            },
        )
        .await;
        return Err(AppError::too_many_requests(
            "too many sign-up attempts; try again later",
        ));
    }

    // Domain policy is public (it is shown on the form), so refusing here does
    // not disclose anything about an account that may or may not exist.
    crate::admission::ensure_provision_allowed(
        state,
        &email,
        crate::admission::via::SIGNUP,
        user_agent(headers),
        ip.as_deref(),
    )
    .await?;

    let display_name = normalize_display_name(body.display_name.as_deref(), &email)?;
    if body.password.len() > MAX_PASSWORD_LEN {
        return Err(AppError::bad_request("password is too long"));
    }
    validate_password_strength(&body.password, state.rt().password_min_length)
        .map_err(|e| AppError::bad_request(e.to_string()))?;

    // Hash before the existence lookup. An existing address then costs the same
    // Argon2 round as a new one — otherwise response time would answer the very
    // question the uniform 202 exists to hide.
    let password_hash = hash_password_offloaded(&body.password).await?;

    let taken: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1 OR username = $1")
            .bind(&email)
            .fetch_one(&state.pool)
            .await?;
    if taken > 0 {
        // One notice per minute per address: enough to tell the owner what
        // happened, not enough to use this endpoint as a mail amplifier.
        if recent_attempts(&state.pool, &email, "1 minute").await? <= 1 {
            send_existing_notice(state, &email).await;
        }
        record(
            state,
            AuditEvent {
                actor: None,
                action: "auth.signup_requested",
                resource_type: "user",
                resource_id: None,
                detail: json!({
                    "email": email,
                    "email_domain": crate::admission::domain_of(&email),
                    "existing_account": true,
                }),
                ip,
                user_agent: user_agent(headers),
                client_id: None,
            },
        )
        .await;
        return Ok(Json(json!({ "status": "ok" })));
    }

    // A request inside the cooldown is acknowledged but changes nothing: the
    // token already mailed stays valid, and no second message is sent.
    let pending_recently: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM signup_requests \
         WHERE email = $1 AND created_at > NOW() - ($2::int * INTERVAL '1 second')",
    )
    .bind(&email)
    .bind(RESEND_COOLDOWN_SECS)
    .fetch_one(&state.pool)
    .await?;
    if pending_recently > 0 {
        return Ok(Json(json!({ "status": "ok" })));
    }

    let token = random_token(32);
    sqlx::query(
        r#"
        INSERT INTO signup_requests
            (id, email, display_name, password_hash, token_hash, ip, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW() + ($7::int * INTERVAL '1 minute'))
        ON CONFLICT (email) DO UPDATE SET
            display_name = EXCLUDED.display_name,
            password_hash = EXCLUDED.password_hash,
            token_hash = EXCLUDED.token_hash,
            ip = EXCLUDED.ip,
            created_at = NOW(),
            expires_at = EXCLUDED.expires_at
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&email)
    .bind(&display_name)
    .bind(&password_hash)
    .bind(sha256_hex(&token))
    .bind(ip.as_deref())
    .bind(TTL_MINUTES)
    .execute(&state.pool)
    .await?;

    let visit = Visit {
        email: email.clone(),
        token,
    };
    send_verification(state, &visit).await;

    record(
        state,
        AuditEvent {
            actor: None,
            action: "auth.signup_requested",
            resource_type: "user",
            resource_id: None,
            detail: json!({
                "email": email,
                "email_domain": crate::admission::domain_of(&email),
                "existing_account": false,
            }),
            ip,
            user_agent: user_agent(headers),
            client_id: None,
        },
    )
    .await;

    // The same answer for every outcome: a new request, a repeat, and an
    // address that already has an account. The email is where the difference
    // is allowed to show.
    Ok(Json(json!({ "status": "ok" })))
}
