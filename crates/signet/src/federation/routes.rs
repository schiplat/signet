//! HTTP flows for federated sign-in.
//!
//! `start` mints a cryptographically random `state`, stores its hash in
//! `identity_link_challenges` plus an HttpOnly cookie, and redirects to the
//! upstream authorize URL. `callback` verifies the state, exchanges the code,
//! resolves the profile, then either signs the linked user in or starts the
//! account-linking flow:
//!
//! - already linked `(provider, subject)` → sign in
//! - authenticated session present → bind to that user and sign in
//! - upstream email verified + matching local user → auto-link and sign in
//! - JIT (default on): verified email, no local user → create `member` + link
//! - otherwise → stash a pending link cookie and ask the visitor to sign in
//!   locally; the next password/MFA/passkey login completes the bind
//!
//! MFA note: federation proves the upstream identity only. Users with TOTP
//! enforced still satisfy the local MFA challenge via the standard flow later.

use crate::crypto_util::{random_token, sha256_hex};
use crate::error::AppError;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie as AxumCookie, SameSite};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::json;

use super::provider::{ProviderConfig, UpstreamProfile, UpstreamProvider};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/sso/{provider}/start", axum::routing::get(start))
        .route(
            "/auth/sso/{provider}/callback",
            axum::routing::get(callback).post(callback_verify),
        )
}

/// Platform-side URL verification shim.
///
/// Feishu (and similar platforms) validate an **event-subscription** URL by
/// POSTing `{"type":"url_verification","challenge":"..."}` and requiring the
/// `challenge` echoed back within 1s. The OAuth browser flow never uses this,
/// but supporting it here means a callback URL pasted into the wrong config
/// field still passes platform-side verification instead of failing with
/// "Challenge code not returned". Real event pushes are acked and dropped —
/// Signet's federation flow consumes no events.
async fn callback_verify(Json(body): Json<serde_json::Value>) -> Response {
    if let Some(challenge) = body.get("challenge").and_then(|c| c.as_str()) {
        return (
            axum::http::StatusCode::OK,
            Json(json!({ "challenge": challenge })),
        )
            .into_response();
    }
    // Ack any other payload so platforms don't retry-storm; content ignored.
    (axum::http::StatusCode::OK, Json(json!({ "code": 0 }))).into_response()
}

/// Machine-readable failures surfaced to the login page via `?sso_error=`.
/// Never leak upstream internals into the URL.
#[derive(Debug)]
enum SsoError {
    UnknownProvider,
    ProviderDisabled,
    /// Retained for the phase-2 binding flow (browser callback redirect).
    #[allow(dead_code)]
    StateMismatch,
    Upstream,
}

impl SsoError {
    fn code(&self) -> &'static str {
        match self {
            SsoError::UnknownProvider => "unknown_provider",
            SsoError::ProviderDisabled => "provider_disabled",
            SsoError::StateMismatch => "state_mismatch",
            SsoError::Upstream => "upstream_error",
        }
    }
}

impl From<SsoError> for AppError {
    fn from(e: SsoError) -> Self {
        // Deliberately terse: details go to the log, not the browser.
        AppError::BadRequest(e.code().to_string())
    }
}

/// A provider row joined with its adapter, ready to drive.
struct LoadedProvider {
    adapter: std::sync::Arc<dyn UpstreamProvider + Send + Sync>,
    cfg: ProviderConfig,
}

/// Columns selected from `upstream_providers` for the SSO flow.
type ProviderRow = (
    String,         // code
    String,         // provider_type
    String,         // display_name
    String,         // client_id
    String,         // client_secret_enc
    Option<String>, // issuer_url
    Option<String>, // scopes
    bool,           // enabled
);

async fn load_provider(state: &AppState, code: &str) -> Result<LoadedProvider, SsoError> {
    let row: Option<ProviderRow> = sqlx::query_as(
        "SELECT code, provider_type, display_name, client_id, client_secret_enc, \
                    issuer_url, scopes, enabled \
             FROM upstream_providers WHERE code = $1",
    )
    .bind(code)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| SsoError::Upstream)?;

    let Some((code, ptype, display_name, client_id, secret_enc, issuer_url, scopes, enabled)) = row
    else {
        return Err(SsoError::UnknownProvider);
    };
    if !enabled {
        return Err(SsoError::ProviderDisabled);
    }
    let client_secret = state
        .encryptor
        .decrypt(&secret_enc)
        .ok_or(SsoError::Upstream)?;

    let adapter: std::sync::Arc<dyn UpstreamProvider + Send + Sync> = match ptype.as_str() {
        "github" => std::sync::Arc::new(super::providers::GitHub),
        "google" => std::sync::Arc::new(super::providers::Google),
        "feishu" => std::sync::Arc::new(super::providers::Feishu),
        "wechat" => std::sync::Arc::new(super::providers::WeChat),
        "oidc" => std::sync::Arc::new(super::providers::GenericOidc),
        _ => return Err(SsoError::Upstream),
    };

    Ok(LoadedProvider {
        adapter,
        cfg: ProviderConfig {
            code,
            provider_type: ptype,
            display_name,
            client_id,
            client_secret,
            issuer_url,
            scopes,
        },
    })
}

#[derive(Debug, Deserialize)]
struct StartQuery {
    /// Optional OIDC client that initiated sign-in; stored with the challenge
    /// so the post-login redirect can return to the client's flow.
    client_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

const STATE_COOKIE: &str = "signet_sso_state";

fn hash_state(state: &str) -> String {
    sha256_hex(state)
}

fn sso_cookie(
    name: &'static str,
    value: &str,
    secure: bool,
    max_age_secs: i64,
) -> AxumCookie<'static> {
    let mut cookie = AxumCookie::build((name, value.to_owned()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(max_age_secs))
        .build();
    if secure {
        cookie.set_secure(true);
    }
    cookie
}

/// Base URL for provider redirect URIs (shared helper in admin.rs).
fn base_url(state: &AppState) -> String {
    super::admin::public_base(state)
}

async fn start(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(provider_code): Path<String>,
    Query(q): Query<StartQuery>,
) -> Result<Response, AppError> {
    let loaded = load_provider(&state, &provider_code).await?;

    // 176 bits of entropy; the cookie carries the raw value while the DB
    // stores only its hash, so a database leak cannot forge a handshake.
    let state_value = random_token(22);
    let nonce = uuid::Uuid::new_v4().to_string();

    sqlx::query("DELETE FROM identity_link_challenges WHERE expires_at < NOW()")
        .execute(&state.pool)
        .await
        .map_err(AppError::from)?;
    sqlx::query(
        "INSERT INTO identity_link_challenges \
             (id, state, code_hash, provider_code, subject, raw, expires_at) \
         VALUES ($1, $2, '', $3, '', $4, NOW() + INTERVAL '10 minutes')",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(hash_state(&state_value))
    .bind(&provider_code)
    .bind(json!({ "client_id": q.client_id, "nonce": nonce }))
    .execute(&state.pool)
    .await
    .map_err(AppError::from)?;

    let redirect_uri = redirect_uri(&state, &provider_code);
    let url = loaded
        .adapter
        .authorize_url(&loaded.cfg, &redirect_uri, &state_value, &nonce)
        .await
        .map_err(|e| {
            tracing::warn!(provider = %provider_code, error = %e, "sso authorize url failed");
            SsoError::Upstream
        })?;

    let cookie = sso_cookie(
        STATE_COOKIE,
        &state_value,
        state.config.cookie_secure,
        10 * 60,
    );
    Ok((jar.add(cookie), Redirect::to(&url)).into_response())
}

async fn callback(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path(provider_code): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    let ip = crate::http_util::client_ip(&headers, Some(addr));
    let user_agent = crate::http_util::user_agent(&headers);

    // 1. Upstream error short-circuit (user denied access, etc.).
    if let Some(err) = q.error {
        tracing::warn!(provider = %provider_code, upstream = %err, "sso callback upstream error");
        return Ok(sso_fail_redirect(
            &state,
            jar,
            &provider_code,
            "upstream_error",
            ip,
            user_agent,
        )
        .await);
    }
    let (Some(code), Some(returned_state)) = (q.code.as_deref(), q.state.as_deref()) else {
        return Ok(
            sso_fail_redirect(&state, jar, &provider_code, "missing_code", ip, user_agent).await,
        );
    };

    // 2. Double-submit state check: cookie value must match the DB row's
    //    hash and the row must be fresh. One-time: delete on read.
    let Some(cookie_state) = jar.get(STATE_COOKIE).map(|c| c.value().to_owned()) else {
        return Ok(sso_fail_redirect(
            &state,
            jar,
            &provider_code,
            "state_mismatch",
            ip,
            user_agent,
        )
        .await);
    };
    if cookie_state != returned_state {
        return Ok(sso_fail_redirect(
            &state,
            jar,
            &provider_code,
            "state_mismatch",
            ip,
            user_agent,
        )
        .await);
    }
    let row: Option<(uuid::Uuid, String, serde_json::Value)> = sqlx::query_as(
        "DELETE FROM identity_link_challenges \
         WHERE state = $1 AND expires_at > NOW() \
         RETURNING id, provider_code, raw",
    )
    .bind(hash_state(&cookie_state))
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::from)?;
    let Some((_challenge_id, challenge_provider, _challenge_meta)) = row else {
        return Ok(sso_fail_redirect(
            &state,
            jar,
            &provider_code,
            "state_mismatch",
            ip,
            user_agent,
        )
        .await);
    };
    if challenge_provider != provider_code {
        return Ok(sso_fail_redirect(
            &state,
            jar,
            &provider_code,
            "state_mismatch",
            ip,
            user_agent,
        )
        .await);
    }
    let jar = jar.remove(STATE_COOKIE);

    // 3. Drive the provider adapter.
    let loaded = load_provider(&state, &provider_code).await?;
    let redirect_uri = redirect_uri(&state, &provider_code);
    let tokens = loaded
        .adapter
        .exchange(&loaded.cfg, &redirect_uri, code)
        .await
        .map_err(|e| {
            tracing::warn!(provider = %provider_code, error = %e, "sso token exchange failed");
            e
        });
    let tokens = match tokens {
        Ok(t) => t,
        Err(_) => {
            return Ok(sso_fail_redirect(
                &state,
                jar,
                &provider_code,
                "upstream_error",
                ip,
                user_agent,
            )
            .await);
        }
    };
    let profile = match loaded.adapter.profile(&loaded.cfg, &tokens).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(provider = %provider_code, error = %e, "sso profile fetch failed");
            return Ok(sso_fail_redirect(
                &state,
                jar,
                &provider_code,
                "upstream_error",
                ip,
                user_agent,
            )
            .await);
        }
    };

    // 4. Link resolution.
    let linked: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM user_identities WHERE provider_code = $1 AND subject = $2",
    )
    .bind(&provider_code)
    .bind(&profile.subject)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::from)?;

    let user_id = match linked {
        Some(user_id) => user_id,
        None => {
            // Providers that can supply email must do so before any new bind
            // (session link, auto-link, JIT, or pending). WeChat has no email
            // API and stays exempt. Already-linked subjects skip this check.
            let has_email = profile
                .email
                .as_deref()
                .is_some_and(|e| !e.trim().is_empty());
            if loaded.cfg.provider_type != "wechat" && !has_email {
                tracing::info!(
                    provider = %provider_code,
                    provider_type = %loaded.cfg.provider_type,
                    "sso profile missing email; refusing new bind"
                );
                return Ok(sso_fail_redirect(
                    &state,
                    jar,
                    &provider_code,
                    "email_required",
                    ip,
                    user_agent,
                )
                .await);
            }

            // Already signed in (e.g. linking from the profile page): bind to
            // the current session user without requiring an email match.
            if let Ok(session_user) = crate::auth::session::current_user(&state, &headers).await {
                sqlx::query(
                    "INSERT INTO user_identities \
                         (id, user_id, provider_code, subject, email, raw, last_login_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, NOW())",
                )
                .bind(uuid::Uuid::new_v4())
                .bind(session_user.id)
                .bind(&provider_code)
                .bind(&profile.subject)
                .bind(profile.email.as_deref())
                .bind(&profile.raw)
                .execute(&state.pool)
                .await
                .map_err(AppError::from)?;
                session_user.id
            } else {
                // 1) Verified email matches an existing active user → link.
                // 2) Else JIT-create a member when enabled + verified email.
                // 3) Else stash pending link for a later local password login.
                let auto: Option<uuid::Uuid> = match (&profile.email, profile.email_verified) {
                    (Some(email), true) => sqlx::query_scalar(
                        "SELECT id FROM users WHERE lower(email) = $1 AND status = 'active'",
                    )
                    .bind(email.to_lowercase())
                    .fetch_optional(&state.pool)
                    .await
                    .map_err(AppError::from)?,
                    _ => None,
                };
                let jit_enabled = super::admin::sso_jit_provision_enabled(
                    &state.pool,
                    state.config.sso_jit_provision,
                )
                .await?;
                let user_id = if let Some(uid) = auto {
                    uid
                } else if jit_enabled
                    && profile.email_verified
                    && profile
                        .email
                        .as_deref()
                        .is_some_and(|e| !e.trim().is_empty())
                {
                    super::link::jit_create_user(&state, &provider_code, &profile).await?
                } else {
                    tracing::info!(
                        provider = %provider_code,
                        has_email = profile.email.is_some(),
                        email_verified = profile.email_verified,
                        jit = jit_enabled,
                        "sso auto-link/jit skipped; stashing pending link"
                    );
                    let jar =
                        super::link::stash_pending_link(&state, jar, &provider_code, &profile)
                            .await;
                    return Ok(sso_fail_redirect(
                        &state,
                        jar,
                        &provider_code,
                        "no_matching_account",
                        ip,
                        user_agent,
                    )
                    .await);
                };
                sqlx::query(
                    "INSERT INTO user_identities \
                         (id, user_id, provider_code, subject, email, raw, last_login_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
                     ON CONFLICT (provider_code, subject) DO NOTHING",
                )
                .bind(uuid::Uuid::new_v4())
                .bind(user_id)
                .bind(&provider_code)
                .bind(&profile.subject)
                .bind(profile.email.as_deref())
                .bind(&profile.raw)
                .execute(&state.pool)
                .await
                .map_err(AppError::from)?;
                user_id
            }
        }
    };

    finish_sign_in(state, jar, user_id, provider_code, profile, ip, user_agent).await
}

fn redirect_uri(state: &AppState, provider_code: &str) -> String {
    format!(
        "{}/api/v1/auth/sso/{provider_code}/callback",
        base_url(state),
    )
}

/// Audits a failed SSO attempt and redirects the browser to the login page
/// with a machine-readable `?sso_error=` code (never leak upstream details).
async fn sso_fail_redirect(
    state: &AppState,
    jar: CookieJar,
    provider_code: &str,
    reason: &str,
    ip: Option<String>,
    user_agent: Option<String>,
) -> Response {
    crate::audit::record(
        &state.pool,
        crate::audit::AuditEvent {
            actor: None,
            action: "auth.login.thirdparty",
            resource_type: "user",
            resource_id: None,
            detail: json!({ "provider": provider_code, "result": "failure", "reason": reason }),
            ip,
            user_agent,
            client_id: None,
        },
    )
    .await;
    (jar, Redirect::to(&format!("/login?sso_error={reason}"))).into_response()
}

/// Issues the session cookie and redirects into the SPA (browser OAuth
/// callbacks must not land on a raw JSON body).
#[allow(clippy::too_many_arguments)]
async fn finish_sign_in(
    state: AppState,
    jar: CookieJar,
    user_id: uuid::Uuid,
    provider_code: String,
    profile: UpstreamProfile,
    ip: Option<String>,
    user_agent: Option<String>,
) -> Result<Response, AppError> {
    let user: crate::models::User = sqlx::query_as(&format!(
        "SELECT {} FROM users WHERE id = $1 AND status = 'active'",
        crate::models::USER_COLS
    ))
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::from(SsoError::Upstream))?;

    sqlx::query(
        "UPDATE user_identities SET last_login_at = NOW(), raw = $3 \
         WHERE provider_code = $1 AND subject = $2",
    )
    .bind(&provider_code)
    .bind(&profile.subject)
    .bind(&profile.raw)
    .execute(&state.pool)
    .await
    .map_err(AppError::from)?;

    let token = crate::auth::session::create_session(
        &state.pool,
        user.id,
        state.config.session_ttl_hours,
        ip.as_deref(),
        user_agent.as_deref(),
    )
    .await?;
    let session = crate::auth::session::session_cookie(
        &token,
        state.config.cookie_secure,
        state.config.session_ttl_hours,
    );

    crate::login_alert::track_login(&state.pool, &user, ip.as_deref(), user_agent.as_deref()).await;

    crate::audit::record(
        &state.pool,
        crate::audit::AuditEvent {
            actor: Some(user),
            action: "auth.login.thirdparty",
            resource_type: "user",
            resource_id: Some(user_id.to_string()),
            detail: json!({
                "provider": provider_code,
                "subject": profile.subject,
                "email": profile.email,
            }),
            ip,
            user_agent,
            client_id: None,
        },
    )
    .await;
    crate::metrics::inc_logins();

    // Land on `/` — the SPA beforeEach guard loads /me from the session cookie
    // and routes staff to /overview (or non-staff to /activity).
    Ok((jar.add(session), Redirect::to("/")).into_response())
}
