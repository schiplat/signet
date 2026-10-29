//! HTTP flows for federated sign-in, and every other `/auth/sso/*` path.
//!
//! This file owns the whole `/api/v1/auth/sso/*` surface — the one prefix an
//! unauthenticated visitor can reach in the federation feature. That includes
//! the pre-auth provider list the login page renders and the self-service
//! identity management a signed-in user does. Keeping them with the flow means
//! the public surface is not scattered across a module named after admins;
//! `federation::admin` is admin-only.
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
//! MFA note: federation proves the upstream identity only — the local gates
//! still apply. `finish_sign_in` runs the account through the same steps a
//! password login walks after its first factor (`begin_login_mfa_flow`):
//! forced password change, TOTP challenge, or forced enrollment, each as a
//! redirect into the login page with `?sso_step=`. The shared continuation
//! endpoints (`/mfa/verify`, `/mfa/enroll/confirm`, `/login/password-change`)
//! then issue the session carrying the challenge's `sso` via.
//!
//! Return note: the login page passes the sanitized `return_to` (the
//! `/oauth/authorize?...` URL that started the whole thing) along to `start`;
//! it rides the challenge and, after the identity resolves — including through
//! the MFA gates — the browser goes back to it, so a third-party sign-in
//! inside an OIDC flow resumes that flow instead of dead-ending on `/`.

use crate::audit::{record, AuditEvent};
use crate::auth::current_user;
use crate::crypto::util::{random_token, sha256_hex};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie as AxumCookie, SameSite};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::json;

use super::provider::{ProviderConfig, UpstreamProfile, UpstreamProvider};

pub fn router() -> Router<AppState> {
    Router::new()
        // `/start` stays a literal: the backend only registers it, and the
        // dashboard is what builds the URL, so there is nothing to keep in sync
        // on this side. `CALLBACK_PATH` has two consumers and is shared.
        .route("/auth/sso/{provider}/start", axum::routing::get(start))
        .route(
            super::CALLBACK_PATH,
            axum::routing::get(callback).post(callback_verify),
        )
        // Public: the login page needs the enabled-provider list before the
        // visitor has a session, so this one has no auth check by design.
        .route(
            "/auth/sso/providers",
            axum::routing::get(public_enabled_providers),
        )
        // Signed in, but not admin: a user manages their own linked identities.
        .route(
            "/auth/sso/identities",
            axum::routing::get(list_my_identities),
        )
        .route(
            "/auth/sso/identities/{provider_code}",
            axum::routing::delete(unlink_identity),
        )
}

// ---------------------------------------------------------------------------
// The signed-in and pre-auth half of the same surface: the provider list the
// login page renders, and the identities a user has linked to their account.
// These live here rather than in `federation::admin` so that every
// `/auth/sso/*` path is in one file, and every route in `admin` needs admin.
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct UserIdentity {
    provider_code: String,
    provider_type: String,
    provider_display_name: String,
    email: Option<String>,
    linked_at: chrono::DateTime<chrono::Utc>,
    last_login_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Enabled providers, for the login page buttons. Public (no auth): the login
/// page itself needs this list before the visitor is authenticated. Returns
/// only what a button needs — code, type and label — so it leaks no config.
async fn public_enabled_providers(
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT code, provider_type, display_name FROM upstream_providers \
         WHERE enabled = TRUE ORDER BY code",
    )
    .fetch_all(&state.pool)
    .await?;
    let providers: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(code, provider_type, display_name)| {
            json!({ "code": code, "type": provider_type, "display_name": display_name })
        })
        .collect();
    Ok(Json(json!({ "providers": providers })))
}

async fn list_my_identities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let user = current_user(&state, &headers).await?;
    let rows: Vec<UserIdentity> = sqlx::query_as(
        r#"
        SELECT ui.provider_code, p.provider_type, p.display_name AS provider_display_name,
               ui.email, ui.linked_at, ui.last_login_at
        FROM user_identities ui
        JOIN upstream_providers p ON p.code = ui.provider_code
        WHERE ui.user_id = $1
        ORDER BY ui.linked_at
        "#,
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({ "identities": rows })))
}

async fn unlink_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider_code): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let user = current_user(&state, &headers).await?;

    // Lockout guard (pre-check): the user must keep at least one login
    // method after the unlink — a usable password or another identity.
    let has_password = !user.password_hash.is_empty();
    let linked: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_identities WHERE user_id = $1")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await?;
    if !has_password && linked <= 1 {
        return Err(AppError::bad_request("cannot unlink the last login method"));
    }

    let deleted =
        sqlx::query("DELETE FROM user_identities WHERE user_id = $1 AND provider_code = $2")
            .bind(user.id)
            .bind(&provider_code)
            .execute(&state.pool)
            .await?;
    if deleted.rows_affected() == 0 {
        return Err(AppError::not_found("identity not linked"));
    }

    record(
        &state,
        AuditEvent {
            resource_id: Some(user.id.to_string()),
            actor: Some(user),
            action: "auth.identity.unlink",
            resource_type: "user",
            detail: json!({ "provider": provider_code }),
            ip: None,
            user_agent: None,
            client_id: None,
        },
    )
    .await;
    Ok(Json(json!({ "ok": true })))
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
    String,         // jit_mode
    String,         // email_trust
);

async fn load_provider(state: &AppState, code: &str) -> Result<LoadedProvider, SsoError> {
    let row: Option<ProviderRow> = sqlx::query_as(
        "SELECT code, provider_type, display_name, client_id, client_secret_enc, \
                    issuer_url, scopes, enabled, jit_mode, email_trust \
             FROM upstream_providers WHERE code = $1",
    )
    .bind(code)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| SsoError::Upstream)?;

    let Some((
        code,
        ptype,
        display_name,
        client_id,
        secret_enc,
        issuer_url,
        scopes,
        enabled,
        jit_mode,
        email_trust,
    )) = row
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
            jit_mode,
            email_trust,
        },
    })
}

#[derive(Debug, Deserialize)]
struct StartQuery {
    /// Optional sanitized `/oauth/authorize?...` URL the visitor came from,
    /// stored with the challenge so the post-login redirect can resume the
    /// client's flow. Sanitized here, at the only door it enters through:
    /// values are browser input, and they become redirects later.
    return_to: Option<String>,
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

/// The same rule the login page applies to `return_to`: only same-origin
/// authorize / end-session paths may become a redirect target. Absolute and
/// protocol-relative URLs are refused, and so is any `..` segment — a path
/// like `/oauth/authorize/../settings` passes the prefix check but the browser
/// would normalize it elsewhere, which is exactly the kind of drift a
/// redirect validator must not let through.
pub fn safe_return_to(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() || raw.contains("://") || raw.starts_with("//") {
        return None;
    }
    if raw
        .split(['?', '#'])
        .next()?
        .split('/')
        .any(|seg| seg == "..")
    {
        return None;
    }
    (raw.starts_with("/oauth/authorize") || raw.starts_with("/oauth/end_session"))
        .then(|| raw.to_string())
}

/// `/login` URL with an optional `return_to` query (percent-encoded; the SPA's
/// router decodes it back into a redirect target). The separator follows the
/// base: callers pass a query-carrying base, but a bare path still works.
pub fn login_url(base: &str, return_to: Option<&str>) -> String {
    match return_to {
        Some(rt) => {
            let sep = if base.contains('?') { '&' } else { '?' };
            format!("{base}{sep}return_to={}", urlencoding::encode(rt))
        }
        None => base.to_string(),
    }
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
    .bind(json!({ "return_to": safe_return_to(q.return_to.as_deref()) }))
    .execute(&state.pool)
    .await
    .map_err(AppError::from)?;

    let redirect_uri = super::callback_url(&state, &provider_code);
    // Adapters take a nonce parameter for OIDC completeness; none of them
    // emits one (identity is resolved from userinfo, not the id_token), so
    // nothing here needs to remember one either.
    let url = loaded
        .adapter
        .authorize_url(&loaded.cfg, &redirect_uri, &state_value, "")
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
    let ip = crate::http::extract::client_ip(&headers, Some(addr));
    let user_agent = crate::http::extract::user_agent(&headers);

    // 1. Upstream error short-circuit (user denied access, etc.).
    if let Some(err) = q.error {
        let reason = match err.as_str() {
            // OAuth / Feishu: user clicked cancel / refuse on the consent page.
            "access_denied" | "user_denied" | "consent_required" => "access_denied",
            _ => "upstream_error",
        };
        if reason == "access_denied" {
            tracing::info!(provider = %provider_code, upstream = %err, "sso authorization denied by user");
        } else {
            tracing::warn!(provider = %provider_code, upstream = %err, "sso callback upstream error");
        }
        return Ok(
            sso_fail_redirect(&state, jar, &provider_code, reason, ip, user_agent, None).await,
        );
    }
    let (Some(code), Some(returned_state)) = (q.code.as_deref(), q.state.as_deref()) else {
        return Ok(sso_fail_redirect(
            &state,
            jar,
            &provider_code,
            "missing_code",
            ip,
            user_agent,
            None,
        )
        .await);
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
            None,
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
            None,
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
    let Some((_challenge_id, challenge_provider, challenge_meta)) = row else {
        return Ok(sso_fail_redirect(
            &state,
            jar,
            &provider_code,
            "state_mismatch",
            ip,
            user_agent,
            None,
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
            None,
        )
        .await);
    }
    let jar = jar.remove(STATE_COOKIE);

    // The challenge carries the sanitized `return_to` the login page handed to
    // `start`. It was validated before storage, so it is safe to redirect to;
    // every outcome below — failure or success — sends the visitor back into
    // the OIDC flow they came from.
    let return_to = challenge_meta
        .get("return_to")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // 3. Drive the provider adapter.
    let loaded = load_provider(&state, &provider_code).await?;
    let redirect_uri = super::callback_url(&state, &provider_code);
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
                return_to.as_deref(),
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
                return_to.as_deref(),
            )
            .await);
        }
    };

    // 4. Link resolution.
    // Read once, before anything below: the bind branch signs in as the
    // session's user, and finish_sign_in needs to know whether the visitor
    // already holds a session for the account it resolved (linking from the
    // profile page must not demand a fresh MFA challenge).
    let session_user_id = crate::auth::session::current_user(&state, &headers)
        .await
        .ok()
        .map(|u| u.id);

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
                    return_to.as_deref(),
                )
                .await);
            }

            // Admission, checked here because this is the first point where the
            // provider's asserted identity is known, and before anything is
            // created or linked: a refused identity must not leave a JIT account
            // or a pending link behind.
            //
            // Skipped for the already-signed-in link below, which admits nobody —
            // the person is already in — and which every later sign-in through
            // this identity goes through this check again.
            //
            // Both lists here are read against the *upstream* address, which is
            // what the provider is asserting. The local account's own address is
            // checked again at session creation, so a linked account cannot be
            // admitted through a provider whose identity is out of scope while its
            // own address is too.
            if session_user_id.is_none() {
                let upstream_email = profile.email.as_deref().filter(|e| !e.trim().is_empty());
                if !super::provider_allows(&state.pool, &provider_code, upstream_email).await? {
                    return Ok(sso_fail_redirect(
                        &state,
                        jar,
                        &provider_code,
                        "domain_not_allowed",
                        ip,
                        user_agent,
                        return_to.as_deref(),
                    )
                    .await);
                }
                // A list that is configured and an identity with no readable email
                // is a refusal: the address cannot be shown to belong, and passing
                // it would turn the restriction into a no-op for exactly the
                // provider that cannot be checked.
                let domains = crate::admission::allowed_domains(
                    &state.pool,
                    &state.config.allowed_email_domains,
                )
                .await?;
                if !crate::admission::allows(&domains, upstream_email.unwrap_or("")) {
                    return Ok(sso_fail_redirect(
                        &state,
                        jar,
                        &provider_code,
                        "domain_not_allowed",
                        ip,
                        user_agent,
                        return_to.as_deref(),
                    )
                    .await);
                }
            }

            if let Some(session_user_id) = session_user_id {
                sqlx::query(
                    "INSERT INTO user_identities \
                         (id, user_id, provider_code, subject, email, raw, last_login_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, NOW())",
                )
                .bind(uuid::Uuid::new_v4())
                .bind(session_user_id)
                .bind(&provider_code)
                .bind(&profile.subject)
                .bind(profile.email.as_deref())
                .bind(&profile.raw)
                .execute(&state.pool)
                .await
                .map_err(AppError::from)?;
                session_user_id
            } else {
                // 1) Trusted email matches an existing active user → link.
                // 2) Else JIT-create a member when enabled + trusted email.
                // 3) Else stash pending link for a later local password login.
                //
                // "Trusted" is the provider row's decision (`email_trust`),
                // resolved against what the adapter reported — not the raw
                // adapter flag.
                let email_verified = super::provider::effective_email_verified(
                    &loaded.cfg.email_trust,
                    profile.email_verified,
                    has_email,
                );
                let auto: Option<uuid::Uuid> = match (&profile.email, email_verified) {
                    (Some(email), true) => sqlx::query_scalar(
                        "SELECT id FROM users WHERE lower(email) = $1 AND status = 'active'",
                    )
                    .bind(email.to_lowercase())
                    .fetch_optional(&state.pool)
                    .await
                    .map_err(AppError::from)?,
                    _ => None,
                };
                let global_jit = super::admin::sso_jit_provision_enabled(
                    &state.pool,
                    state.config.sso_jit_provision,
                )
                .await?;
                let jit_enabled = super::provider::effective_jit(&loaded.cfg.jit_mode, global_jit);
                let user_id = if let Some(uid) = auto {
                    uid
                } else if jit_enabled && email_verified && has_email {
                    super::link::jit_create_user(&state, &provider_code, &profile).await?
                } else {
                    tracing::info!(
                        provider = %provider_code,
                        has_email = profile.email.is_some(),
                        email_verified = email_verified,
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
                        return_to.as_deref(),
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

    finish_sign_in(
        state,
        jar,
        user_id,
        provider_code,
        profile,
        ip,
        user_agent,
        session_user_id,
        return_to,
    )
    .await
}

/// Audits a failed SSO attempt and redirects the browser to the login page
/// with a machine-readable `?sso_error=` code (never leak upstream details).
/// A `return_to` recovered from the challenge rides along, so the visitor who
/// retries — by password or by provider — lands back in their OIDC flow.
async fn sso_fail_redirect(
    state: &AppState,
    jar: CookieJar,
    provider_code: &str,
    reason: &str,
    ip: Option<String>,
    user_agent: Option<String>,
    return_to: Option<&str>,
) -> Response {
    let client_id = crate::audit::resolve_audit_client_id(&state.pool, return_to).await;
    crate::audit::record(
        state,
        crate::audit::AuditEvent {
            actor: None,
            action: "auth.login.thirdparty",
            resource_type: "user",
            resource_id: None,
            detail: json!({ "provider": provider_code, "result": "failure", "reason": reason }),
            ip,
            user_agent,
            client_id,
        },
    )
    .await;
    let url = login_url(&format!("/login?sso_error={reason}"), return_to);
    (jar, Redirect::to(&url)).into_response()
}

/// Issues the session cookie and redirects into the SPA (browser OAuth
/// callbacks must not land on a raw JSON body).
///
/// The provider proved *who*; the local account gates still apply. An account
/// with a pending forced password change, an enrolled TOTP, or an enforced MFA
/// policy goes through the same steps a password login walks after its first
/// factor — as a redirect into the login page with `?sso_step=`, where the
/// shared continuation endpoints issue the session once the gate is satisfied.
/// A visitor who already holds a session for this very account (linking from
/// the profile page) passed the gates when that session was issued.
#[allow(clippy::too_many_arguments)]
async fn finish_sign_in(
    state: AppState,
    jar: CookieJar,
    user_id: uuid::Uuid,
    provider_code: String,
    profile: UpstreamProfile,
    ip: Option<String>,
    user_agent: Option<String>,
    session_user_id: Option<uuid::Uuid>,
    return_to: Option<String>,
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

    // (purpose, next step) for the gate the account must still pass, if any.
    let gate: Option<(&str, &str)> = if session_user_id != Some(user.id) {
        if user.must_change_password {
            Some(("change_password", "/login?sso_step=password_change"))
        } else if user.totp_enabled {
            Some(("login", "/login?sso_step=mfa"))
        } else if crate::mfa::global_mfa_required(&state.pool).await? || user.mfa_required {
            Some(("enroll", "/login?sso_step=enroll"))
        } else {
            None
        }
    } else {
        None
    };

    if let Some((purpose, next)) = gate {
        let token = crate::mfa::create_challenge(
            &state.pool,
            user.id,
            purpose,
            None,
            crate::admission::via::SSO,
        )
        .await?;
        let client_id =
            crate::audit::resolve_audit_client_id(&state.pool, return_to.as_deref()).await;
        crate::audit::record(
            &state,
            AuditEvent {
                actor: Some(user.clone()),
                action: "auth.login.thirdparty",
                resource_type: "user",
                resource_id: Some(user.id.to_string()),
                detail: json!({
                    "provider": provider_code,
                    "subject": profile.subject,
                    "result": "mfa_challenge",
                    "gate": purpose,
                }),
                ip: ip.clone(),
                user_agent: user_agent.clone(),
                client_id,
            },
        )
        .await;
        let jar = jar.add(crate::mfa::mfa_cookie(&token, state.config.cookie_secure));
        // The gate page keeps `return_to`: when the SPA finishes the MFA
        // continuation it bounces the browser back into the authorize flow.
        let url = login_url(next, return_to.as_deref());
        return Ok((jar, Redirect::to(&url)).into_response());
    }

    // The last check before the session exists, and the one the other sign-in
    // paths also go through. Both lists were checked in the callback before
    // anything was created, so a failure here means an administrator saved a
    // narrower list while this sign-in was in flight.
    let token = match crate::auth::session::create_sign_in_session(
        &state,
        &user,
        crate::admission::via::SSO,
        ip.as_deref(),
        user_agent.as_deref(),
    )
    .await
    {
        Ok(token) => token,
        Err(AppError::Unauthorized(_)) => {
            // The browser must not land on a JSON body, so the refusal leaves
            // through the same door as every other SSO failure.
            return Ok(sso_fail_redirect(
                &state,
                jar,
                &provider_code,
                "domain_not_allowed",
                ip,
                user_agent,
                return_to.as_deref(),
            )
            .await);
        }
        Err(e) => return Err(e),
    };
    let session = crate::auth::session::session_cookie(
        &token,
        state.config.cookie_secure,
        state.config.session_ttl_hours,
    );

    crate::auth::login_alert::track_login(&state, &user, ip.as_deref(), user_agent.as_deref())
        .await;

    let client_id = crate::audit::resolve_audit_client_id(&state.pool, return_to.as_deref()).await;
    crate::audit::record(
        &state,
        AuditEvent {
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
            client_id,
        },
    )
    .await;
    crate::metrics::inc_logins();

    // Back into the OIDC flow that started the sign-in when there was one;
    // otherwise the SPA guard routes staff to /overview (others to /activity).
    Ok((
        jar.add(session),
        Redirect::to(return_to.as_deref().unwrap_or("/")),
    )
        .into_response())
}
