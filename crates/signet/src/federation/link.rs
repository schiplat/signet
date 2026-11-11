//! Pending third-party identity binding, and JIT provisioning of new local
//! users from a verified upstream email.
//!
//! When SSO cannot auto-link (no verified email match) and cannot JIT, the
//! callback stashes a pending link cookie. The bind itself is **explicit**:
//! the dashboard surfaces the stashed identity after the next sign-in and the
//! user confirms or discards it. It used to bind automatically at the end of
//! the next login in the same browser — which made the bind follow the
//! *browser* rather than the person, and on a shared machine an attacker's
//! stashed identity would attach itself to whoever signed in next, handing
//! them that account at their next SSO click.

use crate::crypto::util::{random_token, sha256_hex};
use crate::error::{AppError, AppResult};
use crate::models::User;
use crate::state::AppState;
use axum::http::HeaderMap;
use axum_extra::extract::cookie::{Cookie as AxumCookie, SameSite};
use axum_extra::extract::CookieJar;
use serde_json::json;
use uuid::Uuid;

use super::provider::UpstreamProfile;

pub(crate) const PENDING_COOKIE: &str = "signet_sso_pending";

fn pending_cookie(value: &str, secure: bool, max_age_secs: i64) -> AxumCookie<'static> {
    let mut cookie = AxumCookie::build((PENDING_COOKIE, value.to_owned()))
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

fn clear_pending_cookie(secure: bool) -> AxumCookie<'static> {
    let mut cookie = AxumCookie::build((PENDING_COOKIE, String::new()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(0))
        .build();
    if secure {
        cookie.set_secure(true);
    }
    cookie
}

/// Persist a pending upstream identity so the next local login can bind it.
pub(crate) async fn stash_pending_link(
    state: &AppState,
    jar: CookieJar,
    provider_code: &str,
    profile: &UpstreamProfile,
) -> CookieJar {
    let state_value = random_token(22);
    let _ = sqlx::query("DELETE FROM identity_link_challenges WHERE expires_at < NOW()")
        .execute(&state.pool)
        .await;
    if let Err(err) = sqlx::query(
        "INSERT INTO identity_link_challenges \
             (id, state, code_hash, email, display_name, provider_code, subject, raw, expires_at) \
         VALUES ($1, $2, '', $3, $4, $5, $6, $7, NOW() + INTERVAL '15 minutes')",
    )
    .bind(Uuid::new_v4())
    .bind(sha256_hex(&state_value))
    .bind(profile.email.as_deref())
    .bind(profile.display_name.as_deref())
    .bind(provider_code)
    .bind(&profile.subject)
    .bind(&profile.raw)
    .execute(&state.pool)
    .await
    {
        tracing::warn!(error = %err, provider = %provider_code, "failed to stash pending sso link");
        return jar;
    }
    jar.add(pending_cookie(
        &state_value,
        state.config.cookie_secure,
        15 * 60,
    ))
}

/// A stashed pending upstream identity, as surfaced to the signed-in user.
#[derive(Debug, serde::Serialize)]
pub struct PendingIdentity {
    pub provider: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

/// Reads the pending identity the request's cookie points at, if any.
///
/// A peek consumes nothing: the cookie and row survive until the user confirms
/// or discards, or the row's 15-minute TTL lapses.
pub async fn peek_pending_link(state: &AppState, headers: &HeaderMap) -> Option<PendingIdentity> {
    let raw_state = crate::auth::session::cookie_value(headers, PENDING_COOKIE)?;
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT provider_code, email, display_name \
         FROM identity_link_challenges \
         WHERE state = $1 AND expires_at > NOW() AND subject <> ''",
    )
    .bind(sha256_hex(&raw_state))
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    row.map(|(provider, email, display_name)| PendingIdentity {
        provider,
        email,
        display_name,
    })
}

/// Binds the pending upstream identity to `user` — only on their explicit
/// request.
///
/// Unlike the automatic bind it replaces, this is fallible and the errors are
/// the user's to read: a refusal here is a decision they asked for, not noise
/// a login should paper over.
pub async fn confirm_pending_link(
    state: &AppState,
    jar: CookieJar,
    user: &User,
) -> AppResult<(serde_json::Value, CookieJar)> {
    let Some(raw_state) = jar.get(PENDING_COOKIE).map(|c| c.value().to_owned()) else {
        return Err(AppError::not_found("no pending sso identity"));
    };

    // Consume atomically: one confirmation per stashed identity, and a double
    // click on "link" is one bind, not two attempts.
    let row: Option<(String, String, Option<String>, serde_json::Value)> = sqlx::query_as(
        "DELETE FROM identity_link_challenges \
         WHERE state = $1 AND expires_at > NOW() AND subject <> '' \
         RETURNING provider_code, subject, email, raw",
    )
    .bind(sha256_hex(&raw_state))
    .fetch_optional(&state.pool)
    .await?;
    let jar = jar.add(clear_pending_cookie(state.config.cookie_secure));
    let Some((provider_code, subject, email, raw)) = row else {
        return Err(AppError::not_found("no pending sso identity"));
    };

    // A provider deleted between stash and confirm is a clean refusal, not a
    // foreign-key violation: `provider_allows` treats a missing row as "carry
    // on" (its caller is normally the callback, where the next query reports
    // the deletion), but here the next statement is an INSERT into
    // `user_identities`, whose `provider_code` has an FK to
    // `upstream_providers(code)`. Without this check the user gets a 500 and
    // the stash has already been consumed.
    let provider_exists: Option<String> =
        sqlx::query_scalar("SELECT code FROM upstream_providers WHERE code = $1")
            .bind(&provider_code)
            .fetch_optional(&state.pool)
            .await?;
    if provider_exists.is_none() {
        return Err(AppError::not_found(
            "this sign-in provider no longer exists; ask an administrator to re-enable it",
        ));
    }

    // Admission at consume time. The checks ran when the identity was stashed,
    // but the lists are editable: a provider narrowed or deleted in between
    // must not retroactively admit an identity into a local account. The
    // per-provider list is the check that governs this act — the local account
    // itself already passed sign-in admission on its own credentials.
    if !super::provider_allows(&state.pool, &provider_code, email.as_deref()).await? {
        return Err(AppError::forbidden(
            "this identity's email is no longer allowed for this provider",
        ));
    }

    // Subject already bound to someone else — do not steal the link.
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM user_identities WHERE provider_code = $1 AND subject = $2",
    )
    .bind(&provider_code)
    .bind(&subject)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);
    if let Some(other) = existing {
        if other != user.id {
            tracing::warn!(
                provider = %provider_code,
                user_id = %user.id,
                other_user_id = %other,
                "pending sso subject already linked to another user"
            );
            return Err(AppError::conflict(
                "this identity is already linked to another account",
            ));
        }
        return Ok((json!({ "ok": true, "already_linked": true }), jar));
    }

    let inserted = sqlx::query(
        "INSERT INTO user_identities \
             (id, user_id, provider_code, subject, email, raw, last_login_at) \
         VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
         ON CONFLICT (provider_code, subject) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(user.id)
    .bind(&provider_code)
    .bind(&subject)
    .bind(email.as_deref())
    .bind(&raw)
    .execute(&state.pool)
    .await?;
    if inserted.rows_affected() == 0 {
        // Lost a race with a concurrent bind of the same subject.
        return Err(AppError::conflict(
            "this identity is already linked to another account",
        ));
    }

    crate::audit::record(
        state,
        crate::audit::AuditEvent {
            actor: Some(user.clone()),
            action: "auth.identity.link",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "provider": provider_code, "via": "pending_confirmed" }),
            ip: None,
            user_agent: None,
            client_id: None,
        },
    )
    .await;

    tracing::info!(
        provider = %provider_code,
        user_id = %user.id,
        "bound pending sso identity on user confirmation"
    );
    Ok((json!({ "ok": true }), jar))
}

/// Drops the pending identity, binding nothing. Works without a session: a
/// shared machine is exactly where "no" has to be easy.
pub async fn discard_pending_link(state: &AppState, jar: CookieJar) -> CookieJar {
    if let Some(raw_state) = jar.get(PENDING_COOKIE).map(|c| c.value().to_owned()) {
        let _ = sqlx::query("DELETE FROM identity_link_challenges WHERE state = $1")
            .bind(sha256_hex(&raw_state))
            .execute(&state.pool)
            .await;
    }
    jar.add(clear_pending_cookie(state.config.cookie_secure))
}

/// Create a local `member` from a verified upstream email and return its id.
///
/// Password is left empty (SSO-only until the user sets one). Concurrent
/// first-logins on the same email fall back to selecting the existing row.
pub(crate) async fn jit_create_user(
    state: &AppState,
    provider_code: &str,
    profile: &UpstreamProfile,
    email_verified: bool,
) -> AppResult<Uuid> {
    let email = profile
        .email
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::bad_request("jit requires verified email"))?
        .to_lowercase();
    // `email_verified` is the caller's RESOLVED trust decision (the provider
    // row's `email_trust` applied to the adapter flag) — not the raw adapter
    // flag, which providers like the generic OIDC bridge never set.
    if !email_verified {
        return Err(AppError::bad_request("jit requires verified email"));
    }

    // A backstop, not the refusal a person sees: the callback checks the
    // allowlist before anything is created and turns a failure into a redirect
    // with a reason. This one is here so that a future caller of this function
    // cannot create an account the allowlist excludes by simply not knowing about
    // it — the check belongs to the act of creating the account.
    crate::admission::ensure_provision_allowed(state, &email, crate::admission::via::SSO_JIT, None)
        .await?;

    let id = Uuid::new_v4();
    let sub = id.to_string();
    let display_name = profile
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| email.split('@').next().unwrap_or("user"))
        .to_string();

    let inserted: Option<Uuid> = sqlx::query_scalar(
        r#"
        INSERT INTO users (
            id, sub, email, display_name, password_hash, status, role,
            must_change_password, provisioned_via, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, '', 'active', 'member', FALSE, 'sso_jit', NOW(), NOW())
        ON CONFLICT (email) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(id)
    .bind(&sub)
    .bind(&email)
    .bind(&display_name)
    .fetch_optional(&state.pool)
    .await?;

    let user_id = if let Some(uid) = inserted {
        crate::audit::record(
            state,
            crate::audit::AuditEvent {
                actor: None,
                action: "user.create",
                resource_type: "user",
                resource_id: Some(uid.to_string()),
                detail: json!({
                    "via": "sso_jit",
                    "provider": provider_code,
                    "email": email,
                }),
                ip: None,
                user_agent: None,
                client_id: None,
            },
        )
        .await;
        tracing::info!(
            provider = %provider_code,
            user_id = %uid,
            "jit provisioned local user from sso"
        );
        uid
    } else {
        // Lost the race — another request created the same email.
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM users WHERE lower(email) = $1 AND status = 'active'",
        )
        .bind(&email)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::bad_request("email conflict"))?
    };

    Ok(user_id)
}
