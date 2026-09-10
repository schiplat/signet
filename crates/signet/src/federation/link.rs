//! Pending third-party identity binding after a local sign-in.
//!
//! When SSO cannot auto-link (no verified email match), the callback stashes
//! the upstream subject in `identity_link_challenges` and sets an HttpOnly
//! cookie. The next successful password / MFA / passkey login consumes that
//! cookie and inserts `user_identities`.

use crate::crypto_util::{random_token, sha256_hex};
use crate::models::User;
use crate::state::AppState;
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

/// If a pending SSO identity cookie is present, bind it to `user_id`.
///
/// Never fails the login: binding errors are logged and the cookie is cleared.
pub async fn consume_pending_link(state: &AppState, jar: CookieJar, user: &User) -> CookieJar {
    let Some(raw_state) = jar.get(PENDING_COOKIE).map(|c| c.value().to_owned()) else {
        return jar;
    };
    let jar = jar.add(clear_pending_cookie(state.config.cookie_secure));

    let row: Option<(String, String, Option<String>, serde_json::Value)> = match sqlx::query_as(
        "DELETE FROM identity_link_challenges \
         WHERE state = $1 AND expires_at > NOW() AND subject <> '' \
         RETURNING provider_code, subject, email, raw",
    )
    .bind(sha256_hex(&raw_state))
    .fetch_optional(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(error = %err, "failed to load pending sso link");
            return jar;
        }
    };
    let Some((provider_code, subject, email, raw)) = row else {
        return jar;
    };

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
            return jar;
        }
        return jar;
    }

    if let Err(err) = sqlx::query(
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
    .await
    {
        tracing::warn!(
            error = %err,
            provider = %provider_code,
            user_id = %user.id,
            "failed to bind pending sso identity"
        );
        return jar;
    }

    crate::audit::record(
        &state.pool,
        crate::audit::AuditEvent {
            actor: Some(user.clone()),
            action: "auth.identity.link",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "provider": provider_code, "via": "pending_after_login" }),
            ip: None,
            user_agent: None,
            client_id: None,
        },
    )
    .await;

    tracing::info!(
        provider = %provider_code,
        user_id = %user.id,
        "bound pending sso identity after local login"
    );
    jar
}
