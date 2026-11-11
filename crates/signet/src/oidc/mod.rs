mod authorize;
mod consent;
mod discovery;
mod end_session;
mod introspect;
mod jwks;
mod register;
mod revoke;
mod test_callback;
mod token;
mod userinfo;

use crate::error::AppResult;
use crate::state::AppState;
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use uuid::Uuid;

/// Returns true when `scope` (space-separated) contains `wanted`.
pub(crate) fn scope_contains(scope: &str, wanted: &str) -> bool {
    scope.split_whitespace().any(|s| s == wanted)
}

/// Revoking a refresh family on reuse detection is the one token behavior tests
/// pin directly (the family SQL outlives the handler plumbing around it), so it
/// is re-exported past the private `token` module. Its credential-event
/// sibling rides along for the same reason: the password paths in `auth` and
/// `admin` revoke it without importing the token plumbing.
pub use token::revoke_refresh_family;
pub use token::revoke_refresh_tokens_for_user;

/// De-duplicates a space-separated scope list, preserving first-seen order.
/// OIDC scopes form a set, so duplicates (e.g. a client that sends
/// `openid openid profile`) carry no extra meaning and only cause repeated
/// entries on the consent page and in stored grants.
pub(crate) fn normalize_scope(scope: &str) -> String {
    let mut seen: Vec<&str> = Vec::new();
    for s in scope.split_whitespace() {
        if !seen.contains(&s) {
            seen.push(s);
        }
    }
    seen.join(" ")
}

/// Returns true when every requested scope is present in `granted`.
pub(crate) fn scope_covered(granted: &str, requested: &str) -> bool {
    requested
        .split_whitespace()
        .all(|r| scope_contains(granted, r))
}

/// Rejects any requested scope that is not in the client's registered `scopes`
/// allow-list. `openid` is always present in both, so it always passes.
pub(crate) fn validate_client_scope(requested: &str, allowed: &[String]) -> AppResult<()> {
    for s in requested.split_whitespace() {
        if !allowed.iter().any(|a| a == s) {
            return Err(crate::error::AppError::bad_request(format!(
                "scope not allowed for this client: {s}"
            )));
        }
    }
    Ok(())
}

/// RFC 7636 §4.1/§4.2: a PKCE verifier and its S256 challenge are 43–128
/// characters from the unreserved set. Nothing exploits a violation — the
/// exchange still hashes what it received — but an unbounded value is stored in
/// the code row and echoed into requests, so the bound belongs at the edge.
pub(crate) fn validate_pkce_param(name: &str, value: &str) -> AppResult<()> {
    if !(43..=128).contains(&value.len()) {
        return Err(crate::error::AppError::bad_request(format!(
            "{name} must be 43-128 characters"
        )));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
    {
        return Err(crate::error::AppError::bad_request(format!(
            "{name} contains characters outside the unreserved set"
        )));
    }
    Ok(())
}

/// Caps a caller-supplied value that is otherwise echoed back (state into the
/// redirect, nonce into the id_token). OIDC sets no limit; a megabyte of state
/// is a client bug, and storing it makes the code row and redirect unbounded.
pub(crate) fn validate_param_len(name: &str, value: &str, max: usize) -> AppResult<()> {
    if value.len() > max {
        return Err(crate::error::AppError::bad_request(format!(
            "{name} exceeds {max} characters"
        )));
    }
    Ok(())
}

/// Decodes an access token generically for introspection: signature (by kid),
/// issuer, algorithm — everything except expiry, which the caller checks to
/// keep `active: false` as data rather than an error.
pub(crate) struct IntrospectionClaims {
    pub sub: String,
    pub aud: String,
    pub iss: String,
    pub exp: i64,
    pub iat: i64,
    pub scope: String,
    pub token_use: Option<String>,
}

pub(crate) fn decode_access_token(
    state: &AppState,
    token: &str,
) -> Result<IntrospectionClaims, jsonwebtoken::errors::Error> {
    use jsonwebtoken::{Algorithm, Validation};
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(std::slice::from_ref(&state.config.issuer));
    validation.validate_exp = false;
    validation.validate_aud = false;
    let data = state.keys.verify::<serde_json::Value>(token, &validation)?;
    let claims = data.claims;
    let string = |k: &str| {
        claims
            .get(k)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    Ok(IntrospectionClaims {
        sub: string("sub").unwrap_or_default(),
        aud: string("aud").unwrap_or_default(),
        iss: string("iss").unwrap_or_default(),
        exp: claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(0),
        iat: claims.get("iat").and_then(|v| v.as_i64()).unwrap_or(0),
        scope: string("scope").unwrap_or_default(),
        token_use: string("token_use"),
    })
}

/// Fires OIDC Back-Channel Logout (1.0) to every client that registered a
/// `backchannel_logout_uri` and holds a grant for this user.
///
/// Fired best-effort by design: the user's Signet session is already gone by
/// the time this runs, so a failed notification cannot be rolled back — it is
/// logged, and RPs that need certainty should also reconcile via introspection
/// or short access-token TTLs. The logout token is a signed JWT with the
/// `events` member the draft specifies and **no** `sid` (Signet's consents are
/// user-scoped, so the RP is told to clear the whole subject).
pub async fn fire_backchannel_logout(state: &AppState, user_id: Uuid) {
    fire_backchannel_logout_core(
        &state.pool,
        &state.keys,
        state.config.issuer.as_str(),
        state.config.outbound_allow_private,
        user_id,
    )
    .await;
}

async fn fire_backchannel_logout_core(
    pool: &sqlx::PgPool,
    keys: &crate::crypto::keys::JwtKeys,
    issuer: &str,
    allow_private: bool,
    user_id: Uuid,
) {
    let Ok(user) = crate::models::user_by_id(pool, user_id).await else {
        return;
    };
    let rows: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT c.client_id, c.backchannel_logout_uri
        FROM client_apps c
        JOIN oauth_consents o ON o.client_id = c.client_id
        WHERE o.user_id = $1
          AND c.backchannel_logout_uri IS NOT NULL
          AND c.backchannel_logout_uri <> ''
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    if rows.is_empty() {
        return;
    }

    let now = chrono::Utc::now().timestamp();
    for (client_id, uri) in rows {
        let claims = json!({
            "iss": issuer,
            "aud": client_id,
            "sub": user.sub,
            "iat": now,
            "exp": now + 120,
            "jti": Uuid::new_v4().to_string(),
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            },
        });
        let Ok(token) = keys.encode(&claims) else {
            tracing::error!(%client_id, "failed to sign back-channel logout token");
            continue;
        };
        let Ok(target) = url::Url::parse(&uri) else {
            tracing::warn!(%client_id, uri, "backchannel_logout_uri is not a valid URL");
            continue;
        };
        let Ok(client) = crate::outbound::pinned_client(&uri, allow_private)
            .await
            .map(|(c, _)| c)
        else {
            tracing::warn!(%client_id, uri, "backchannel_logout_uri rejected by outbound policy");
            continue;
        };
        // form-encoded `logout_token=...` per the draft; 200 expected, body ignored.
        let result = client
            .post(target)
            .form(&[("logout_token", token.as_str())])
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await;
        match result {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => {
                tracing::warn!(%client_id, status = %resp.status(), "back-channel logout rejected")
            }
            Err(e) => tracing::warn!(error = %e, %client_id, "back-channel logout failed"),
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(discovery::openid_configuration),
        )
        .route("/oauth/jwks", get(jwks::jwks))
        .route(
            "/oauth/authorize",
            get(authorize::authorize).post(authorize::authorize),
        )
        .route("/oauth/token", post(token::token))
        .route("/oauth/introspect", post(introspect::introspect))
        .route("/oauth/revoke", post(revoke::revoke))
        .route("/oauth/register", post(register::register))
        .route(
            "/oauth/userinfo",
            get(userinfo::userinfo).post(userinfo::userinfo),
        )
        .route(
            "/oauth/end_session",
            // GET requires a valid id_token_hint (CSRF-safe); POST does not,
            // because a cross-site form POST carries no Lax cookie.
            get(end_session::end_session_get).post(end_session::end_session_post),
        )
        .route("/oauth/consent", post(consent::consent))
        .route(
            "/oauth/test-callback/{client_id}",
            get(test_callback::test_callback),
        )
}
