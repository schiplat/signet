mod authorize;
mod consent;
mod discovery;
mod end_session;
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

/// Returns true when `scope` (space-separated) contains `wanted`.
pub(crate) fn scope_contains(scope: &str, wanted: &str) -> bool {
    scope.split_whitespace().any(|s| s == wanted)
}

/// Revoking a refresh family on reuse detection is the one token behavior tests
/// pin directly (the family SQL outlives the handler plumbing around it), so it
/// is re-exported past the private `token` module.
pub use token::revoke_refresh_family;

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
        .route("/oauth/revoke", post(revoke::revoke))
        .route("/oauth/register", post(register::register))
        .route(
            "/oauth/userinfo",
            get(userinfo::userinfo).post(userinfo::userinfo),
        )
        .route(
            "/oauth/end_session",
            get(end_session::end_session).post(end_session::end_session),
        )
        .route("/oauth/consent", post(consent::consent))
        .route(
            "/oauth/test-callback/{client_id}",
            get(test_callback::test_callback),
        )
}
