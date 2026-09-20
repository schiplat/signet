//! Federated identity: sign-in via upstream identity providers (GitHub,
//! Google, Feishu, WeChat Open Platform, and any standard OIDC issuer).
//!
//! Architecture:
//! - [`provider`]: the connector trait. Each adapter in [`providers`]
//!   implements three operations: build the authorize URL, exchange the
//!   callback code for tokens, and fetch a normalized profile.
//! - [`routes`]: `/auth/sso/:provider/start` and `/auth/sso/:provider/callback`
//!   plus session issuance and the account-linking flow.
//! - Account linking: a verified upstream email that matches an existing
//!   local user auto-links; otherwise a pending link is stashed and completed
//!   on the next local password / MFA / passkey sign-in. An already-authenticated
//!   session can also bind on the SSO callback.

pub mod admin;
pub mod link;
pub mod provider;
pub mod providers;
pub mod routes;

pub use link::consume_pending_link;

use crate::state::AppState;

/// Public base URL for provider redirect URIs: `SIGNET_PUBLIC_BASE_URL` when
/// set, falling back to the issuer (single-host deployments).
fn public_base(state: &AppState) -> String {
    state
        .config
        .public_base_url
        .clone()
        .unwrap_or_else(|| state.config.issuer.clone())
        .trim_end_matches('/')
        .to_string()
}

/// The one redirect-URI pattern shared by every provider type.
///
/// Composed here rather than at each use site, because the same URL has to
/// agree in two directions: [`routes`] sends it upstream as the OAuth
/// `redirect_uri` on both the authorize and token-exchange requests, while
/// [`admin`] shows it to the operator to register with the provider. Both
/// silently break sign-in if they disagree, so there is exactly one
/// implementation. Platform quirks (WeChat encoding, Feishu app tokens, OIDC
/// discovery) are absorbed by the adapters, never by the URL shape.
fn callback_url(state: &AppState, code: &str) -> String {
    format!(
        "{}{}/auth/sso/{code}/callback",
        public_base(state),
        crate::API_PREFIX
    )
}
