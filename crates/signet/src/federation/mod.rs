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

/// Path template for the SSO callback, relative to [`crate::API_PREFIX`].
///
/// One literal serves both directions: [`routes`] registers it as a route, and
/// [`callback_url`] fills in the provider code to build the absolute URL sent
/// upstream as the OAuth `redirect_uri`. Splitting these into two literals
/// would work until someone edited one of them, and then sign-in would fail
/// only at the IdP with a `redirect_uri_mismatch` while everything here still
/// looked right.
const CALLBACK_PATH: &str = "/auth/sso/{provider}/callback";

/// The callback path for `code`, below [`crate::API_PREFIX`].
///
/// Exposed for `tests/`; the route in [`routes`] and the URL sent upstream
/// both derive from [`CALLBACK_PATH`], so this is only about pinning the
/// resulting literal, not about the wiring.
pub fn callback_path(code: &str) -> String {
    CALLBACK_PATH.replace("{provider}", code)
}

/// The absolute callback URL for `code`, as handed to the provider and shown
/// to admins.
///
/// Composed here rather than at each use site, because the same URL has to
/// agree in two directions: [`routes`] sends it upstream on both the authorize
/// and token-exchange requests, while [`admin`] shows it to the operator to
/// register with the provider. Platform quirks (WeChat encoding, Feishu app
/// tokens, OIDC discovery) are absorbed by the adapters, never by the URL shape.
fn callback_url(state: &AppState, code: &str) -> String {
    format!(
        "{}{}{}",
        state.config.public_base(),
        crate::API_PREFIX,
        callback_path(code)
    )
}
