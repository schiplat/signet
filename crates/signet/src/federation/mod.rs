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
