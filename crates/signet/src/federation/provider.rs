//! Upstream provider connectors.
//!
//! [`UpstreamProvider`] is the single integration surface: the flow in
//! [`super::routes`] drives `authorize_url` → `exchange` → `profile` for any
//! provider. Adding a provider means implementing this trait; nothing else in
//! Signet changes.
//!
//! Configuration lives in the `upstream_providers` table (client id/secret,
//! issuer for OIDC), so onboarding a provider needs no redeploy.

use anyhow::{anyhow, Result};
use serde::Deserialize;

/// Normalized who-just-signed-in payload from an upstream provider.
///
/// `subject` must be stable for the same upstream account (GitHub user id,
/// OIDC `sub`, WeChat unionid, ...). `email_verified == true` is required for
/// the auto-link path; without it the visitor must confirm the link.
#[derive(Debug, Clone)]
pub struct UpstreamProfile {
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    /// Full upstream profile payload, stored on `user_identities.raw`.
    pub raw: serde_json::Value,
}

/// Decrypted row of `upstream_providers`, ready for adapter use.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub code: String,
    pub provider_type: String,
    pub display_name: String,
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: Option<String>,
    pub scopes: Option<String>,
    /// `inherit` | `on` | `off` — this provider's override of the global JIT
    /// toggle. Resolved with [`effective_jit`].
    pub jit_mode: String,
    /// `inherit` | `any` | `verified` — how this provider's email assertion is
    /// read for auto-link/JIT. Resolved with [`effective_email_verified`].
    pub email_trust: String,
    /// The deployment's `SIGNET_OUTBOUND_ALLOW_PRIVATE` opt-in, threaded to the
    /// adapters: an intranet upstream IdP is exactly the deployment that opts
    /// in, and a hardcoded `false` at the fetch site makes the flag a no-op
    /// for generic OIDC discovery.
    pub outbound_allow_private: bool,
}

impl ProviderConfig {
    /// Admin forms store blank scopes as `""`; treat that as "use defaults".
    pub fn effective_scopes(&self, default: &str) -> String {
        self.scopes
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(default)
            .to_string()
    }
}

/// Resolves the provider's `jit_mode` against the global JIT toggle.
///
/// `on`/`off` are the administrator's per-provider word over the global
/// setting — the shape of "the corporate tenant may auto-create, the open
/// IdP may not". Unknown values fall through to `inherit`: a CHECK constraint
/// already guards the column, so this branch is belt-and-suspenders.
pub fn effective_jit(jit_mode: &str, global: bool) -> bool {
    match jit_mode {
        "on" => true,
        "off" => false,
        _ => global,
    }
}

/// Resolves how much a provider's email assertion is trusted, given what the
/// adapter reported and whether it returned an address at all.
///
/// - `any`: an address is proof enough (the Feishu stance — no verified flag
///   exists there; the row is pinned to this by migration for old providers).
/// - `verified` / `inherit`: the adapter's own flag stands.
pub fn effective_email_verified(
    email_trust: &str,
    adapter_verified: bool,
    has_email: bool,
) -> bool {
    match email_trust {
        "any" => has_email,
        _ => adapter_verified,
    }
}

type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Provider-specific OAuth2/OIDC behavior.
pub trait UpstreamProvider {
    /// Scope string sent to the provider (empty config → provider default).
    fn scopes(&self, cfg: &ProviderConfig) -> String;

    /// Build the URL the browser is redirected to. `code_challenge` is the
    /// S256 PKCE challenge for this attempt — upstreams that mandate PKCE
    /// (increasingly all of them) refuse the request without it.
    fn authorize_url<'a>(
        &'a self,
        cfg: &'a ProviderConfig,
        redirect_uri: &'a str,
        state: &'a str,
        nonce: &'a str,
        code_challenge: &'a str,
    ) -> BoxFuture<'a, Result<String>>;

    /// Exchange the callback `code` for tokens. `code_verifier` is this
    /// attempt's PKCE verifier, matched to the challenge sent on authorize.
    fn exchange<'a>(
        &'a self,
        cfg: &'a ProviderConfig,
        redirect_uri: &'a str,
        code: &'a str,
        code_verifier: &'a str,
    ) -> BoxFuture<'a, Result<TokenSet>>;

    /// Resolve the signed-in identity from the token set.
    fn profile<'a>(
        &'a self,
        cfg: &'a ProviderConfig,
        tokens: &'a TokenSet,
    ) -> BoxFuture<'a, Result<UpstreamProfile>>;
}

/// Normalized token response subset the adapters rely on.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenSet {
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl TokenSet {
    pub fn require_access(&self) -> Result<&str> {
        self.access_token
            .as_deref()
            .ok_or_else(|| anyhow!("provider response missing access_token"))
    }
}

/// POSTs a form-encoded token request and parses the JSON response.
pub async fn post_token_form(token_url: &str, form: &[(&str, &str)]) -> Result<TokenSet> {
    let resp = crate::outbound::client()
        .post(token_url)
        .form(form)
        .header("Accept", "application/json")
        .send()
        .await?;
    let status = resp.status();
    let body = crate::outbound::read_body_capped(resp).await?;
    if !status.is_success() {
        return Err(anyhow!(
            "token endpoint returned {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    Ok(serde_json::from_slice(&body)?)
}

/// GETs a JSON API endpoint with a bearer token.
pub async fn get_json(url: &str, access_token: &str) -> Result<serde_json::Value> {
    let resp = crate::outbound::client()
        .get(url)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .header("User-Agent", "signet-sso")
        .send()
        .await?;
    let status = resp.status();
    let body = crate::outbound::read_body_capped(resp).await?;
    if !status.is_success() {
        return Err(anyhow!(
            "GET {url} returned {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    Ok(serde_json::from_slice(&body)?)
}

/// GETs a JSON API endpoint with no Authorization header (e.g. WeChat token).
pub async fn get_json_plain(url: &str) -> Result<serde_json::Value> {
    let resp = crate::outbound::client()
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await?;
    let status = resp.status();
    let body = crate::outbound::read_body_capped(resp).await?;
    if !status.is_success() {
        return Err(anyhow!(
            "GET {url} returned {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    Ok(serde_json::from_slice(&body)?)
}
