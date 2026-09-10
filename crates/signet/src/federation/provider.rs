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

type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Provider-specific OAuth2/OIDC behavior.
pub trait UpstreamProvider {
    /// Scope string sent to the provider (empty config → provider default).
    fn scopes(&self, cfg: &ProviderConfig) -> String;

    /// Build the URL the browser is redirected to.
    fn authorize_url<'a>(
        &'a self,
        cfg: &'a ProviderConfig,
        redirect_uri: &'a str,
        state: &'a str,
        nonce: &'a str,
    ) -> BoxFuture<'a, Result<String>>;

    /// Exchange the callback `code` for tokens.
    fn exchange<'a>(
        &'a self,
        cfg: &'a ProviderConfig,
        redirect_uri: &'a str,
        code: &'a str,
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
    let client = reqwest::Client::new();
    let resp = client
        .post(token_url)
        .form(form)
        .header("Accept", "application/json")
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow!("token endpoint returned {status}: {body}"));
    }
    Ok(serde_json::from_str(&body)?)
}

/// GETs a JSON API endpoint with a bearer token.
pub async fn get_json(url: &str, access_token: &str) -> Result<serde_json::Value> {
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .header("User-Agent", "signet-sso")
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow!("GET {url} returned {status}: {body}"));
    }
    Ok(serde_json::from_str(&body)?)
}

/// GETs a JSON API endpoint with no Authorization header (e.g. WeChat token).
pub async fn get_json_plain(url: &str) -> Result<serde_json::Value> {
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow!("GET {url} returned {status}: {body}"));
    }
    Ok(serde_json::from_str(&body)?)
}
