use super::{jbool, jstr, oauth2_profile};
use crate::federation::provider::{
    post_token_form, ProviderConfig, TokenSet, UpstreamProfile, UpstreamProvider,
};
use anyhow::{anyhow, Result};
use serde_json::Value;

pub struct GenericOidc;

/// Fetches `{issuer}/.well-known/openid-configuration`.
async fn discovery(issuer: &str) -> Result<Value> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow!("discovery {url} returned {status}: {body}"));
    }
    Ok(serde_json::from_str(&body)?)
}

/// Resolve the authorization endpoint: if `issuer_url` already looks like an
/// authorize path (ends with `/authorize` or `/auth`), use it directly so
/// offline tests / advanced overrides work; otherwise run OIDC discovery.
async fn authorization_endpoint(issuer: &str) -> Result<String> {
    let trimmed = issuer.trim_end_matches('/');
    if trimmed.ends_with("/authorize") || trimmed.ends_with("/auth") {
        return Ok(trimmed.to_string());
    }
    let doc = discovery(trimmed).await?;
    jstr(&doc, "authorization_endpoint")
        .ok_or_else(|| anyhow!("discovery missing authorization_endpoint"))
}

impl UpstreamProvider for GenericOidc {
    fn scopes(&self, cfg: &ProviderConfig) -> String {
        cfg.effective_scopes("openid email profile")
    }

    fn authorize_url<'a>(
        &'a self,
        cfg: &'a ProviderConfig,
        redirect_uri: &'a str,
        state: &'a str,
        nonce: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
        Box::pin(async move {
            let issuer = cfg
                .issuer_url
                .as_deref()
                .ok_or_else(|| anyhow!("oidc provider requires issuer_url"))?;
            let auth = authorization_endpoint(issuer).await?;
            let query = format!(
                "client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&nonce={}",
                urlencoding::encode(&cfg.client_id),
                urlencoding::encode(redirect_uri),
                urlencoding::encode(&self.scopes(cfg)),
                urlencoding::encode(state),
                urlencoding::encode(nonce),
            );
            Ok(format!("{auth}?{query}"))
        })
    }

    fn exchange<'a>(
        &'a self,
        cfg: &'a ProviderConfig,
        redirect_uri: &'a str,
        code: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<TokenSet>> + Send + 'a>> {
        Box::pin(async move {
            let issuer = cfg
                .issuer_url
                .as_deref()
                .ok_or_else(|| anyhow!("oidc provider requires issuer_url"))?;
            // Discovery root: if admin pasted a full authorize URL, strip the
            // path back to the issuer for .well-known lookup.
            let discovery_root = issuer
                .trim_end_matches('/')
                .trim_end_matches("/authorize")
                .trim_end_matches("/auth");
            let doc = discovery(discovery_root).await?;
            let token_endpoint = jstr(&doc, "token_endpoint")
                .ok_or_else(|| anyhow!("discovery missing token_endpoint"))?;
            post_token_form(
                &token_endpoint,
                &[
                    ("client_id", &cfg.client_id),
                    ("client_secret", &cfg.client_secret),
                    ("code", code),
                    ("redirect_uri", redirect_uri),
                    ("grant_type", "authorization_code"),
                ],
            )
            .await
        })
    }

    fn profile<'a>(
        &'a self,
        cfg: &'a ProviderConfig,
        tokens: &'a TokenSet,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<UpstreamProfile>> + Send + 'a>>
    {
        Box::pin(async move {
            let issuer = cfg
                .issuer_url
                .as_deref()
                .ok_or_else(|| anyhow!("oidc provider requires issuer_url"))?;
            let discovery_root = issuer
                .trim_end_matches('/')
                .trim_end_matches("/authorize")
                .trim_end_matches("/auth");
            let doc = discovery(discovery_root).await?;
            let userinfo = jstr(&doc, "userinfo_endpoint")
                .ok_or_else(|| anyhow!("discovery missing userinfo_endpoint"))?;
            let info = oauth2_profile(cfg, tokens, &userinfo).await?;
            Ok(UpstreamProfile {
                subject: jstr(&info, "sub").ok_or_else(|| anyhow!("oidc profile missing sub"))?,
                email: jstr(&info, "email"),
                email_verified: jbool(&info, "email_verified"),
                display_name: jstr(&info, "name"),
                raw: info,
            })
        })
    }
}
