use super::{jbool, jstr, oauth2_profile};
use crate::federation::provider::{
    post_token_form, ProviderConfig, TokenSet, UpstreamProfile, UpstreamProvider,
};
use anyhow::{anyhow, Result};
use serde_json::Value;

pub struct GenericOidc;

/// Fetches `{issuer}/.well-known/openid-configuration`.
async fn discovery(issuer: &str, allow_private: bool) -> Result<Value> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let client = crate::outbound::client();
    // `issuer` is operator-supplied, so reject anything that is not a plain
    // http(s) URL before the call; whether literal private addresses are
    // admitted is the deployment's SIGNET_OUTBOUND_ALLOW_PRIVATE decision,
    // threaded through the provider config (internal IdPs are the point).
    crate::outbound::validate_shape(&url, allow_private).map_err(|e| anyhow!(e.to_string()))?;
    let resp = client.get(&url).send().await?;
    let status = resp.status();
    let body = crate::outbound::read_body_capped(resp).await?;
    if !status.is_success() {
        return Err(anyhow!(
            "discovery {url} returned {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    Ok(serde_json::from_slice(&body)?)
}

/// Resolve the authorization endpoint: if `issuer_url` already looks like an
/// authorize path (ends with `/authorize` or `/auth`), use it directly so
/// offline tests / advanced overrides work; otherwise run OIDC discovery.
async fn authorization_endpoint(issuer: &str, allow_private: bool) -> Result<String> {
    let trimmed = issuer.trim_end_matches('/');
    if trimmed.ends_with("/authorize") || trimmed.ends_with("/auth") {
        return Ok(trimmed.to_string());
    }
    let doc = discovery(trimmed, allow_private).await?;
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
        _nonce: &'a str,
        code_challenge: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
        Box::pin(async move {
            let issuer = cfg
                .issuer_url
                .as_deref()
                .ok_or_else(|| anyhow!("oidc provider requires issuer_url"))?;
            let auth = authorization_endpoint(issuer, cfg.outbound_allow_private).await?;
            // No `nonce`: identity is resolved from userinfo over the
            // server-side token exchange, never from the id_token a nonce
            // would protect — sending an unverified one would only suggest
            // protection that is not there. PKCE S256, by contrast, is sent
            // for real and verified on exchange: modern upstreams require it.
            let query = format!(
                "client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
                urlencoding::encode(&cfg.client_id),
                urlencoding::encode(redirect_uri),
                urlencoding::encode(&self.scopes(cfg)),
                urlencoding::encode(state),
                urlencoding::encode(code_challenge),
            );
            Ok(format!("{auth}?{query}"))
        })
    }

    fn exchange<'a>(
        &'a self,
        cfg: &'a ProviderConfig,
        redirect_uri: &'a str,
        code: &'a str,
        code_verifier: &'a str,
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
            let doc = discovery(discovery_root, cfg.outbound_allow_private).await?;
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
                    ("code_verifier", code_verifier),
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
            let doc = discovery(discovery_root, cfg.outbound_allow_private).await?;
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
