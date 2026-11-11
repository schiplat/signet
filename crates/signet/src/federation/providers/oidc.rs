use super::{jbool, jstr, oauth2_profile};
use crate::federation::provider::{
    post_token_form, ProviderConfig, TokenSet, UpstreamProfile, UpstreamProvider,
};
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub struct GenericOidc;

/// Discovery documents, cached briefly per issuer.
///
/// One sign-in used to fetch the document three times (authorize, exchange,
/// profile) — three round trips to the upstream IdP, and no guarantee the
/// `token_endpoint` used for the exchange was the one shown by the document
/// that produced the authorize URL. A short TTL keeps the endpoints consistent
/// across the legs while still picking up an upstream change within minutes.
/// Failures are never cached: a transient outage must not pin an error.
static DISCOVERY_CACHE: OnceLock<Mutex<HashMap<String, (Instant, Value)>>> = OnceLock::new();
const DISCOVERY_TTL: Duration = Duration::from_secs(300);

/// Fetches `{issuer}/.well-known/openid-configuration`, or the cached copy.
async fn discovery(issuer: &str, allow_private: bool) -> Result<Value> {
    let key = issuer.trim_end_matches('/').to_string();
    let cache = DISCOVERY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let cached = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&key)
        .and_then(|(at, doc)| (at.elapsed() < DISCOVERY_TTL).then(|| doc.clone()));
    if let Some(doc) = cached {
        return Ok(doc);
    }

    let url = format!("{key}/.well-known/openid-configuration");
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
    let doc: Value = serde_json::from_slice(&body)?;
    cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(key, (Instant::now(), doc.clone()));
    Ok(doc)
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

/// Applies the outbound policy to an endpoint URL read out of a discovery
/// document.
///
/// The document comes from the operator's issuer, but its endpoint fields are
/// *upstream data*, not operator data: an issuer that is compromised — or whose
/// DNS has been re-pointed — can aim `token_endpoint` at an internal address,
/// and the token POST carries the `client_secret`. Every endpoint this adapter
/// hands to the HTTP client therefore passes the same guard the issuer URL did,
/// re-checked at call time (§12: a check made when the provider was saved is
/// worthless at fetch time).
///
/// The authorization endpoint is deliberately *not* guarded here: the browser
/// visits it, so there is no server-side request to protect. The discovery
/// root keeps its shape-only check because it carries no credentials and every
/// server-fetched URL read out of the document is re-checked below anyway.
async fn ensure_endpoint_allowed(url: &str, allow_private: bool) -> Result<()> {
    crate::outbound::ensure_allowed(url, allow_private)
        .await
        .map(|_| ())
        .map_err(|e| anyhow!(e.to_string()))
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
            ensure_endpoint_allowed(&token_endpoint, cfg.outbound_allow_private).await?;
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
            ensure_endpoint_allowed(&userinfo, cfg.outbound_allow_private).await?;
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
