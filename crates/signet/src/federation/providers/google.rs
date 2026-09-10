use super::{jbool, jstr, oauth2_profile, ready_url};
use crate::federation::provider::{
    post_token_form, ProviderConfig, TokenSet, UpstreamProfile, UpstreamProvider,
};
use anyhow::{anyhow, Result};

pub struct Google;

impl Google {
    const AUTHORIZE: &'static str = "https://accounts.google.com/o/oauth2/v2/auth";
    const TOKEN: &'static str = "https://oauth2.googleapis.com/token";
    const USERINFO: &'static str = "https://openidconnect.googleapis.com/v1/userinfo";
}

impl UpstreamProvider for Google {
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
        let scope = self.scopes(cfg);
        let query = format!(
            "client_id={}&redirect_uri={}&response_type=code&state={}&scope={}&nonce={}&access_type=online&include_granted_scopes=true",
            urlencoding::encode(&cfg.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(&scope),
            urlencoding::encode(nonce),
        );
        ready_url(format!("{}?{}", Self::AUTHORIZE, query))
    }

    fn exchange<'a>(
        &'a self,
        cfg: &'a ProviderConfig,
        redirect_uri: &'a str,
        code: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<TokenSet>> + Send + 'a>> {
        Box::pin(async move {
            post_token_form(
                Self::TOKEN,
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
            let info = oauth2_profile(cfg, tokens, Self::USERINFO).await?;
            Ok(UpstreamProfile {
                subject: jstr(&info, "sub").ok_or_else(|| anyhow!("google profile missing sub"))?,
                email: jstr(&info, "email"),
                email_verified: jbool(&info, "email_verified"),
                display_name: jstr(&info, "name"),
                raw: info,
            })
        })
    }
}
