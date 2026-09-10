use super::{jbool, jstr, oauth2_profile, ready_url};
use crate::federation::provider::{
    get_json, post_token_form, ProviderConfig, TokenSet, UpstreamProfile, UpstreamProvider,
};
use anyhow::{anyhow, Result};

pub struct GitHub;

impl GitHub {
    const AUTHORIZE: &'static str = "https://github.com/login/oauth/authorize";
    const TOKEN: &'static str = "https://github.com/login/oauth/access_token";
    const USER: &'static str = "https://api.github.com/user";
    const EMAILS: &'static str = "https://api.github.com/user/emails";
}

impl UpstreamProvider for GitHub {
    fn scopes(&self, cfg: &ProviderConfig) -> String {
        cfg.effective_scopes("read:user user:email")
    }

    fn authorize_url<'a>(
        &'a self,
        cfg: &'a ProviderConfig,
        redirect_uri: &'a str,
        state: &'a str,
        _nonce: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
        let query = format!(
            "client_id={}&redirect_uri={}&response_type=code&state={}&scope={}",
            urlencoding::encode(&cfg.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(&self.scopes(cfg)),
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
            let user = oauth2_profile(cfg, tokens, Self::USER).await?;
            // GitHub returns `id` as a JSON number — coerce via jstr().
            let subject = jstr(&user, "id").ok_or_else(|| anyhow!("github profile missing id"))?;

            // GitHub does not surface emails on /user; ask /user/emails and
            // prefer the primary+verified address. Without a verified email
            // the auto-link path stays disabled (by design).
            let access = tokens.require_access()?;
            let emails = get_json(Self::EMAILS, access).await.unwrap_or_default();
            let email = emails
                .as_array()
                .and_then(|list| {
                    list.iter()
                        .find(|e| jbool(e, "primary") && jbool(e, "verified"))
                        .or_else(|| list.iter().find(|e| jbool(e, "verified")))
                })
                .and_then(|e| jstr(e, "email"));

            let verified_email = email.clone();
            Ok(UpstreamProfile {
                subject,
                email,
                email_verified: verified_email.is_some(),
                display_name: jstr(&user, "name").or_else(|| jstr(&user, "login")),
                raw: user,
            })
        })
    }
}
