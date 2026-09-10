use super::{jstr, ready_url};
use crate::federation::provider::{ProviderConfig, TokenSet, UpstreamProfile, UpstreamProvider};
use anyhow::{anyhow, Result};
use serde_json::Value;

pub struct Feishu;

impl Feishu {
    const AUTHORIZE: &'static str = "https://accounts.feishu.cn/open-apis/authen/v1/authorize";
    const APP_TOKEN: &'static str =
        "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal";
    const USER_TOKEN: &'static str = "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token";
    const USERINFO: &'static str = "https://open.feishu.cn/open-apis/authen/v1/user_info";
}

impl UpstreamProvider for Feishu {
    fn scopes(&self, cfg: &ProviderConfig) -> String {
        // App console must grant these; Feishu authorize URL does not send scope=.
        // email → contact:user.email:readonly; enterprise_email → contact:user.employee:readonly.
        cfg.effective_scopes(
            "contact:user.base:readonly contact:user.email:readonly contact:user.employee:readonly",
        )
    }

    fn authorize_url<'a>(
        &'a self,
        cfg: &'a ProviderConfig,
        redirect_uri: &'a str,
        state: &'a str,
        _nonce: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
        // Feishu still accepts `app_id` (App ID); `client_id` is the newer alias.
        let query = format!(
            "app_id={}&redirect_uri={}&response_type=code&state={}",
            urlencoding::encode(&cfg.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
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
            let _ = redirect_uri;
            // Feishu needs an app_access_token before exchanging the code.
            let client = reqwest::Client::new();
            let app: Value = client
                .post(Self::APP_TOKEN)
                .json(&serde_json::json!({
                    "app_id": cfg.client_id,
                    "app_secret": cfg.client_secret,
                }))
                .send()
                .await?
                .json()
                .await?;
            let app_access = app
                .pointer("/app_access_token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("feishu app_access_token missing"))?
                .to_string();

            // Prefer the OIDC token endpoint (current Feishu docs); fall back
            // shape is still `{ data: { access_token } }`.
            let resp: Value = client
                .post(Self::USER_TOKEN)
                .header("Authorization", format!("Bearer {app_access}"))
                .json(&serde_json::json!({
                    "grant_type": "authorization_code",
                    "code": code,
                }))
                .send()
                .await?
                .json()
                .await?;
            let access = resp
                .pointer("/data/access_token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("feishu access_token missing"))?
                .to_string();

            Ok(TokenSet {
                access_token: Some(access),
                id_token: None,
                extra: resp.as_object().cloned().unwrap_or_default(),
            })
        })
    }

    fn profile<'a>(
        &'a self,
        _cfg: &'a ProviderConfig,
        tokens: &'a TokenSet,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<UpstreamProfile>> + Send + 'a>>
    {
        Box::pin(async move {
            let access = tokens.require_access()?;
            let client = reqwest::Client::new();
            let resp: Value = client
                .get(Self::USERINFO)
                .header("Authorization", format!("Bearer {access}"))
                .send()
                .await?
                .json()
                .await?;
            let data = resp
                .get("data")
                .cloned()
                .ok_or_else(|| anyhow!("feishu userinfo missing data"))?;

            Ok(UpstreamProfile {
                subject: jstr(&data, "open_id")
                    .or_else(|| jstr(&data, "user_id"))
                    .or_else(|| jstr(&data, "union_id"))
                    .ok_or_else(|| anyhow!("feishu profile missing open_id"))?,
                email: jstr(&data, "email").or_else(|| jstr(&data, "enterprise_email")),
                // Feishu does not expose a separate verified flag; treat a
                // returned email as verified for auto-link purposes.
                email_verified: jstr(&data, "email")
                    .or_else(|| jstr(&data, "enterprise_email"))
                    .is_some(),
                display_name: jstr(&data, "name"),
                raw: data,
            })
        })
    }
}
