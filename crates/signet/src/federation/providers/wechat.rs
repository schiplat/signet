use super::{jstr, jstr_map, ready_url};
use crate::federation::provider::{
    get_json_plain, ProviderConfig, TokenSet, UpstreamProfile, UpstreamProvider,
};
use anyhow::{anyhow, Result};

pub struct WeChat;

impl WeChat {
    const AUTHORIZE: &'static str = "https://open.weixin.qq.com/connect/qrconnect";
    const TOKEN: &'static str = "https://api.weixin.qq.com/sns/oauth2/access_token";
}

impl UpstreamProvider for WeChat {
    fn scopes(&self, cfg: &ProviderConfig) -> String {
        cfg.effective_scopes("snsapi_login")
    }

    fn authorize_url<'a>(
        &'a self,
        cfg: &'a ProviderConfig,
        redirect_uri: &'a str,
        state: &'a str,
        _nonce: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>> {
        // WeChat website QR login requires the `#wechat_redirect` fragment.
        let query = format!(
            "appid={}&redirect_uri={}&response_type=code&scope={}&state={}#wechat_redirect",
            urlencoding::encode(&cfg.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(&self.scopes(cfg)),
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
            let url = format!(
                "{}?appid={}&secret={}&code={}&grant_type=authorization_code",
                Self::TOKEN,
                urlencoding::encode(&cfg.client_id),
                urlencoding::encode(&cfg.client_secret),
                urlencoding::encode(code),
            );
            // WeChat token endpoint rejects Authorization headers — plain GET.
            let tokens = get_json_plain(&url).await?;
            if let Some(errcode) = tokens.get("errcode").and_then(|v| v.as_i64()) {
                if errcode != 0 {
                    return Err(anyhow!(
                        "wechat token error {}: {}",
                        errcode,
                        jstr(&tokens, "errmsg").unwrap_or_default()
                    ));
                }
            }
            Ok(TokenSet {
                access_token: jstr(&tokens, "access_token"),
                id_token: None,
                extra: tokens.as_object().cloned().unwrap_or_default(),
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
            // unionid is the stable cross-app id; openid alone is per-app.
            // WeChat Open Platform often returns both on the token response;
            // no separate userinfo call is required for subject binding.
            let extra = &tokens.extra;
            let subject = jstr_map(extra, "unionid")
                .or_else(|| jstr_map(extra, "openid"))
                .ok_or_else(|| anyhow!("wechat profile missing unionid/openid"))?;
            Ok(UpstreamProfile {
                subject,
                email: None,
                email_verified: false,
                display_name: jstr_map(extra, "nickname"),
                raw: serde_json::to_value(extra.clone())?,
            })
        })
    }
}
