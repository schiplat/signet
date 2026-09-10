//! Contract tests for the federation connector framework.
//!
//! These exercise the pure, URL-building surface of the provider adapters:
//! scopes defaults, authorize URL shape/encoding, and endpoint constants.
//! Network-bound token/profile paths are covered by integration tests with
//! mocked upstreams (see P3 todo).

use signet::federation::provider::{ProviderConfig, UpstreamProvider};
use signet::federation::providers::{Feishu, GenericOidc, GitHub, Google, WeChat};

fn cfg(provider_type: &str, scopes: Option<&str>, issuer: Option<&str>) -> ProviderConfig {
    ProviderConfig {
        code: "acme".into(),
        provider_type: provider_type.into(),
        display_name: "Acme".into(),
        client_id: "cid&=x".into(),
        client_secret: "sec".into(),
        issuer_url: issuer.map(|s| s.into()),
        scopes: scopes.map(|s| s.into()),
    }
}

fn block_on_url<F>(fut: F) -> anyhow::Result<String>
where
    F: std::future::Future<Output = anyhow::Result<String>>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
}

#[test]
fn github_default_scopes_and_url() {
    let c = cfg("github", None, None);
    let url = block_on_url(GitHub.authorize_url(
        &c,
        "https://id.example.com/api/v1/auth/sso/acme/callback",
        "st at/e",
        "",
    ))
    .unwrap();
    assert!(url.starts_with("https://github.com/login/oauth/authorize?"));
    assert!(url.contains("client_id=cid%26%3Dx"));
    assert!(url.contains("scope=read%3Auser%20user%3Aemail"));
    assert!(url.contains("state=st%20at%2Fe"));
}

#[test]
fn empty_scopes_string_uses_defaults() {
    // Admin forms persist blank scopes as "" — must not send empty scope=.
    let c = cfg("github", Some(""), None);
    let url = block_on_url(GitHub.authorize_url(&c, "https://x/cb", "s", "")).unwrap();
    assert!(url.contains("scope=read%3Auser%20user%3Aemail"));
    assert_eq!(
        c.effective_scopes("read:user user:email"),
        "read:user user:email"
    );
}

#[test]
fn google_includes_nonce_and_scope() {
    let c = cfg("google", None, None);
    let url = block_on_url(Google.authorize_url(&c, "https://id.example.com/cb", "s2", "nonce-1"))
        .unwrap();
    assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
    assert!(url.contains("nonce=nonce-1"));
    assert!(url.contains("scope=openid%20email%20profile"));
}

#[test]
fn feishu_uses_app_id_param() {
    let c = cfg("feishu", None, None);
    let url =
        block_on_url(Feishu.authorize_url(&c, "https://id.example.com/cb", "s3", "")).unwrap();
    assert!(url.starts_with("https://accounts.feishu.cn/open-apis/authen/v1/authorize?"));
    assert!(url.contains("app_id=cid%26%3Dx"));
    assert!(!url.contains("scope=")); // feishu authorize does not take scope
}

#[test]
fn wechat_uses_appid_snsapi_login_and_fragment() {
    let c = cfg("wechat", None, None);
    let url =
        block_on_url(WeChat.authorize_url(&c, "https://id.example.com/cb", "s4", "")).unwrap();
    assert!(url.starts_with("https://open.weixin.qq.com/connect/qrconnect?"));
    assert!(url.contains("appid=cid%26%3Dx"));
    assert!(url.contains("scope=snsapi_login"));
    assert!(url.ends_with("#wechat_redirect"));
}

#[test]
fn generic_oidc_requires_issuer() {
    let c = cfg("oidc", None, None);
    assert!(
        block_on_url(GenericOidc.authorize_url(&c, "https://id.example.com/cb", "s5", "n5"))
            .is_err()
    );
}

#[test]
fn generic_oidc_direct_authorize_url_encodes_params() {
    // When issuer_url already looks like an authorize endpoint, skip discovery
    // (offline-safe contract test).
    let c = cfg(
        "oidc",
        Some("openid email"),
        Some("https://sso.acme.com/authorize"),
    );
    let url = block_on_url(GenericOidc.authorize_url(&c, "https://id.example.com/cb", "s6", "n6"))
        .unwrap();
    assert!(url.starts_with("https://sso.acme.com/authorize?"));
    assert!(url.contains("nonce=n6"));
    assert!(url.contains("scope=openid%20email"));
}

#[test]
fn custom_scopes_override_defaults() {
    let c = cfg("github", Some("user:email"), None);
    let url = block_on_url(GitHub.authorize_url(&c, "https://x/cb", "s", "")).unwrap();
    assert!(url.contains("scope=user%3Aemail"));
}
