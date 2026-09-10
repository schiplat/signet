//! Concrete provider adapters.
//!
//! One file per upstream vendor. Each adapter maps onto [`UpstreamProvider`].
//! Endpoint URLs are fixed (GitHub/Google/Feishu/WeChat) or discovered
//! (generic OIDC via `{issuer}/.well-known/openid-configuration`).

mod feishu;
mod github;
mod google;
mod oidc;
mod wechat;

pub use feishu::Feishu;
pub use github::GitHub;
pub use google::Google;
pub use oidc::GenericOidc;
pub use wechat::WeChat;

use super::provider::{get_json, ProviderConfig, TokenSet};
use anyhow::Result;
use serde_json::{Map, Value};

fn jstr(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn jstr_map(v: &Map<String, Value>, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn jbool(v: &Value, key: &str) -> bool {
    v.get(key).and_then(|x| x.as_bool()).unwrap_or(false)
}

fn ready_url(
    url: String,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send>> {
    Box::pin(async move { Ok(url) })
}

async fn oauth2_profile(cfg: &ProviderConfig, tokens: &TokenSet, user_url: &str) -> Result<Value> {
    let _ = cfg;
    let access = tokens.require_access()?;
    get_json(user_url, access).await
}
