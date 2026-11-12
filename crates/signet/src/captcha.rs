//! CAPTCHA on the unauthenticated doors.
//!
//! A brute-force password spray looks exactly like users mistyping: same
//! endpoint, human-shaped traffic, and the lockout counter only starts once
//! an address is targeted. A CAPTCHA adds a cost the attack cannot amortize.
//! Signet integrates the two providers with the same siteverify wire shape —
//! Cloudflare Turnstile and hCaptcha — selected by name; both are POST
//! `secret` + `response` (+ `remoteip`) to a fixed URL and read `success`.
//!
//! Configuration follows the runtime-settings precedence **DB > env** and is
//! managed from the dashboard like the SMTP relay. It is *enabled* only when
//! a provider, a site key (what the browser renders) and a secret (what the
//! server verifies with) are all present; anything less disables the gate so
//! a half-saved settings row cannot lock everyone out. The verify URL is
//! overridable for self-hosted hCaptcha-compatible services and for tests.
//!
//! The outbound POST goes to an operator-configured, provider-named URL —
//! never to anything derived from user input — so the SSRF guards that gate
//! user-supplied webhook URLs do not apply here.

use crate::error::{AppError, AppResult};
use crate::state::AppState;
use serde_json::Value;
use std::collections::HashMap;

/// The provider and the siteverify endpoint it implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Turnstile,
    HCaptcha,
}

impl Provider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Turnstile => "turnstile",
            Provider::HCaptcha => "hcaptcha",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "turnstile" => Some(Provider::Turnstile),
            "hcaptcha" => Some(Provider::HCaptcha),
            _ => None,
        }
    }

    /// The canonical siteverify URL. `SIGNET_CAPTCHA_VERIFY_URL` overrides it
    /// (self-hosted services, tests).
    fn verify_url(self) -> &'static str {
        match self {
            Provider::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            Provider::HCaptcha => "https://api.hcaptcha.com/siteverify",
        }
    }
}

/// The gate as it currently stands: `None` means "no CAPTCHA required".
#[derive(Debug, Clone)]
pub struct Enabled {
    pub provider: Provider,
    /// Rendered by the browser; not a secret.
    pub site_key: String,
    secret: String,
}

/// Resolves the effective CAPTCHA gate: `captcha.*` rows over
/// `SIGNET_CAPTCHA_*`. `None` = disabled.
pub async fn resolve(state: &AppState) -> Option<Enabled> {
    let rows: HashMap<String, String> = match sqlx::query_as::<_, (String, Value)>(
        "SELECT key, value FROM app_settings WHERE key LIKE 'captcha.%'",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows
            .into_iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "could not read CAPTCHA settings; using env");
            HashMap::new()
        }
    };
    let db = |key: &str| {
        rows.get(key)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let env = |key: &str| {
        std::env::var(key)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };

    let provider_name = db("captcha.provider").or_else(|| env("SIGNET_CAPTCHA_PROVIDER"))?;
    let provider = Provider::parse(&provider_name)?;

    let site_key = db("captcha.site_key").or_else(|| env("SIGNET_CAPTCHA_SITE_KEY"))?;

    // The stored secret is ciphertext from the application encryptor; an
    // undecryptable row reads as absent (the gate then stays off — see the
    // module comment on half-configured states).
    let secret = rows
        .get("captcha.secret_key")
        .and_then(|enc| state.encryptor.decrypt(enc))
        .or_else(|| env("SIGNET_CAPTCHA_SECRET_KEY"))?;

    Some(Enabled {
        provider,
        site_key,
        secret,
    })
}

/// Verifies one token with the provider. A transport failure counts as a
/// failure to verify — fail closed: the token might be replayed garbage.
async fn verify(
    client: &reqwest::Client,
    gate: &Enabled,
    token: &str,
    ip: Option<&str>,
) -> Result<(), String> {
    let url = std::env::var("SIGNET_CAPTCHA_VERIFY_URL")
        .ok()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| gate.provider.verify_url().to_string());

    let mut form: Vec<(&str, &str)> = vec![("secret", gate.secret.as_str()), ("response", token)];
    if let Some(ip) = ip {
        form.push(("remoteip", ip));
    }

    let response = client
        .post(&url)
        .form(&form)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("captcha provider unreachable: {e}"))?;

    let body: Value = response
        .json()
        .await
        .map_err(|e| format!("captcha provider response unreadable: {e}"))?;
    if body.get("success").and_then(Value::as_bool) == Some(true) {
        return Ok(());
    }
    // Error codes help the operator debug a misconfigured widget (domain
    // mismatch, expired secret) without logging the token itself.
    let codes = body
        .get("error-codes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    Err(if codes.is_empty() {
        "captcha verification refused".to_string()
    } else {
        format!("captcha verification refused ({codes})")
    })
}

/// The gate a login/reset handler calls: verifies `token` when the gate is
/// enabled, passes through otherwise.
///
/// A missing token and a failed verification give the same response — both are
/// "complete the challenge", and distinguishing them would tell an attacker
/// which part of their request to fix.
pub async fn require(state: &AppState, token: Option<&str>, ip: Option<&str>) -> AppResult<()> {
    let Some(gate) = resolve(state).await else {
        return Ok(());
    };
    let Some(token) = token.map(str::trim).filter(|t| !t.is_empty()) else {
        return Err(AppError::bad_request(
            "complete the CAPTCHA challenge to continue",
        ));
    };
    let client = reqwest::Client::new();
    verify(&client, &gate, token, ip)
        .await
        .map_err(|_| AppError::bad_request("CAPTCHA verification failed; try again"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encryption::Encryptor;

    #[test]
    fn provider_names_parse() {
        assert_eq!(Provider::parse("turnstile"), Some(Provider::Turnstile));
        assert_eq!(Provider::parse("HCaptcha"), Some(Provider::HCaptcha));
        assert_eq!(Provider::parse("bogus"), None);
        assert_eq!(Provider::parse(""), None);
    }

    #[test]
    fn verify_urls_are_provider_constants() {
        // These are the outbound targets; pin them so a refactor cannot
        // silently point the gate somewhere else.
        assert!(Provider::Turnstile
            .verify_url()
            .starts_with("https://challenges.cloudflare.com/"));
        assert!(Provider::HCaptcha
            .verify_url()
            .starts_with("https://api.hcaptcha.com/"));
    }

    #[tokio::test]
    async fn verify_fail_closed_on_transport_error() {
        // An unreachable provider must refuse, not pass: the point of the
        // gate is that a missing verification is a hard stop.
        let gate = Enabled {
            provider: Provider::Turnstile,
            site_key: "site".into(),
            secret: "secret".into(),
        };
        let client = reqwest::Client::new();
        let result = verify(&client, &gate, "some-token", None).await;
        // The default URL points at Cloudflare; in a sandbox without network
        // this fails with a transport error, and with network the token is
        // invalid — either way it must not be Ok.
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_roundtrip_matches_webhook_convention() {
        // The stored secret is `encryptor.encrypt(plaintext)`; resolve must
        // decrypt it. This is the same convention the webhook secrets use.
        let key = [7u8; 32];
        let encryptor = Encryptor::new(&key);
        let enc = encryptor.encrypt("relay-secret");
        assert_eq!(encryptor.decrypt(&enc).as_deref(), Some("relay-secret"));
    }
}
