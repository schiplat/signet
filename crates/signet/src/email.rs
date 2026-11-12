//! Outbound email.
//!
//! Until SMTP is configured, the log is the only "delivery" there is. That is a
//! development convenience, not a mailer: a password-reset link that lands in a
//! log stream is a working takeover for anyone who can read the logs, and a
//! caller that answers "ok" while nothing was delivered strands the user.
//! [`configured`] therefore lets the reset flow refuse honestly (503) instead
//! of pretending, and [`send`] fails when the transport fails.
//!
//! The configuration follows the runtime-settings precedence **DB > env**, so
//! an operator can point the instance at a mail relay from the dashboard
//! without touching `.env`: `smtp.*` rows in `app_settings` (the password
//! stored encrypted with the application key) override `SIGNET_SMTP_*`. The
//! relay is resolved per send — mail volume is bounded by resets and change
//! confirmations, and a settings change then applies to the very next message
//! with no cache to invalidate.

use crate::state::AppState;
use anyhow::{anyhow, Result};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::Value;
use std::collections::HashMap;

/// The effective relay, resolved from DB rows over the environment.
#[derive(Debug, Clone)]
pub struct EffectiveSmtp {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
}

impl EffectiveSmtp {
    /// Never the password — this shape goes to the admin API and audit log.
    pub fn redacted(&self) -> Value {
        serde_json::json!({
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "from": self.from,
        })
    }
}

/// Resolves the effective SMTP relay: `app_settings` `smtp.*` rows over
/// `SIGNET_SMTP_*`, `None` when no host is configured anywhere.
///
/// A database error falls back to the environment (with a warning) — email
/// delivery must not take its settings availability from a transient DB
/// hiccup any more than the rest of the process does.
pub async fn resolve(state: &AppState) -> Option<EffectiveSmtp> {
    let rows: HashMap<String, String> = match sqlx::query_as::<_, (String, Value)>(
        "SELECT key, value FROM app_settings WHERE key LIKE 'smtp.%'",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows
            .into_iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "could not read SMTP settings; using env");
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

    let host = db("smtp.host").or_else(|| env("SIGNET_SMTP_HOST"))?;

    let port = db("smtp.port")
        .and_then(|p| p.parse::<u16>().ok())
        .or_else(|| env("SIGNET_SMTP_PORT").and_then(|p| p.parse::<u16>().ok()))
        .unwrap_or(587);

    // The stored password is ciphertext from the application encryptor, same
    // as webhook secrets and TOTP secrets; a row we cannot decrypt reads as
    // absent and the environment (if any) answers instead.
    let password = rows
        .get("smtp.password")
        .and_then(|enc| state.encryptor.decrypt(enc))
        .or_else(|| env("SIGNET_SMTP_PASSWORD"));

    Some(EffectiveSmtp {
        host,
        port,
        username: db("smtp.username").or_else(|| env("SIGNET_SMTP_USERNAME")),
        password,
        from: db("smtp.from")
            .or_else(|| Some(state.config.email_from.clone()))
            .unwrap_or_else(|| "signet@localhost".to_string()),
    })
}

/// True when a real transport is configured (DB `smtp.host` or env).
pub async fn configured(state: &AppState) -> bool {
    resolve(state).await.is_some()
}

/// Sends one plain-text message.
///
/// `log_body` is the dev opt-in that also writes the body to the log stream
/// (`SIGNET_DEV_LOG_LINKS`): bodies can carry one-time credentials. It only
/// applies to the log fallback; a delivered message is never logged.
pub async fn send(
    state: &AppState,
    to: &str,
    subject: &str,
    body: &str,
    log_body: bool,
) -> Result<()> {
    let Some(smtp) = resolve(state).await else {
        tracing::info!(to = %to, subject = %subject, "outbound email (log mailer: SMTP not configured)");
        if log_body {
            tracing::info!("  body:\n{body}");
        }
        return Ok(());
    };

    let from: Mailbox = smtp
        .from
        .parse()
        .map_err(|e| anyhow!("sender is not a mailbox ({}): {e}", smtp.from))?;
    let to: Mailbox = to
        .parse()
        .map_err(|e| anyhow!("recipient is not a mailbox: {e}"))?;
    let message = Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .body(body.to_string())
        .map_err(|e| anyhow!("build message: {e}"))?;

    let transport = transport(&smtp)?;
    transport
        .send(message)
        .await
        .map_err(|e| anyhow!("smtp send failed: {e}"))?;
    Ok(())
}

fn transport(smtp: &EffectiveSmtp) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
    let host = smtp.host.trim();
    let port = smtp.port;

    // 465 is implicit TLS; everything else (587, 25) negotiates STARTTLS. Both
    // paths require a certificate the system trusts — there is no
    // "accept anything" switch, matching the LDAPS stance.
    let builder = if port == 465 {
        let tls = TlsParameters::new(host.to_string())
            .map_err(|e| anyhow!("smtp TLS parameters: {e}"))?;
        AsyncSmtpTransport::<Tokio1Executor>::relay(host)
            .map_err(|e| anyhow!("smtp transport: {e}"))?
            .tls(Tls::Wrapper(tls))
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .map_err(|e| anyhow!("smtp transport: {e}"))?
    }
    .port(port);

    let builder = match (&smtp.username, &smtp.password) {
        (Some(user), Some(pass)) if !user.trim().is_empty() => {
            builder.credentials(Credentials::new(user.to_string(), pass.to_string()))
        }
        _ => builder,
    };
    Ok(builder.build())
}
