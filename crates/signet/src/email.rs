//! Outbound email.
//!
//! Until SMTP is configured, the log is the only "delivery" there is. That is a
//! development convenience, not a mailer: a password-reset link that lands in a
//! log stream is a working takeover for anyone who can read the logs, and a
//! caller that answers "ok" while nothing was delivered strands the user.
//! [`configured`] therefore lets the reset flow refuse honestly (503) instead
//! of pretending, and [`send`] fails when the transport fails.

use crate::state::AppState;
use anyhow::{anyhow, Result};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// True when a real transport is configured (`SIGNET_SMTP_HOST`).
pub fn configured(state: &AppState) -> bool {
    state
        .config
        .smtp_host
        .as_deref()
        .is_some_and(|h| !h.trim().is_empty())
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
    if !configured(state) {
        tracing::info!(to = %to, subject = %subject, "outbound email (log mailer: SMTP not configured)");
        if log_body {
            tracing::info!("  body:\n{body}");
        }
        return Ok(());
    }

    let from: Mailbox = state
        .config
        .email_from
        .parse()
        .map_err(|e| anyhow!("SIGNET_EMAIL_FROM is not a mailbox: {e}"))?;
    let to: Mailbox = to
        .parse()
        .map_err(|e| anyhow!("recipient is not a mailbox: {e}"))?;
    let message = Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .body(body.to_string())
        .map_err(|e| anyhow!("build message: {e}"))?;

    let transport = transport(state)?;
    transport
        .send(message)
        .await
        .map_err(|e| anyhow!("smtp send failed: {e}"))?;
    Ok(())
}

fn transport(state: &AppState) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
    let host = state
        .config
        .smtp_host
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| anyhow!("SIGNET_SMTP_HOST is not set"))?;
    let port = state.config.smtp_port;

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

    let builder = match (
        state.config.smtp_username.as_deref(),
        state.config.smtp_password.as_deref(),
    ) {
        (Some(user), Some(pass)) if !user.trim().is_empty() => {
            builder.credentials(Credentials::new(user.to_string(), pass.to_string()))
        }
        _ => builder,
    };
    Ok(builder.build())
}
