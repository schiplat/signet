use tracing::info;

/// Minimal outbound mailer abstraction.
///
/// Production delivery should be wired to a real SMTP provider (e.g. via
/// `SIGNET_SMTP_HOST`). Until then, outbound messages are emitted to the log
/// stream so flows (password reset, new-device alerts) are fully testable.
///
/// `log_body` exists because bodies can carry one-time credentials (the
/// password-reset link): printing them belongs behind the deployment's
/// `SIGNET_DEV_LOG_LINKS` opt-in, not in every log stream by default.
pub async fn send(to: &str, subject: &str, body: &str, log_body: bool) {
    info!(to = %to, subject = %subject, "outbound email (log mailer)");
    if log_body {
        info!("  body:\n{body}");
    }
}
