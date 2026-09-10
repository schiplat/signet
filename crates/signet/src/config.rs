use anyhow::{bail, Context, Result};
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub http_bind: SocketAddr,
    pub issuer: String,
    pub cookie_secure: bool,
    pub jwt_private_key_path: PathBuf,
    pub encryption_key_path: PathBuf,
    pub session_ttl_hours: i64,
    pub auth_code_ttl_secs: i64,
    pub access_token_ttl_secs: i64,
    pub refresh_token_ttl_days: i64,
    pub id_token_ttl_secs: i64,
    pub max_login_attempts: i64,
    pub lockout_minutes: i64,
    pub password_min_length: usize,
    pub password_history_size: i64,
    pub audit_retention_days: i64,
    pub rate_limit_per_minute: usize,
    pub email_from: String,
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    pub public_base_url: Option<String>,
    pub scim_bearer_token: Option<String>,
    pub webauthn_rp_id: String,
    pub webauthn_rp_origin: String,
    /// Fallback when `app_settings.sso.jit_provision` is missing. Prefer the
    /// Dashboard Settings toggle (persisted in DB). When true, SSO with a
    /// verified email that matches no local user creates a `member` (JIT).
    pub sso_jit_provision: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let _ = dotenvy::dotenv();

        let database_url = env::var("SIGNET_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://signet:signet@127.0.0.1:5433/signet".into());
        let http_bind: SocketAddr = env::var("SIGNET_HTTP_BIND")
            .unwrap_or_else(|_| "0.0.0.0:8443".into())
            .parse()
            .context("invalid SIGNET_HTTP_BIND")?;
        let issuer = env::var("SIGNET_ISSUER").unwrap_or_else(|_| "http://localhost:8443".into());
        if issuer.ends_with('/') {
            bail!("SIGNET_ISSUER must not end with '/'");
        }

        let cookie_secure = env::var("SIGNET_COOKIE_SECURE")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"))
            .unwrap_or(false);

        let jwt_private_key_path = env::var("SIGNET_JWT_PRIVATE_KEY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data/jwt_private.pem"));
        let encryption_key_path = env::var("SIGNET_ENCRYPTION_KEY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data/encryption.key"));

        Ok(Self {
            database_url,
            http_bind,
            issuer,
            cookie_secure,
            jwt_private_key_path,
            encryption_key_path,
            session_ttl_hours: 12,
            auth_code_ttl_secs: 300,
            access_token_ttl_secs: 3600,
            refresh_token_ttl_days: 30,
            id_token_ttl_secs: 3600,
            max_login_attempts: env::var("SIGNET_MAX_LOGIN_ATTEMPTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            lockout_minutes: env::var("SIGNET_LOCKOUT_MINUTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),
            password_min_length: env::var("SIGNET_PASSWORD_MIN_LENGTH")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            password_history_size: env::var("SIGNET_PASSWORD_HISTORY_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),
            audit_retention_days: env::var("SIGNET_AUDIT_RETENTION_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(180),
            rate_limit_per_minute: env::var("SIGNET_RATE_LIMIT_PER_MINUTE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            email_from: env::var("SIGNET_EMAIL_FROM").unwrap_or_else(|_| "signet@localhost".into()),
            smtp_host: env::var("SIGNET_SMTP_HOST").ok(),
            smtp_port: env::var("SIGNET_SMTP_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(587),
            public_base_url: env::var("SIGNET_PUBLIC_BASE_URL").ok(),
            scim_bearer_token: env::var("SIGNET_SCIM_BEARER_TOKEN").ok(),
            webauthn_rp_id: env::var("SIGNET_WEBAUTHN_RP_ID")
                .unwrap_or_else(|_| "localhost".into()),
            webauthn_rp_origin: env::var("SIGNET_WEBAUTHN_RP_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:8443".into()),
            // Default on: Feishu/Google/OIDC OA flows can first-login without
            // an admin pre-creating the user (requires verified email).
            sso_jit_provision: env::var("SIGNET_SSO_JIT_PROVISION")
                .map(|v| !matches!(v.as_str(), "0" | "false" | "FALSE" | "no"))
                .unwrap_or(true),
        })
    }
}
