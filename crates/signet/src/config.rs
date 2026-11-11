use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    /// Connection pool ceiling. Not a dashboard setting: it is a capacity
    /// decision tied to the database server, not an operational policy, and a
    /// value too small for the process's own query fan-out is a deployment
    /// error rather than something to tune live.
    pub db_max_connections: u32,
    pub http_bind: SocketAddr,
    pub issuer: String,
    pub cookie_secure: bool,
    /// Deployment opt-in letting outbound HTTP reach private/loopback/link-local
    /// addresses, for webhook receivers that live on a trusted intranet. Off by
    /// default: the server would otherwise be an SSRF proxy into its own network.
    pub outbound_allow_private: bool,
    pub jwt_private_key_path: PathBuf,
    /// Retired signing keys (public PEMs written by `signet keys rotate`).
    /// Loaded at boot so tokens signed before a rotation keep verifying until
    /// they expire. Missing directory = never rotated, which is normal.
    pub jwt_retired_key_dir: PathBuf,
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
    /// SMTP AUTH credentials. Optional: a relay that trusts this host by
    /// network policy needs none (`SIGNET_SMTP_USERNAME`/`SIGNET_SMTP_PASSWORD`).
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub public_base_url: Option<String>,
    pub scim_bearer_token: Option<String>,
    pub webauthn_rp_id: String,
    pub webauthn_rp_origin: String,
    /// Fallback when `app_settings.sso.jit_provision` is missing. Prefer the
    /// Dashboard Settings toggle (persisted in DB). When true, SSO with a
    /// verified email that matches no local user creates a `member` (JIT).
    pub sso_jit_provision: bool,
    /// Default for the sign-in and provisioning allowlist, used when
    /// `app_settings.auth.allowed_email_domains` is absent. Empty means no
    /// restriction; see [`crate::admission`].
    pub allowed_email_domains: Vec<String>,
    /// Where the metrics listener binds (`SIGNET_METRICS_BIND`).
    ///
    /// Defaults to loopback: the counters are reconnaissance for anyone who can
    /// reach them. Set it to `0.0.0.0:9464` (or an internal interface) when the
    /// scraper runs on another host, or to `off` to disable the listener.
    pub metrics_bind: Option<SocketAddr>,
    /// Reverse proxies allowed to assert the client IP via `X-Forwarded-For`.
    /// Empty (the default) trusts nobody: header-derived IPs are ignored and
    /// the peer address is used, so a spoofed header cannot dodge client IP
    /// allowlists, rate limits, or audit trails.
    pub trusted_proxies: Vec<IpNet>,
    /// Dev-only opt-in (`SIGNET_DEV_LOG_LINKS`) that lets one-time credentials
    /// reach the log stream: the password-reset link (a live 30-minute token)
    /// and email bodies that carry it. Off by default — log aggregation makes
    /// every log line a credential store — and never needed in production.
    pub dev_log_links: bool,
}

impl Config {
    /// The externally reachable base URL for absolute links handed to a browser
    /// or to an upstream IdP: the SSO callback URL, password-reset links, and
    /// the SCIM base URL shown to IdPs.
    ///
    /// Prefers `SIGNET_PUBLIC_BASE_URL`, falling back to the issuer for
    /// single-host deployments. Trailing slashes are trimmed because callers
    /// append a leading-slash path, and because the issuer is the only one of
    /// the two that [`Config::from_env`] rejects a trailing slash on.
    pub fn public_base(&self) -> &str {
        self.public_base_url
            .as_deref()
            .unwrap_or(&self.issuer)
            .trim_end_matches('/')
    }

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

        // An https issuer means browsers only ever reach the service over TLS;
        // marking the session cookies Secure there is not something an operator
        // should have to remember (and localhost dev keeps its http default).
        let cookie_secure = env::var("SIGNET_COOKIE_SECURE")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"))
            .unwrap_or(false)
            || issuer.starts_with("https://");

        let trusted_proxies = match env::var("SIGNET_TRUSTED_PROXIES") {
            Err(_) => Vec::new(),
            Ok(raw) => parse_trusted_proxies(&raw)?,
        };
        // The extractors read the list from a process global, because they are
        // free functions without state access on hot paths.
        crate::http::extract::init_trusted_proxies(trusted_proxies.clone());

        let outbound_allow_private = env::var("SIGNET_OUTBOUND_ALLOW_PRIVATE")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"))
            .unwrap_or(false);

        let jwt_private_key_path = env::var("SIGNET_JWT_PRIVATE_KEY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data/jwt_private.pem"));
        let jwt_retired_key_dir = env::var("SIGNET_JWT_RETIRED_KEY_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data/retired_keys"));
        let encryption_key_path = env::var("SIGNET_ENCRYPTION_KEY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data/encryption.key"));

        Ok(Self {
            database_url,
            db_max_connections: env::var("SIGNET_DB_MAX_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20),
            http_bind,
            issuer,
            cookie_secure,
            outbound_allow_private,
            jwt_private_key_path,
            jwt_retired_key_dir,
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
            audit_retention_days: {
                let days: i64 = env::var("SIGNET_AUDIT_RETENTION_DAYS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(180);
                // 0 (or negative) would delete the entire audit trail on the
                // first prune — the compliance record is exactly the thing a
                // mistyped env var must not be able to erase. "Keep everything
                // forever" is spelled by leaving the rows alone, not by a zero
                // day window, so refuse the value instead of interpreting it.
                if days < 1 {
                    bail!("SIGNET_AUDIT_RETENTION_DAYS must be >= 1, got {days}");
                }
                days
            },
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
            smtp_username: env::var("SIGNET_SMTP_USERNAME").ok(),
            smtp_password: env::var("SIGNET_SMTP_PASSWORD").ok(),
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
            allowed_email_domains: match env::var("SIGNET_ALLOWED_EMAIL_DOMAINS") {
                Err(_) => Vec::new(),
                // Comma or whitespace separated, since an address list is as
                // likely to arrive wrapped as it is on one line.
                Ok(raw) => {
                    let entries: Vec<String> = raw
                        .split(|c: char| c == ',' || c.is_whitespace())
                        .map(str::to_string)
                        .filter(|s| !s.is_empty())
                        .collect();
                    crate::admission::validate_domains(&entries, "SIGNET_ALLOWED_EMAIL_DOMAINS")
                        .map_err(|e| anyhow::anyhow!(e))?
                }
            },
            metrics_bind: match env::var("SIGNET_METRICS_BIND") {
                Ok(raw)
                    if matches!(
                        raw.trim().to_ascii_lowercase().as_str(),
                        "" | "off" | "none" | "false"
                    ) =>
                {
                    None
                }
                Ok(raw) => Some(
                    raw.trim()
                        .parse()
                        .context("invalid SIGNET_METRICS_BIND (expected host:port or off)")?,
                ),
                Err(_) => Some("127.0.0.1:9464".parse().expect("static metrics address")),
            },
            trusted_proxies,
            dev_log_links: env::var("SIGNET_DEV_LOG_LINKS")
                .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"))
                .unwrap_or(false),
        })
    }
}

/// Parses `SIGNET_TRUSTED_PROXIES`: comma-separated IPs or CIDRs. A malformed
/// entry is a startup error, not a silent skip — a typo'd CIDR that quietly
/// disappears would put the proxy address in audit trails instead of clients.
fn parse_trusted_proxies(raw: &str) -> Result<Vec<IpNet>> {
    let mut out = Vec::new();
    for entry in raw.split(',') {
        let t = entry.trim();
        if t.is_empty() {
            continue;
        }
        let net = if let Ok(net) = IpNet::from_str(t) {
            net
        } else if let Ok(ip) = t.parse::<IpAddr>() {
            IpNet::from(ip)
        } else {
            bail!("invalid SIGNET_TRUSTED_PROXIES entry: {t} (examples: 10.0.0.0/8, 172.17.0.5)");
        };
        out.push(net);
    }
    Ok(out)
}
