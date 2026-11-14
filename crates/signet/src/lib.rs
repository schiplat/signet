pub mod admin;
pub mod admission;
pub mod audit;
pub mod auth;
pub mod authority;
pub mod bootstrap;
pub mod captcha;
pub mod config;
pub mod crypto;
pub mod db;
pub mod developer;
pub mod directory;
pub mod email;
pub mod error;
pub mod federation;
pub mod groups;
pub mod http;
pub mod maintenance;
pub mod metrics;
pub mod mfa;
pub mod models;
pub mod oidc;
pub mod otel;
pub mod outbound;
pub mod outbox;
pub mod roles;
pub mod scim;
pub mod settings;
pub mod setup;
pub mod state;
pub mod webhooks;

use crate::config::Config;
use crate::state::AppState;
use anyhow::Context;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;

/// The prefix every JSON API route is nested under.
///
/// This is a constant rather than a literal because the SSO callback URL is
/// composed as an *absolute* path: it is sent upstream as the OAuth
/// `redirect_uri` and also shown to admins to register with the provider, so
/// it cannot be derived from the router at runtime. Changing the nest below
/// without changing this would break sign-in with a redirect-URI mismatch.
pub const API_PREFIX: &str = "/api/v1";

pub async fn build_app(cfg: Config) -> anyhow::Result<Router> {
    let state = build_state(cfg).await?;

    // Server startup only (the CLI and tests want build_state without policy):
    // refuse to serve when this instance's encryption key is not the one the
    // database was provisioned with. TOTP and webhook secrets are AES-GCM
    // ciphertexts under that key — a second instance on the same database with
    // a different key would silently break the other's rows (a TOTP enrolled
    // via instance A fails base32 decoding on instance B). Fail-closed here is
    // the loud version of that failure. Re-keying intentionally: delete the
    // `crypto.encryption_key_fingerprint` row in app_settings.
    {
        use sha2::{Digest, Sha256};
        let key = crypto::encryption::load_or_generate_key(&state.config.encryption_key_path)?;
        let fingerprint = data_encoding::HEXLOWER
            .encode(&Sha256::digest(key)[..])
            .get(..16)
            .unwrap_or_default()
            .to_string();
        bootstrap::ensure_encryption_key_fingerprint(&state.pool, &fingerprint).await?;
    }

    // Started here rather than in `build_state`: the CLI and the tests want the
    // engine without a background loop firing syncs at them.
    directory::scheduler::spawn(state.clone());

    // Hourly audit-retention prune plus the expired-credential sweeps (see the
    // module docs). Boot-time only used to be the whole story for retention,
    // which silently re-grew past the configured window between restarts.
    maintenance::spawn(state.clone());

    // Converge runtime settings across replicas every 30s (the PATCH path
    // publishes to its own process instantly; this is the cross-replica path).
    settings::spawn_refresher(state.clone());

    // Pick up out-of-band key rotation (`signet keys rotate`, a peer replica
    // on a shared data dir) without a restart.
    crypto::keys::spawn_key_watcher(state.clone());

    // Durable webhook/email delivery with backoff (see the module docs).
    outbox::spawn(state.clone());

    // Metrics get their own listener. They used to be an unauthenticated route
    // on the public API: token-issuance, login-failure and lockout counters are
    // reconnaissance, and a scrape endpoint has no business being reachable by
    // every client that can reach the IdP. The default binds loopback; a
    // scraper on another host sets SIGNET_METRICS_BIND explicitly (or scrapes
    // through a proxy that is allowed to reach it). `SIGNET_METRICS_BIND=off`
    // disables the listener.
    if let Some(bind) = state.config.metrics_bind {
        // Metrics are optional telemetry: a second instance on the same host
        // (or a stale process holding the port) must not keep the IdP from
        // starting. The warning names the setting, so the operator can move it
        // or set SIGNET_METRICS_BIND=off deliberately.
        match tokio::net::TcpListener::bind(bind).await {
            Ok(listener) => {
                tracing::info!(%bind, "metrics listening (health + metrics only)");
                let metrics_app = metrics::router(state.clone());
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(listener, metrics_app).await {
                        tracing::error!(error = %e, "metrics listener stopped");
                    }
                });
            }
            Err(e) => tracing::warn!(
                %bind,
                error = %e,
                "metrics listener unavailable (port in use?); serving without /metrics — \
                 set SIGNET_METRICS_BIND to another address or off"
            ),
        }
    }

    let api_v1 = Router::new()
        // Public: the unauthenticated pages (sign-in, reset, setup) read the
        // product name here.
        .route("/branding", get(settings::public_branding))
        .merge(auth::router())
        .merge(mfa::router())
        .merge(auth::passkey::router())
        .merge(developer::router())
        .merge(federation::routes::router())
        .merge(federation::admin::router())
        .merge(admin::router())
        .merge(groups::router())
        .merge(audit::router())
        .merge(auth::password_reset::router())
        .merge(webhooks::router())
        .merge(directory::api::router())
        .merge(admission::router())
        .merge(settings::router())
        .merge(setup::router());

    let api = Router::new()
        // `/health` stays on the main listener: the container healthcheck and
        // any load balancer need it, and it exposes only database liveness.
        .route("/health", get(metrics::health))
        .nest(API_PREFIX, api_v1)
        .merge(scim::router())
        .merge(oidc::router())
        .fallback(http::static_files::spa_fallback)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            http::ratelimit::track,
        ))
        .layer(axum::middleware::from_fn(metrics::track))
        .layer(axum::middleware::from_fn(http::access_log::track))
        .layer(axum::middleware::from_fn(http::headers::security))
        .layer(axum::middleware::from_fn(http::request_id::track))
        .with_state(state);

    Ok(api)
}

/// Builds the application state, running migrations and the boot-time fixups.
///
/// Split out of [`build_app`] so the CLI can drive the same engine against the
/// same database and encryption key without standing up an HTTP server.
pub async fn build_state(cfg: Config) -> anyhow::Result<AppState> {
    if cfg.outbound_allow_private {
        // Security-relevant downshift: make it loud in the logs.
        tracing::warn!("outbound private-address blocking is disabled");
    }
    let pool = db::connect(&cfg.database_url, cfg.db_max_connections).await?;
    db::migrate(&pool).await?;

    // Operational policy: DB overrides layered over the environment. Loaded
    // once here so boot-time decisions (the rate limiter's initial budget, the
    // startup summary) agree with the first request.
    let (runtime, overridden) = settings::load(&pool, &cfg).await;
    // Effective issuer for this process: SIGNET_ISSUER when set, else the
    // dashboard value, else the built-in default. Published so the first
    // request already sees it (the refresher converges peers every 30s).
    let issuer = settings::effective_issuer(&pool, &cfg)
        .await
        .context("load the effective issuer")?;
    let rate_limit_per_minute = runtime.rate_limit_per_minute;

    // Audit pruning deliberately does NOT run at boot any more: it was a
    // synchronous DELETE that could hold up startup on a large table, and the
    // hourly sweeper (maintenance) now owns retention. Boot-time work stays to
    // what must be true before the first request.
    bootstrap::ensure_scim_token(&pool, &cfg).await?;

    // An allowlist that excludes every admin cannot be fixed from inside the
    // product — the dashboard needs a sign-in it refuses — so say so at startup,
    // where the operator can still reach the environment.
    admission::warn_if_all_admins_excluded(&pool, &cfg.allowed_email_domains).await;

    tracing::info!(
        session_ttl_hours = runtime.session_ttl_hours,
        auth_code_ttl_secs = runtime.auth_code_ttl_secs,
        access_token_ttl_secs = runtime.access_token_ttl_secs,
        id_token_ttl_secs = runtime.id_token_ttl_secs,
        refresh_token_ttl_days = runtime.refresh_token_ttl_days,
        max_login_attempts = runtime.max_login_attempts,
        lockout_minutes = runtime.lockout_minutes,
        password_min_length = runtime.password_min_length,
        password_history_size = runtime.password_history_size,
        audit_retention_days = runtime.audit_retention_days,
        rate_limit_per_minute = runtime.rate_limit_per_minute,
        issuer = %issuer,
        db_overrides = ?overridden,
        "runtime settings in effect (change these in Dashboard -> Settings)"
    );

    let keys = crypto::keys::JwtKeys::load_or_generate_with_retired(
        &cfg.jwt_private_key_path,
        Some(&cfg.jwt_retired_key_dir),
    )?;
    let encryption_key = crypto::encryption::load_or_generate_key(&cfg.encryption_key_path)?;
    let encryptor = crypto::encryption::Encryptor::new(&encryption_key);
    let client_secret_key = Arc::new(crypto::encryption::client_secret_key(&encryption_key));
    // One-way move of webhook secrets out of the legacy plaintext column.
    // Deliberately fatal: carrying on would leave `secret_enc` NULL and
    // silently downgrade webhook deliveries to unsigned.
    bootstrap::encrypt_webhook_secrets(&pool, &encryptor).await?;
    let webauthn = {
        let origin = url::Url::parse(&cfg.webauthn_rp_origin)
            .context("invalid SIGNET_WEBAUTHN_RP_ORIGIN")?;
        webauthn_rs::WebauthnBuilder::new(&cfg.webauthn_rp_id, &origin)
            .context("invalid webauthn configuration")?
            .build()
            .context("invalid webauthn configuration")?
    };
    Ok(AppState {
        pool,
        config: Arc::new(cfg),
        settings: Arc::new(std::sync::RwLock::new(runtime)),
        issuer: Arc::new(std::sync::RwLock::new(issuer.clone())),
        runtime_overridden: Arc::new(std::sync::RwLock::new(overridden)),
        keys: Arc::new(arc_swap::ArcSwap::from_pointee(keys)),
        encryptor: Arc::new(encryptor),
        client_secret_key,
        rate_limiter: Arc::new(http::ratelimit::RateLimiter::new(rate_limit_per_minute)),
        webauthn: Arc::new(webauthn),
        passkey_challenges: auth::passkey::new_store(),
    })
}
