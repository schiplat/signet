pub mod access_log;
pub mod admin;
pub mod audit;
pub mod auth;
pub mod bootstrap;
pub mod client_ip;
pub mod config;
pub mod crypto_util;
pub mod db;
pub mod email;
pub mod encryption;
pub mod error;
pub mod federation;
pub mod http_util;
pub mod keys;
pub mod login_alert;
pub mod metrics;
pub mod mfa;
pub mod models;
pub mod oidc;
pub mod passkey;
pub mod password;
pub mod password_reset;
pub mod ratelimit;
pub mod request_id;
pub mod roles;
pub mod scim;
pub mod setup;
pub mod state;
pub mod static_files;
pub mod ua;
pub mod webhooks;

use crate::config::Config;
use crate::state::AppState;
use anyhow::Context;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;

pub async fn build_app(cfg: Config) -> anyhow::Result<Router> {
    let pool = db::connect(&cfg.database_url).await?;
    db::migrate(&pool).await?;
    bootstrap::ensure_scim_token(&pool, &cfg).await?;

    if let Err(e) = audit::prune_audit_logs(&pool, cfg.audit_retention_days).await {
        tracing::warn!(error = %e, "failed to prune old audit logs");
    }

    let keys = keys::JwtKeys::load_or_generate(&cfg.jwt_private_key_path)?;
    let encryption_key = encryption::load_or_generate_key(&cfg.encryption_key_path)?;
    let rate_limit_per_minute = cfg.rate_limit_per_minute;
    let webauthn = {
        let origin = url::Url::parse(&cfg.webauthn_rp_origin)
            .context("invalid SIGNET_WEBAUTHN_RP_ORIGIN")?;
        webauthn_rs::WebauthnBuilder::new(&cfg.webauthn_rp_id, &origin)
            .context("invalid webauthn configuration")?
            .build()
            .context("invalid webauthn configuration")?
    };
    let state = AppState {
        pool,
        config: Arc::new(cfg),
        keys: Arc::new(keys),
        encryptor: Arc::new(encryption::Encryptor::new(&encryption_key)),
        rate_limiter: Arc::new(ratelimit::RateLimiter::new(rate_limit_per_minute)),
        webauthn: Arc::new(webauthn),
        passkey_challenges: passkey::new_store(),
    };

    let api_v1 = Router::new()
        .merge(auth::router())
        .merge(mfa::router())
        .merge(passkey::router())
        .merge(federation::routes::router())
        .merge(federation::admin::router())
        .merge(admin::router())
        .merge(audit::router())
        .merge(password_reset::router())
        .merge(webhooks::router())
        .merge(setup::router());

    let api = Router::new()
        .route("/health", get(metrics::health))
        .route("/metrics", get(metrics::metrics))
        .nest("/api/v1", api_v1)
        .merge(scim::router())
        .merge(oidc::router())
        .fallback(static_files::spa_fallback)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            ratelimit::track,
        ))
        .layer(axum::middleware::from_fn(metrics::track))
        .layer(axum::middleware::from_fn(access_log::track))
        .layer(axum::middleware::from_fn(request_id::track))
        .with_state(state);

    Ok(api)
}
