use crate::auth::passkey::ChallengeStore;
use crate::config::Config;
use crate::crypto::encryption::Encryptor;
use crate::crypto::keys::JwtKeys;
use crate::http::ratelimit::RateLimiter;
use crate::settings::RuntimeSettings;
use arc_swap::ArcSwap;
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use webauthn_rs::prelude::Webauthn;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    /// Live operational policy (DB > env > default). Read through [`Self::rt`]
    /// at the point of use, never cached in a long-lived object, so a settings
    /// change applies to the next request.
    ///
    /// Multi-replica: a PATCH publishes here and to the database; peer
    /// replicas converge via the background re-reader in [`crate::settings`]
    /// (a 30-second interval), so cross-replica propagation is bounded by that
    /// interval rather than "at next restart".
    pub(crate) settings: Arc<RwLock<RuntimeSettings>>,
    /// The **effective** issuer: `SIGNET_ISSUER` when set (environment always
    /// wins — it is the recovery path), else `app_settings.server.issuer`, else
    /// the built-in default. Behind a lock because an administrator can change
    /// it from the dashboard; read it through [`Self::issuer`], never from
    /// `config.issuer` (that is only the boot-time fallback).
    pub(crate) issuer: Arc<RwLock<String>>,
    /// Field names the database currently overrides; reported by the admin API
    /// so the UI can mark "inherited from environment" vs "set here".
    pub(crate) runtime_overridden: Arc<RwLock<Vec<&'static str>>>,
    /// The signing key ring, behind an [`ArcSwap`]: reads are lock-free and
    /// the background watcher (`crate::crypto::keys::spawn_key_watcher`) can
    /// swap in a rotated ring without a restart. Load at the point of use.
    pub keys: Arc<ArcSwap<JwtKeys>>,
    pub encryptor: Arc<Encryptor>,
    /// The pepper for client-secret digests.
    ///
    /// Derived from the same key file as `encryptor`, under its own label, so a
    /// database dump alone cannot be used to test a guess against a stored
    /// secret. See [`crate::auth::client_secret`].
    pub client_secret_key: Arc<[u8; 32]>,
    pub rate_limiter: Arc<RateLimiter>,
    pub webauthn: Arc<Webauthn>,
    pub(crate) passkey_challenges: ChallengeStore,
}

impl AppState {
    /// A copy of the current runtime settings. Eleven integers — copying is
    /// cheaper than holding a lock across an await, and the snapshot keeps one
    /// request immune to a settings change landing between two reads.
    pub fn rt(&self) -> RuntimeSettings {
        *self
            .settings
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The issuer every token, discovery document and public link must use.
    pub fn issuer(&self) -> String {
        self.issuer
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn publish_issuer(&self, next: String) {
        *self
            .issuer
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
    }

    /// Whether cookies must carry `Secure`: forced by the environment, or the
    /// effective issuer is https. Evaluated per response so a dashboard change
    /// from http to https secures cookies immediately.
    pub fn cookie_secure(&self) -> bool {
        self.config.cookie_secure_forced || self.issuer().starts_with("https://")
    }

    /// The origin used for absolute links (reset links, SSO callbacks, test
    /// drive): `SIGNET_PUBLIC_BASE_URL` when configured, else the effective
    /// issuer. Same precedence the issuer itself follows.
    pub fn public_base(&self) -> String {
        self.config
            .public_base_url
            .clone()
            .unwrap_or_else(|| self.issuer())
    }

    pub fn publish_settings(&self, next: RuntimeSettings) {
        *self
            .settings
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
    }

    pub fn overridden(&self) -> Vec<&'static str> {
        self.runtime_overridden
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn replace_overridden(&self, fields: Vec<&'static str>) {
        *self
            .runtime_overridden
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = fields;
    }

    pub fn mark_overridden(&self, fields: &[&'static str]) {
        let mut current = self
            .runtime_overridden
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for field in fields {
            if !current.contains(field) {
                current.push(field);
            }
        }
    }
}
