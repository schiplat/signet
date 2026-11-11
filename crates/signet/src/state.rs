use crate::auth::passkey::ChallengeStore;
use crate::config::Config;
use crate::crypto::encryption::Encryptor;
use crate::crypto::keys::JwtKeys;
use crate::http::ratelimit::RateLimiter;
use crate::settings::RuntimeSettings;
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
    pub(crate) settings: Arc<RwLock<RuntimeSettings>>,
    /// Field names the database currently overrides; reported by the admin API
    /// so the UI can mark "inherited from environment" vs "set here".
    pub(crate) runtime_overridden: Arc<RwLock<Vec<&'static str>>>,
    pub keys: Arc<JwtKeys>,
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
