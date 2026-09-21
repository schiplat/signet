use crate::auth::passkey::ChallengeStore;
use crate::config::Config;
use crate::crypto::encryption::Encryptor;
use crate::crypto::keys::JwtKeys;
use crate::http::ratelimit::RateLimiter;
use sqlx::PgPool;
use std::sync::Arc;
use webauthn_rs::prelude::Webauthn;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
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
