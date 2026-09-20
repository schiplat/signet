use crate::config::Config;
use crate::crypto::encryption::Encryptor;
use crate::crypto::keys::JwtKeys;
use crate::passkey::ChallengeStore;
use crate::ratelimit::RateLimiter;
use sqlx::PgPool;
use std::sync::Arc;
use webauthn_rs::prelude::Webauthn;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub keys: Arc<JwtKeys>,
    pub encryptor: Arc<Encryptor>,
    pub rate_limiter: Arc<RateLimiter>,
    pub webauthn: Arc<Webauthn>,
    pub(crate) passkey_challenges: ChallengeStore,
}
