use anyhow::{anyhow, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use password_hash::rand_core::OsRng;
use sqlx::PgPool;
use std::sync::OnceLock;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("hash password: {e}"))?
        .to_string();
    Ok(hash)
}

pub fn verify_password(password: &str, password_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(password_hash).map_err(|e| anyhow!("parse hash: {e}"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Bounds how many hashes are being computed at any one moment.
///
/// Argon2 is memory-hard by design: the defaults below spend 19 MiB and tens of
/// milliseconds per hash. Moving it to the blocking pool keeps the async workers
/// free, but the blocking pool is hundreds of threads wide, so a burst of sign-in
/// attempts would otherwise multiply those 19 MiB by the whole pool. One hash per
/// core keeps peak memory at cores × 19 MiB and lets the rest queue.
fn hashing_gate() -> &'static Semaphore {
    static GATE: OnceLock<Semaphore> = OnceLock::new();
    GATE.get_or_init(|| {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Semaphore::new(cores)
    })
}

/// Runs a deliberately slow, CPU-bound hash on the blocking pool.
///
/// Every `hash_password`/`verify_password` call site reachable from a request
/// handler must go through here. Called directly from an async handler, one
/// Argon2 hash parks a whole Tokio worker for tens of milliseconds — and the
/// default runtime has one worker per core, so a handful of concurrent sign-ins
/// or token requests stall every unrelated request behind them.
async fn offload<T, F>(job: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let _permit = hashing_gate()
        .acquire()
        .await
        .expect("the hashing gate is never closed");
    tokio::task::spawn_blocking(job)
        .await
        .map_err(|e| anyhow!("hashing task did not run to completion: {e}"))?
}

/// [`hash_password`], off the async worker threads.
pub async fn hash_password_offloaded(password: &str) -> Result<String> {
    let password = password.to_string();
    offload(move || hash_password(&password)).await
}

/// [`hash_password`] for a whole batch, in a single blocking task.
///
/// Recovery codes are generated and hashed ten at a time; one hand-off per code
/// would pay the pool round trip ten times over for the same amount of CPU.
pub async fn hash_passwords_offloaded(passwords: Vec<String>) -> Result<Vec<String>> {
    offload(move || passwords.iter().map(|p| hash_password(p)).collect()).await
}

/// [`verify_password`], off the async worker threads.
pub async fn verify_password_offloaded(password: &str, password_hash: &str) -> Result<bool> {
    let (password, password_hash) = (password.to_string(), password_hash.to_string());
    offload(move || verify_password(&password, &password_hash)).await
}

/// The index of the first hash `password` matches, or `None`.
///
/// A list of candidate hashes is verified in one blocking task: callers that
/// keep a history of previous passwords, or ten recovery codes, would otherwise
/// occupy the pool once per entry. A hash that cannot be parsed is treated as a
/// non-match rather than an error, so one corrupt row cannot lock a user out.
pub async fn match_password_among(password: &str, hashes: Vec<String>) -> Result<Option<usize>> {
    let password = password.to_string();
    offload(move || {
        Ok(hashes
            .iter()
            .position(|h| verify_password(&password, h).unwrap_or(false)))
    })
    .await
}

/// Validates password strength. Returns a human-readable message on failure.
pub fn validate_password_strength(password: &str, min_length: usize) -> Result<()> {
    if password.len() < min_length {
        return Err(anyhow!("password must be at least {min_length} characters"));
    }
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    if !has_lower || !has_upper || !has_digit {
        return Err(anyhow!(
            "password must include upper and lower case letters and a digit"
        ));
    }
    Ok(())
}

/// Rejects the new password if it matches any of the user's recent hashes.
pub async fn validate_password_history(
    pool: &PgPool,
    user_id: Uuid,
    new_password: &str,
    history_size: i64,
) -> AppResult<()> {
    let hashes: Vec<String> = sqlx::query_scalar(
        "SELECT password_hash FROM password_history WHERE user_id = $1 \
         ORDER BY created_at DESC LIMIT $2",
    )
    .bind(user_id)
    .bind(history_size)
    .fetch_all(pool)
    .await?;
    // One blocking task for the whole history: every entry is an Argon2
    // verification, and these are all attempted hashes of the same candidate.
    if match_password_among(new_password, hashes).await?.is_some() {
        return Err(AppError::bad_request(
            "password was used recently, choose a different one",
        ));
    }
    Ok(())
}

pub async fn record_password_history(
    pool: &PgPool,
    user_id: Uuid,
    password_hash: &str,
) -> AppResult<()> {
    sqlx::query("INSERT INTO password_history (id, user_id, password_hash) VALUES ($1, $2, $3)")
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(password_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Validates strength + history, then sets the user's password and records it.
///
/// Refuses outright for a user a *live* directory manages. The login path
/// authenticates those users by bind-through (§8.1), so a local hash is never
/// consulted — writing one would not just be useless, it would leave a dormant
/// credential behind that turns live the moment the source is disabled or
/// removed. Failing here is the single choke point for all four callers (self
/// change, admin reset, emailed reset, forced change), so none of them can
/// accidentally create that credential.
pub async fn set_user_password(
    pool: &PgPool,
    user_id: Uuid,
    new_password: &str,
    min_length: usize,
    history_size: i64,
) -> AppResult<()> {
    if let Some(source) = crate::directory::enabled_managing_source(pool, user_id).await? {
        return Err(AppError::bad_request(format!(
            "this account's password is held by directory source {source}; \
             change it in the directory"
        )));
    }
    validate_password_strength(new_password, min_length)
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    validate_password_history(pool, user_id, new_password, history_size).await?;
    let hash = hash_password_offloaded(new_password).await?;
    record_password_history(pool, user_id, &hash).await?;
    sqlx::query(
        "UPDATE users SET password_hash = $2, password_changed_at = NOW(), updated_at = NOW() WHERE id = $1",
    )
    .bind(user_id)
    .bind(hash)
    .execute(pool)
    .await?;
    Ok(())
}
