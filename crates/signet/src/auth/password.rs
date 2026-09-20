use anyhow::{anyhow, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use password_hash::rand_core::OsRng;
use sqlx::PgPool;
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
    for h in &hashes {
        if verify_password(new_password, h).unwrap_or(false) {
            return Err(AppError::bad_request(
                "password was used recently, choose a different one",
            ));
        }
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
    let hash = hash_password(new_password)?;
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
