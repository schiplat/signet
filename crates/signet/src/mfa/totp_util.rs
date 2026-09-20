use crate::auth::password::{hash_password, verify_password};
use crate::error::{AppError, AppResult};
use rand::RngCore;
use totp_rs::{Algorithm, Secret, TOTP};

pub fn generate_totp_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

fn build_totp(secret_b32: &str, issuer: &str, account: &str) -> AppResult<TOTP> {
    let secret = Secret::Encoded(secret_b32.to_string());
    let bytes = secret
        .to_bytes()
        .map_err(|e| AppError::bad_request(format!("invalid totp secret: {e}")))?;
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        bytes,
        Some(issuer.to_string()),
        account.to_string(),
    )
    .map_err(|e| AppError::Anyhow(anyhow::anyhow!("totp: {e}")))
}

pub fn otpauth_uri(secret_b32: &str, issuer: &str, account: &str) -> AppResult<String> {
    Ok(build_totp(secret_b32, issuer, account)?.get_url())
}

pub fn verify_totp_code(secret_b32: &str, code: &str) -> AppResult<bool> {
    let code = code.trim().replace(' ', "");
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Ok(false);
    }
    let totp = build_totp(secret_b32, "Signet", "verify")?;
    Ok(totp.check_current(&code).unwrap_or(false))
}

/// Generate recovery codes like `ABCD-EFGH`.
pub fn generate_recovery_codes(n: usize) -> Vec<String> {
    let alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| {
            let mut raw = [0u8; 8];
            rng.fill_bytes(&mut raw);
            let mut s = String::with_capacity(9);
            for (i, b) in raw.iter().enumerate() {
                if i == 4 {
                    s.push('-');
                }
                s.push(alphabet[(*b as usize) % alphabet.len()] as char);
            }
            s
        })
        .collect()
}

pub fn normalize_recovery_code(code: &str) -> String {
    code.trim()
        .to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

pub fn hash_recovery_code(code: &str) -> AppResult<String> {
    let normalized = normalize_recovery_code(code);
    hash_password(&normalized).map_err(AppError::from)
}

pub fn verify_recovery_code(code: &str, code_hash: &str) -> AppResult<bool> {
    let normalized = normalize_recovery_code(code);
    verify_password(&normalized, code_hash).map_err(AppError::from)
}
