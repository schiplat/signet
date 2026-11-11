use crate::auth::password::{hash_passwords_offloaded, match_password_among};
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
    Ok(verify_totp_code_step(secret_b32, code)?.is_some())
}

/// Verifies `code` and returns the timestep that matched, if any.
///
/// The step — not just a boolean — is what replay protection needs: a code is
/// single-use per timestep, so the login path records the accepted step and
/// refuses everything at or below it later. The window is the same ±1 step
/// `check_current` uses (skew 1), evaluated step by step so the *matching*
/// step is known rather than merely that some step matched.
pub fn verify_totp_code_step(secret_b32: &str, code: &str) -> AppResult<Option<u64>> {
    let code = code.trim().replace(' ', "");
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Ok(None);
    }
    let totp = build_totp(secret_b32, "Signet", "verify")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let current = now / 30;
    for offset in [-1i64, 0, 1] {
        let step = (current as i64 + offset).max(0) as u64;
        // `TOTP::generate` takes the Unix timestamp in *seconds* and divides by
        // the step internally (totp-rs `check` does `time / self.step`).
        // Passing the step number produces codes from 1970 — a mistake e2e
        // caught, because nothing else exercises a real authenticator.
        if totp.generate(step * 30) == code {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

/// The code an authenticator app would show for `step`.
///
/// **Exposed for tests**: the server only ever verifies, but a test needs a way
/// to produce a code that is valid *now* without re-implementing TOTP. Keep the
/// surface here minimal; nothing in production calls this.
pub fn code_for_step(secret_b32: &str, step: u64) -> AppResult<String> {
    Ok(build_totp(secret_b32, "Signet", "verify")?.generate(step * 30))
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

/// Hashes a freshly generated batch of recovery codes.
///
/// The batch goes to the blocking pool as a unit: enrolling MFA hashes ten codes
/// at once, and each one is a full Argon2 hash (19 MiB, tens of milliseconds), so
/// doing them one hand-off at a time would occupy a worker per code in sequence.
pub async fn hash_recovery_codes(codes: &[String]) -> AppResult<Vec<String>> {
    let normalized: Vec<String> = codes.iter().map(|c| normalize_recovery_code(c)).collect();
    hash_passwords_offloaded(normalized)
        .await
        .map_err(AppError::from)
}

/// The index of the recovery code matching one of `hashes`, if any.
///
/// Verification stops at the first match, but a non-match has to try every code
/// the user was issued, so the list is verified in one blocking task.
pub async fn match_recovery_code(code: &str, hashes: Vec<String>) -> AppResult<Option<usize>> {
    let normalized = normalize_recovery_code(code);
    match_password_among(&normalized, hashes)
        .await
        .map_err(AppError::from)
}
