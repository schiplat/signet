//! Client-secret hashing.
//!
//! A client secret is a credential like a password, but it is *not* the same
//! threat, and hashing it the same way costs more than it buys.
//!
//! User passwords are chosen by people, so they have to be assumed guessable,
//! and Argon2's deliberate slowness is the only thing between a leaked table and
//! a plaintext. There is one hash per login.
//!
//! A client secret is verified on **every** request to `/oauth/token` — every
//! refresh, every API access token — which makes an Argon2 verification (19 MiB,
//! tens of milliseconds, on a Tokio worker) a self-inflicted load spike on the
//! busiest endpoint there is.
//!
//! So the digest is fast HMAC-SHA256, keyed with a secret the database does not
//! hold. The key is what makes that safe: generated secrets are 32 bytes of
//! CSPRNG output and need no help, but an administrator may also *type* a secret
//! as short as 16 characters, and a bare SHA-256 of something guessable is
//! crackable in seconds. An attacker holding only a database dump cannot test a
//! guess without the key. This is the usual "pepper" arrangement, and it is why
//! the digest cannot be compared across deployments.
//!
//! Rows written before this module existed hold an Argon2 hash. They are still
//! verified (off the async workers), and a successful match **upgrades the row**
//! to the HMAC form — so an existing deployment converges onto the fast path as
//! its clients sign in, without rotating a single secret.

use crate::error::AppResult;
use crate::state::AppState;

/// Marks a digest produced by [`digest`].
///
/// Stored in the column rather than assumed, so a legacy Argon2 hash (which
/// looks like `$argon2id$…`) is unmistakably different from a digest, and no
/// migration has to rewrite rows before the new code can read them.
const PREFIX: &str = "hmac-sha256:";

/// The stored form of `secret` under `key`.
///
/// No salt: a salt's job is to stop one precomputation from covering many
/// passwords at once, and the key already does that job better — there is no
/// precomputation to do without it, whatever the table looks like.
pub fn digest(key: &[u8; 32], secret: &str) -> String {
    format!(
        "{PREFIX}{}",
        crate::crypto::util::hmac_sha256_hex(key, secret.as_bytes())
    )
}

/// Whether `stored` was produced by [`digest`].
pub fn is_digest(stored: &str) -> bool {
    stored.starts_with(PREFIX)
}

/// Checks a presented client secret against the stored value for `client_id`.
///
/// `client_id` and the pool are needed only for the legacy upgrade path: on a
/// successful Argon2 match the row is rewritten in the digest form. The update
/// is guarded on the hash it is replacing, so a secret rotated between the read
/// and the write is not silently reverted to the old value.
pub async fn verify(
    state: &AppState,
    client_id: &str,
    presented: &str,
    stored: &str,
) -> AppResult<bool> {
    if is_digest(stored) {
        let expected = digest(&state.client_secret_key, presented);
        return Ok(constant_time_eq(expected.as_bytes(), stored.as_bytes()));
    }

    // Legacy row: an Argon2 hash, verified off the async workers for the same
    // reason it is being replaced.
    if !crate::auth::password::verify_password_offloaded(presented, stored).await? {
        return Ok(false);
    }

    let upgraded = digest(&state.client_secret_key, presented);
    match sqlx::query(
        "UPDATE client_apps SET client_secret_hash = $3, updated_at = NOW() \
         WHERE client_id = $1 AND client_secret_hash = $2",
    )
    .bind(client_id)
    .bind(stored)
    .bind(&upgraded)
    .execute(&state.pool)
    .await
    {
        Ok(result) => {
            if result.rows_affected() == 1 {
                tracing::info!(
                    client_id,
                    "upgraded a client secret hash off argon2 after a successful verification"
                );
            }
        }
        // The upgrade is an optimization, never a condition of the login: the
        // secret just proved itself, so a failed write must not reject it.
        Err(err) => {
            tracing::warn!(error = %err, client_id, "could not upgrade a client secret hash")
        }
    }
    Ok(true)
}

/// Compares two digests without leaking *where* they differ through timing.
///
/// Written out rather than using `==` because the comparison is against a
/// secret-derived value: `==` on a slice stops at the first differing byte, and
/// the time it takes is a signal a caller could in principle read. Length is not
/// hidden — both sides are fixed-width digests, so it carries nothing.
///
/// Public so the timing property can be pinned from `tests/client_secret.rs`;
/// it is not otherwise part of the module's surface.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
