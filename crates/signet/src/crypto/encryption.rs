//! Application-layer encryption for at-rest secrets (e.g. TOTP secrets).
//! Uses AES-256-GCM with a random 96-bit nonce per encryption; the nonce is
//! prepended to the ciphertext and the whole blob is base64-encoded.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use std::fs;
use std::path::Path;

#[derive(Clone)]
pub struct Encryptor {
    cipher: Aes256Gcm,
}

impl Encryptor {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(key).expect("AES-256-GCM requires a 32-byte key"),
        }
    }

    pub fn encrypt(&self, plaintext: &str) -> String {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .expect("encryption must not fail for valid inputs");
        let mut blob = nonce_bytes.to_vec();
        blob.extend_from_slice(&ciphertext);
        STANDARD.encode(blob)
    }

    pub fn decrypt(&self, encoded: &str) -> Option<String> {
        let bytes = STANDARD.decode(encoded).ok()?;
        if bytes.len() <= 12 {
            return None;
        }
        let (nonce_bytes, ciphertext) = bytes.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self.cipher.decrypt(nonce, ciphertext).ok()?;
        String::from_utf8(plaintext).ok()
    }
}

/// Loads a 32-byte key from `path` (hex-encoded), generating and persisting a
/// fresh one on first use — mirroring the JWT key bootstrap behavior.
pub fn load_or_generate_key(path: &Path) -> Result<[u8; 32]> {
    let hex = if path.exists() {
        fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let hex = data_encoding::HEXLOWER.encode(&key);
        fs::write(path, &hex).with_context(|| format!("write {}", path.display()))?;
        tracing::info!(path = %path.display(), "generated encryption key");
        hex
    };

    let bytes = data_encoding::HEXLOWER
        .decode(hex.trim().as_bytes())
        .context("decode encryption key (expected hex)")?;
    if bytes.len() != 32 {
        anyhow::bail!("encryption key must be 32 bytes");
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}
