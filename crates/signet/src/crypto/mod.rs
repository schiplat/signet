//! Cryptographic primitives and the key material built on them.
//!
//! * `util` — hashing, HMAC, constant-time compare and random tokens;
//! * `encryption` — the AES-256-GCM encryptor for secrets held at rest;
//! * `keys` — the RSA signing key and the JWKS published for it.

pub mod encryption;
pub mod keys;
pub mod util;
