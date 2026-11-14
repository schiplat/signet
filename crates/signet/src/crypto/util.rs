//! Hashing, HMAC, encoding and key-file bootstrap shared by the rest of
//! `crypto`.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Prefixed, scan-friendly credential tokens: `sgn_pat_…`, `sgn_cs_…`,
/// `sgn_cl_…`, `sgn_reg_…`.
///
/// The prefix identifies a credential as Signet's the moment someone pastes it
/// into a log, a config file or a support ticket, and gives secret scanners
/// (gitleaks-style `sgn_[a-z]+_` rules) an anchor to match against — without
/// changing the entropy of the random part. Only long-lived credentials
/// handed to operators or other systems carry one; short-lived internal
/// tokens (sessions, auth codes, one-time links) stay bare.
pub fn prefixed_token(prefix: &str, bytes: usize) -> String {
    format!("{prefix}_{}", random_token(bytes))
}

pub fn sha256_hex(input: &str) -> String {
    hex_encode(&Sha256::digest(input.as_bytes()))
}

pub fn sha256_b64url(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// OIDC `at_hash`: base64url of the left half of SHA-256 over the access token
/// (OpenID Connect Core 3.1.3.6). A client verifies it against the access
/// token it received, binding the two halves of one token response.
pub fn at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
}

pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// HMAC-SHA256, hex-encoded (for webhook signatures).
pub fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    hex_encode(&hmac_sha256(key, msg))
}

/// HMAC-SHA256, standard-base64-encoded (for Feishu bot signing).
pub fn hmac_sha256_b64(key: &[u8], msg: &[u8]) -> String {
    b64_encode(&hmac_sha256(key, msg))
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    // HMAC accepts a key of any length (it hashes longer-than-block keys), so
    // `new_from_slice` cannot fail here.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

pub fn hex_encode(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

/// Reads a key file, generating and persisting it on first use.
///
/// `what` names the key in logs ("encryption key", "JWT signing key"). The
/// generated file is created with `0600` on Unix: it holds private key
/// material, so the default `0644` would expose it to every local user. An
/// existing file is left as it is, but a group- or world-readable one is
/// reported so the operator can tighten it.
///
/// If another process creates the file first — two replicas starting against
/// one shared volume — the winner's key is adopted rather than replaced, so
/// every process converges on a single key. Overwriting would instead leave
/// the replicas signing JWTs the others reject, and unable to decrypt each
/// other's secrets.
pub fn read_or_generate_file(
    path: &Path,
    what: &str,
    generate: impl FnOnce() -> anyhow::Result<String>,
) -> anyhow::Result<String> {
    use anyhow::Context;

    if path.exists() {
        return read_existing(path);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let contents = generate()?;
    match write_private(path, &contents) {
        Ok(()) => {
            tracing::info!(path = %path.display(), kind = what, "generated key file");
            Ok(contents)
        }
        // Lost the race. The winner's file may still be mid-write, in which
        // case reading it fails loudly rather than yielding a truncated key.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_existing(path),
        Err(e) => Err(e).with_context(|| format!("write {}", path.display())),
    }
}

fn read_existing(path: &Path) -> anyhow::Result<String> {
    use anyhow::Context;

    let contents = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    warn_if_other_readable(path);
    Ok(contents)
}

#[cfg(unix)]
pub(crate) fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    // `create_new` rather than `create`: never clobber a key another process
    // already published.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
pub(crate) fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    fs::write(path, contents)
}

#[cfg(unix)]
fn warn_if_other_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let Ok(meta) = fs::metadata(path) else {
        return;
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        tracing::warn!(
            path = %path.display(),
            mode = %format!("{mode:o}"),
            "key file is readable by other local users"
        );
    }
}

#[cfg(not(unix))]
fn warn_if_other_readable(_path: &Path) {}
