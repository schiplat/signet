use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex_encode(&digest)
}

pub fn sha256_b64url(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
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
    const BLOCK: usize = 64;
    let mut k = key.to_vec();
    if k.len() > BLOCK {
        k = Sha256::digest(&k).to_vec();
    }
    k.resize(BLOCK, 0);

    let mut ipad = Vec::with_capacity(BLOCK + msg.len());
    let mut opad = Vec::with_capacity(BLOCK);
    for b in &k {
        ipad.push(b ^ 0x36);
        opad.push(b ^ 0x5c);
    }
    ipad.extend_from_slice(msg);
    let inner = Sha256::digest(&ipad);
    opad.extend_from_slice(&inner);
    Sha256::digest(&opad).to_vec()
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}
