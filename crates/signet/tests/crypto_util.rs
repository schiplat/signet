//! Tests for `signet::crypto::util`.
//!
//! The HMAC vectors are RFC 4231 §4.2, §4.3, §4.4 and §4.6, with the base64
//! and hex encodings asserted separately so an encoding regression cannot hide
//! behind a matching digest.

use signet::crypto::util::{
    b64_encode, b64url_encode, hex_encode, hmac_sha256_b64, hmac_sha256_hex, random_token,
    read_or_generate_file, sha256_b64url, sha256_hex,
};
use std::path::PathBuf;

/// RFC 4231 uses an 0xaa key of 131 bytes, longer than SHA-256's 64-byte block,
/// so it exercises the "hash the key first" branch.
fn long_key() -> Vec<u8> {
    vec![0xaa; 131]
}

#[test]
fn hmac_sha256_hex_matches_rfc_4231_case_1() {
    // 20-byte key, "Hi There".
    let key = vec![0x0b; 20];
    assert_eq!(
        hmac_sha256_hex(&key, b"Hi There"),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn hmac_sha256_hex_matches_rfc_4231_case_2() {
    // A key shorter than the block size.
    assert_eq!(
        hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn hmac_sha256_hex_matches_rfc_4231_case_3() {
    // Non-ascii key and message.
    assert_eq!(
        hmac_sha256_hex(&[0xaa; 20], &[0xdd; 50]),
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    );
}

#[test]
fn hmac_sha256_hex_matches_rfc_4231_case_6() {
    assert_eq!(
        hmac_sha256_hex(
            &long_key(),
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn hmac_sha256_hex_handles_data_longer_than_one_block() {
    assert_eq!(
        hmac_sha256_hex(
            &long_key(),
            b"Test using larger than block-size key and larger than one block-size data"
        ),
        "a1954b6483317754a53981cefcc8720a7d54d7b9a9898e81c307a253c4dd5557"
    );
}

#[test]
fn hmac_sha256_b64_is_the_base64_of_the_same_digest() {
    // The webhook header and the Feishu body signing share one digest, so these
    // two encoders must never drift apart.
    assert_eq!(
        hmac_sha256_b64(&[0x0b; 20], b"Hi There"),
        "sDRMYdjbOFNcqK/OrwvxK4gdwgDJgz2nJuk3bC4yz/c="
    );
}

#[test]
fn hex_encode_is_lowercase() {
    assert_eq!(hex_encode(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
}

#[test]
fn sha256_hex_matches_a_known_digest() {
    assert_eq!(
        sha256_hex("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_b64url_is_unpadded_url_safe_base64() {
    // 32 bytes -> 43 chars with no '=' padding.
    let encoded = sha256_b64url("abc");
    assert_eq!(encoded.len(), 43);
    assert!(!encoded.contains('='));
    assert!(!encoded.contains('+') && !encoded.contains('/'));
}

#[test]
fn b64url_encode_is_unpadded() {
    assert_eq!(b64url_encode(&[0xff, 0xef]), "_-8");
}

#[test]
fn b64_encode_uses_the_standard_alphabet() {
    assert_eq!(b64_encode(&[0xff, 0xef]), "/+8=");
}

#[test]
fn random_token_is_url_safe_and_does_not_repeat() {
    let token = random_token(32);
    // 32 bytes -> 43 unpadded url-safe base64 chars.
    assert_eq!(token.len(), 43);
    assert!(token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

    let tokens: std::collections::HashSet<_> = (0..64).map(|_| random_token(32)).collect();
    assert_eq!(tokens.len(), 64, "random tokens must not collide");
}

/// A scratch path unique to this test run.
fn scratch_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("signet-crypto-{}-{tag}", std::process::id()))
}

#[test]
fn a_generated_key_file_is_not_readable_by_other_users() {
    let dir = scratch_dir("private");
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("nested").join("test.key");

    let contents = read_or_generate_file(&path, "test key", || Ok("secret".to_string()))
        .expect("generate key file");

    assert_eq!(contents, "secret");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret");
    // The parent directory is created on demand.
    assert!(path.parent().unwrap().is_dir());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "private key material must not be world readable"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_existing_key_file_is_reused_instead_of_regenerated() {
    let dir = scratch_dir("reuse");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.key");
    std::fs::write(&path, "original").unwrap();

    let contents = read_or_generate_file(&path, "test key", || {
        panic!("must not regenerate a key that already exists")
    })
    .expect("read existing key file");

    assert_eq!(contents, "original");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_process_that_loses_the_creation_race_adopts_the_other_key() {
    let dir = scratch_dir("race");
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("test.key");

    // The generator runs before the write, so creating the file from inside it
    // reproduces "another process published the key while we were generating"
    // deterministically.
    let contents = read_or_generate_file(&path, "test key", || {
        std::fs::write(&path, "winner").unwrap();
        Ok("loser".to_string())
    })
    .expect("adopt the key the other process published");

    assert_eq!(
        contents, "winner",
        "the loser must adopt the published key, never overwrite it"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "winner");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_key_file_around_an_unwritable_path_is_an_error_not_a_panic() {
    let path = PathBuf::from("/proc/does/not/exist/test.key");

    let err = read_or_generate_file(&path, "test key", || Ok("secret".to_string()))
        .expect_err("writing under /proc must fail");

    // The error names the operation and the path, so an operator can act on it.
    let message = err.to_string();
    assert!(
        message.contains("create") || message.contains("write"),
        "unexpected error message: {message}"
    );
}
