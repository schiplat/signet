//! The instance's own JWT round trip: a token it signs must pass its own
//! `decoding()` key — the check userinfo performs on every bearer request.
//!
//! `DecodingKey::from_rsa_pem` was found to produce a key that fails
//! verification of its own signatures (ring on aarch64), which 401'd every
//! userinfo call while all JWKS-based client paths kept working. The fix
//! builds the decoding key from the public components; this test pins that
//! property so the construction cannot silently regress.

use jsonwebtoken::{decode, Algorithm, Validation};
use serde::Deserialize;
use signet::crypto::keys::JwtKeys;

#[derive(Deserialize)]
struct Claims {
    sub: String,
}

#[test]
fn a_token_the_instance_signs_passes_its_own_decoding_key() {
    let path = std::env::temp_dir().join(format!("signet-jwt-{}.pem", uuid::Uuid::new_v4()));
    let keys = JwtKeys::load_or_generate(&path).expect("keys");

    let now = chrono::Utc::now().timestamp();
    let token = keys
        .encode(&serde_json::json!({
            "sub": "roundtrip-sub",
            "iss": "https://sso.example.com",
            "aud": "some-client",
            "exp": now + 3600,
            "iat": now,
        }))
        .expect("sign jwt");

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["https://sso.example.com"]);
    validation.validate_aud = false;
    let data = decode::<Claims>(&token, keys.decoding(), &validation).expect("decode own token");
    assert_eq!(data.claims.sub, "roundtrip-sub");

    std::fs::remove_file(&path).ok();
}

/// Rotation must not invalidate tokens already issued.
///
/// `signet keys rotate` writes the old key as a public PEM into the retired
/// directory and replaces the active file. A restarted instance loads both:
/// it signs with the new key and still verifies tokens whose `kid` names the
/// old one, and JWKS publishes both so clients can do the same.
#[test]
fn rotation_keeps_old_tokens_verifiable() {
    let dir = std::env::temp_dir().join(format!("signet-keys-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("jwt_private.pem");
    let retired = dir.join("retired_keys");

    let original = JwtKeys::load_or_generate(&path).expect("initial keys");
    let now = chrono::Utc::now().timestamp();
    let old_token = original
        .encode(&serde_json::json!({
            "sub": "before-rotation",
            "iss": "https://sso.example.com",
            "aud": "some-client",
            "exp": now + 3600,
            "iat": now,
        }))
        .expect("sign jwt");
    let old_kid = original.kid.clone();

    let new_kid = signet::crypto::keys::rotate(&path, &retired).expect("rotate");
    assert_ne!(new_kid, old_kid, "rotation must produce a new kid");

    let rotated = JwtKeys::load_or_generate_with_retired(&path, Some(&retired))
        .expect("reload after rotation");
    assert_eq!(rotated.kid, new_kid);

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["https://sso.example.com"]);
    validation.validate_aud = false;
    let data = rotated
        .verify::<Claims>(&old_token, &validation)
        .expect("a token signed before the rotation must still verify");
    assert_eq!(data.claims.sub, "before-rotation");

    // JWKS carries both, so a client can follow the same rule.
    let jwks = rotated.jwks();
    let kids: Vec<&str> = jwks.keys.iter().map(|k| k.kid.as_str()).collect();
    assert_eq!(kids.len(), 2, "active plus one retired key");
    assert!(kids.contains(&new_kid.as_str()));
    assert!(kids.contains(&old_kid.as_str()));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Pruning keeps the newest retired keys and nothing older.
#[test]
fn pruning_retired_keys_keeps_the_newest() {
    let dir = std::env::temp_dir().join(format!("signet-prune-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("jwt_private.pem");
    let retired = dir.join("retired_keys");
    let _ = JwtKeys::load_or_generate(&path).expect("initial keys");

    // Two rotations produce two retired keys; stagger mtimes so "newest" is
    // deterministic regardless of filesystem timestamp resolution.
    let first = signet::crypto::keys::rotate(&path, &retired).expect("rotate 1");
    std::thread::sleep(std::time::Duration::from_millis(20));
    let second = signet::crypto::keys::rotate(&path, &retired).expect("rotate 2");
    assert_ne!(first, second);

    let count = || {
        std::fs::read_dir(&retired)
            .expect("retired dir")
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("pem"))
            .count()
    };
    assert_eq!(count(), 2);

    let removed = signet::crypto::keys::prune_retired(&retired, 1).expect("prune");
    assert_eq!(removed, 1);
    assert_eq!(count(), 1);

    // `rotate` returns the *new active* kid; the file it retires is the
    // previous active key. So after two rotations the retired set is
    // {original, first}, and the newest is `first`.
    // The ring still loads: a pruned key only drops tokens older than the
    // retained window.
    let survivors: Vec<String> = std::fs::read_dir(&retired)
        .expect("retired dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(survivors, vec![format!("{first}.pem")]);
    let _ = JwtKeys::load_or_generate_with_retired(&path, Some(&retired)).expect("reload");

    let _ = std::fs::remove_dir_all(&dir);
}
