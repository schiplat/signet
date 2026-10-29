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
