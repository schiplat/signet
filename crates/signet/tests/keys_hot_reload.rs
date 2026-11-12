//! Hot reload of the signing-key ring: rotation done out-of-band (the CLI, or
//! a peer replica sharing the data directory) must reach a running instance on
//! the watcher's next poll, without a restart and without invalidating tokens
//! the old key signed.

use signet::crypto::keys::{reload_ring, JwtKeys};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

fn temp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "signet-keywatch-{}-{}",
        tag,
        uuid::Uuid::new_v4().simple()
    ))
}

/// Boot-shaped setup: a key file on disk plus the ring the instance would hold.
fn boot(dir: &Path) -> JwtKeys {
    let path = dir.join("jwt_private.pem");
    let retired = dir.join("retired_keys");
    JwtKeys::load_or_generate_with_retired(&path, Some(&retired)).expect("boot load")
}

#[test]
fn watcher_reloads_rotation_and_keeps_old_tokens_verifying() {
    let dir = temp_dir("rotate");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("jwt_private.pem");
    let retired = dir.join("retired_keys");

    // Boot: the ring loads (generating the first key) and signs a token.
    let ring = boot(&dir);
    let old_kid = ring.kid.clone();
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        + 3600;
    let token = ring
        .encode(&serde_json::json!({ "sub": "user-1", "exp": exp }))
        .expect("sign with the boot key");

    let keys = Arc::new(arc_swap::ArcSwap::from_pointee(ring));
    let mut prev = None;

    // Production primes `prev` with the boot fingerprint before the loop; the
    // test primes by one reload — the same PEM is on disk, so the ring is
    // rebuilt identically (same kid).
    reload_ring(&keys, &path, &retired, &mut prev);
    assert_eq!(
        keys.load().kid,
        old_kid,
        "priming reload keeps the boot key"
    );
    assert!(
        !reload_ring(&keys, &path, &retired, &mut prev),
        "a steady-state poll is a no-op"
    );

    // Out-of-band rotation, exactly what `signet keys rotate` does.
    let new_kid = signet::crypto::keys::rotate(&path, &retired).expect("rotate");
    assert_ne!(
        keys.load().kid,
        new_kid,
        "rotation is not applied mid-flight"
    );

    // The poll picks the new ring up without a restart.
    assert!(
        reload_ring(&keys, &path, &retired, &mut prev),
        "rotation detected"
    );
    assert_eq!(keys.load().kid, new_kid, "the new key now signs");
    assert_eq!(
        keys.load().jwks().keys.len(),
        2,
        "JWKS publishes active + retired"
    );

    // A token signed before the rotation still verifies (the retired key is in
    // the ring), and an idempotent poll does not swap anything again.
    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    keys.load()
        .verify::<serde_json::Value>(&token, &validation)
        .expect("old token verifies via the retired key");
    assert!(
        !reload_ring(&keys, &path, &retired, &mut prev),
        "steady state"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn missing_key_file_is_ignored_not_regenerated() {
    let dir = temp_dir("missing");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("jwt_private.pem");
    let retired = dir.join("retired_keys");
    let ring = boot(&dir);
    let kid = ring.kid.clone();
    let keys = Arc::new(arc_swap::ArcSwap::from_pointee(ring));
    let mut prev = None;
    reload_ring(&keys, &path, &retired, &mut prev);

    // Operator mid-move, or a transient filesystem hiccup: the file is gone.
    // The watcher must wait, never generate a replacement key.
    std::fs::remove_file(&path).expect("remove the active key");
    assert!(
        !reload_ring(&keys, &path, &retired, &mut prev),
        "missing key file is not a rotation"
    );
    assert_eq!(keys.load().kid, kid, "the current ring is untouched");
    assert!(
        !path.exists(),
        "the poll must not have written a new key file"
    );

    std::fs::remove_dir_all(&dir).ok();
}
