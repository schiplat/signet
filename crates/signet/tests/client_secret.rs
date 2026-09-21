//! Client-secret storage: the digest form, and the upgrade off legacy Argon2.
//!
//! `/oauth/token` verifies a client secret on every request, so it is stored as
//! a keyed digest instead of an Argon2 hash. These tests pin the parts that
//! would be dangerous to get wrong: that a wrong secret never passes, that a
//! digest from another deployment's key never passes, and that a row still
//! holding an Argon2 hash is both accepted *and* rewritten — the upgrade is what
//! makes an existing deployment converge onto the fast path without anyone
//! rotating a secret by hand.

mod common;

use signet::auth::client_secret::{constant_time_eq, digest, is_digest, verify};
use uuid::Uuid;

/// Plants an enabled client app whose secret is stored in the given form.
async fn client_with_hash(state: &signet::state::AppState, secret_hash: &str) -> String {
    let client_id = format!("cl_test_{}", Uuid::new_v4().simple());
    sqlx::query(
        r#"
        INSERT INTO client_apps (id, client_id, client_secret_hash, redirect_uris)
        VALUES ($1, $2, $3, ARRAY['https://example.invalid/cb'])
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&client_id)
    .bind(secret_hash)
    .execute(&state.pool)
    .await
    .expect("insert a client app");
    client_id
}

async fn stored_hash(state: &signet::state::AppState, client_id: &str) -> String {
    sqlx::query_scalar("SELECT client_secret_hash FROM client_apps WHERE client_id = $1")
        .bind(client_id)
        .fetch_one(&state.pool)
        .await
        .expect("read the stored hash")
}

async fn remove(state: &signet::state::AppState, client_id: &str) {
    let _ = sqlx::query("DELETE FROM client_apps WHERE client_id = $1")
        .bind(client_id)
        .execute(&state.pool)
        .await;
}

#[test]
fn a_digest_is_recognizable_and_stable() {
    let key = [7u8; 32];
    let stored = digest(&key, "a-generated-secret");
    assert!(is_digest(&stored), "the stored form marks its own scheme");
    assert_eq!(stored, digest(&key, "a-generated-secret"));
}

#[test]
fn a_digest_from_another_key_does_not_match() {
    // The pepper is the whole reason a fast digest is acceptable here: an
    // attacker with the table alone cannot test a guess, because testing it
    // means running this comparison, which needs the key.
    assert_ne!(digest(&[1u8; 32], "hunter2"), digest(&[2u8; 32], "hunter2"));
}

#[test]
fn an_argon2_hash_is_not_mistaken_for_a_digest() {
    assert!(!is_digest("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"));
}

#[test]
fn digests_compare_without_stopping_at_the_first_difference() {
    assert!(constant_time_eq(b"abcdef", b"abcdef"));
    assert!(!constant_time_eq(b"abcdef", b"abcdeff"), "length differs");
    assert!(!constant_time_eq(b"abcdef", b"abcdeg"), "last byte differs");
    assert!(
        !constant_time_eq(b"abcdef", b"ABCDEF"),
        "first byte differs"
    );
}

#[tokio::test]
async fn a_generated_secret_verifies_against_its_digest() {
    let Some(state) = common::state().await else {
        return;
    };
    let secret = "8Vd2mQk0xR7pL1nT4wZbYcEfHgJiKlMnOpQrStUvWx";
    let client_id = client_with_hash(&state, &digest(&state.client_secret_key, secret)).await;

    assert!(
        verify(
            &state,
            &client_id,
            secret,
            &stored_hash(&state, &client_id).await
        )
        .await
        .expect("verify"),
        "the secret it was made from has to pass"
    );
    assert!(
        !verify(
            &state,
            &client_id,
            "the-wrong-secret-entirely",
            &stored_hash(&state, &client_id).await
        )
        .await
        .expect("verify"),
        "and nothing else may"
    );

    remove(&state, &client_id).await;
}

#[tokio::test]
async fn a_legacy_argon2_secret_is_accepted_and_rewritten_as_a_digest() {
    let Some(state) = common::state().await else {
        return;
    };
    // An admin-supplied secret is short and guessable, which is exactly the case
    // where the Argon2 hash used to matter. It must still verify after the
    // upgrade — the pepper, not the KDF, is what protects it from here on.
    let secret = "short-but-fine!";
    let legacy = signet::auth::password::hash_password(secret).expect("hash");
    let client_id = client_with_hash(&state, &legacy).await;

    assert!(
        verify(&state, &client_id, secret, &legacy)
            .await
            .expect("verify"),
        "a legacy row still signs in"
    );

    let after = stored_hash(&state, &client_id).await;
    assert!(
        is_digest(&after),
        "and the row was rewritten in the digest form, got {after}"
    );
    assert!(!after.starts_with("$argon2"), "the argon2 hash is gone");

    // The rewritten row is what the next sign-in reads, so it has to work too.
    assert!(
        verify(&state, &client_id, secret, &after)
            .await
            .expect("verify"),
        "the upgraded row verifies on its own"
    );
    assert!(
        !verify(&state, &client_id, "short-but-fine?", &after)
            .await
            .expect("verify"),
        "a near miss must not pass against the upgraded row"
    );

    remove(&state, &client_id).await;
}

#[tokio::test]
async fn a_wrong_secret_does_not_upgrade_the_row() {
    let Some(state) = common::state().await else {
        return;
    };
    // If a failed attempt rewrote the row, a wrong guess would destroy the
    // credential — the account would be bricked rather than merely refused.
    let legacy = signet::auth::password::hash_password("the-real-secret").expect("hash");
    let client_id = client_with_hash(&state, &legacy).await;

    assert!(
        !verify(&state, &client_id, "the-wrong-secret", &legacy)
            .await
            .expect("verify"),
        "the wrong secret is refused"
    );
    assert_eq!(
        stored_hash(&state, &client_id).await,
        legacy,
        "and the stored hash is left exactly as it was"
    );

    remove(&state, &client_id).await;
}
