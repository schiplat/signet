//! TOTP verification against a real authenticator-shaped code.
//!
//! The unit surface (`verify_totp_code_step`) is what the login and enrollment
//! paths call. Nothing else in the suite produces a live code, which is how a
//! wrong `generate(time)` unit slipped through: the server was comparing against
//! codes for 1970 and every real enrollment failed. This test generates a code
//! the way an authenticator does and asserts both the accept window and its
//! bounds.

use signet::mfa::{code_for_step, new_totp_secret_for_tests, verify_totp_code_step};

fn current_step() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        / 30
}

#[test]
fn a_live_code_verifies_and_returns_its_step() {
    let secret = new_totp_secret_for_tests();
    let step = current_step();
    let code = code_for_step(&secret, step).expect("generate code");
    let matched = verify_totp_code_step(&secret, &code).expect("verify");
    assert!(
        matched.is_some(),
        "a code for the current step must verify (step {step})"
    );
}

#[test]
fn the_window_is_one_step_either_side() {
    let secret = new_totp_secret_for_tests();
    let step = current_step();

    // One step back/forward is inside the skew window; five steps away is not.
    for offset in [-1i64, 1] {
        let near = (step as i64 + offset).max(0) as u64;
        let code = code_for_step(&secret, near).expect("generate");
        assert!(
            verify_totp_code_step(&secret, &code)
                .expect("verify")
                .is_some(),
            "offset {offset} must be accepted"
        );
    }
    let far = step.saturating_sub(5);
    let code = code_for_step(&secret, far).expect("generate");
    assert!(
        verify_totp_code_step(&secret, &code)
            .expect("verify")
            .is_none(),
        "a five-step-old code must be refused"
    );
}

#[test]
fn malformed_codes_are_refused_without_a_crypto_error() {
    let secret = new_totp_secret_for_tests();
    for bad in ["", "12345", "abcdef", "1234567"] {
        assert_eq!(
            verify_totp_code_step(&secret, bad).expect("no error"),
            None,
            "{bad:?} must not verify"
        );
    }
}
