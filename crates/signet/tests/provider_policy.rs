//! Per-provider JIT and email-trust resolution.
//!
//! The global JIT toggle cannot express "the corporate Feishu tenant may
//! auto-create accounts, GitHub — where anyone registers — may only link".
//! The provider row's `jit_mode` / `email_trust` carry that decision; these
//! tests pin how they resolve, because the resolution is exactly two match
//! arms and exactly the place where an inverted arm would silently open or
//! close an account-creation path.

use signet::federation::provider::{effective_email_verified, effective_jit};

#[test]
fn jit_inherit_follows_the_global_toggle() {
    assert!(effective_jit("inherit", true));
    assert!(!effective_jit("inherit", false));
}

#[test]
fn jit_on_and_off_override_the_global_toggle() {
    assert!(effective_jit("on", false), "provider on beats global off");
    assert!(!effective_jit("off", true), "provider off beats global on");
    assert!(effective_jit("on", true));
    assert!(!effective_jit("off", false));
}

/// The column has a CHECK constraint; a stray value degrades to `inherit`
/// rather than to a permissive default.
#[test]
fn an_unknown_jit_mode_degrades_to_inherit() {
    assert!(!effective_jit("", false));
    assert!(effective_jit("", true));
    assert!(!effective_jit("ON", false), "values are lowercase, no trim");
}

#[test]
fn email_trust_any_treats_a_bare_address_as_verified() {
    assert!(effective_email_verified("any", false, true));
    assert!(!effective_email_verified("any", false, false));
    assert!(effective_email_verified("any", true, true));
}

#[test]
fn email_trust_inherit_and_verified_defer_to_the_adapter() {
    // The honest adapters (github/google/oidc) report a real flag; both modes
    // pass it through unchanged.
    assert!(effective_email_verified("inherit", true, true));
    assert!(!effective_email_verified("inherit", false, true));
    assert!(effective_email_verified("verified", true, true));
    assert!(!effective_email_verified("verified", false, true));

    // The Feishu adapter now reports false; under `verified` that keeps it
    // pending-link-only, which is the point of the mode.
    assert!(!effective_email_verified("verified", false, true));
}

/// A provider whose adapter reported nothing verified never auto-links, no
/// matter how loose the trust setting.
#[test]
fn no_email_is_never_verified() {
    assert!(!effective_email_verified("any", true, false));
    assert!(!effective_email_verified("inherit", false, false));
}
