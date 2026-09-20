//! Contract tests for the directory ownership policy (docs/directory-sync.md §5).
//!
//! Only the pure policy surface is covered here. `managing_source` is a
//! database query and needs the DB-backed harness rather than a unit test.

use signet::directory::{managed_delete_error, managed_write_error, DIRECTORY_OWNED_FIELDS};

#[test]
fn directory_owned_fields_match_the_design_table() {
    assert_eq!(
        DIRECTORY_OWNED_FIELDS,
        &["email", "username", "display_name", "directory_groups"]
    );
}

#[test]
fn directory_owned_fields_are_refused() {
    for field in ["email", "username", "display_name", "directory_groups"] {
        let msg = managed_write_error("corp-ldap", field)
            .unwrap_or_else(|| panic!("{field} must be refused for a managed user"));
        assert!(msg.contains(field), "message must name the field: {msg}");
        assert!(
            msg.contains("corp-ldap"),
            "message must name the source so an admin knows where to change it: {msg}"
        );
    }
}

#[test]
fn locally_owned_fields_are_still_writable() {
    // Everything the §5 table marks as locally owned (or locally overridable)
    // must pass through untouched, otherwise P1 would silently break these
    // admin flows.
    for field in [
        "role",
        "phone",
        "groups",
        "status",
        "local_disabled",
        "password_hash",
        "must_change_password",
        "mfa_required",
        "totp_enabled",
        "totp_secret",
        "provisioned_via",
    ] {
        assert!(
            managed_write_error("corp-ldap", field).is_none(),
            "{field} must remain locally editable"
        );
    }
}

#[test]
fn unknown_fields_are_not_assumed_directory_owned() {
    // Defaulting to "allowed" is deliberate: a typo in a caller must fail open
    // on a *local* field rather than lock admins out of an unrelated attribute.
    assert!(managed_write_error("corp-ldap", "something_new").is_none());
}

#[test]
fn delete_is_refused_with_a_usable_remedy() {
    let msg = managed_delete_error("corp-ldap");
    assert!(msg.contains("corp-ldap"), "{msg}");
    assert!(
        msg.contains("disable"),
        "the message must point at the supported alternative: {msg}"
    );
}
