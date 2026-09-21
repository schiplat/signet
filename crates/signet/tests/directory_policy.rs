//! Contract tests for the directory ownership policy (docs/directory-sync.md §5).
//!
//! Only the pure policy surface is covered here. `managing_source` is a
//! database query and needs the DB-backed harness rather than a unit test.

use signet::authority::Authority;

/// The directory authority, as the guards construct it from a source code.
fn directory() -> Authority {
    Authority::Directory("corp-ldap".to_string())
}

/// The other upstream, which owns a smaller set of fields.
fn scim() -> Authority {
    Authority::Scim
}

#[test]
fn directory_owned_fields_match_the_design_table() {
    assert_eq!(
        directory().managed_fields(),
        &["email", "username", "display_name", "directory_groups"]
    );
}

#[test]
fn directory_owned_fields_are_refused() {
    for field in ["email", "username", "display_name", "directory_groups"] {
        let msg = directory()
            .write_error(field)
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
            directory().write_error(field).is_none(),
            "{field} must remain locally editable"
        );
    }
}

#[test]
fn unknown_fields_are_not_assumed_directory_owned() {
    // Defaulting to "allowed" is deliberate: a typo in a caller must fail open
    // on a *local* field rather than lock admins out of an unrelated attribute.
    assert!(directory().write_error("something_new").is_none());
}

#[test]
fn delete_is_refused_with_a_usable_remedy() {
    let msg = directory().delete_error();
    assert!(msg.contains("corp-ldap"), "{msg}");
    assert!(
        msg.contains("disable"),
        "the message must point at the supported alternative: {msg}"
    );
}

#[test]
fn scim_owns_the_attributes_it_provisions() {
    assert_eq!(
        scim().managed_fields(),
        &["email", "username", "display_name"]
    );
}

#[test]
fn scim_does_not_own_membership_or_the_local_intent() {
    // Two deliberate omissions. `directory_groups` is the directory's separate
    // membership column — SCIM still writes `users.groups`, so claiming it would
    // fail local group edits against a value SCIM overwrites. `local_disabled`
    // and the MFA settings stay locally owned for a SCIM user as much as for a
    // directory one: an upstream disable is a different intent (migration `026`).
    for field in [
        "directory_groups",
        "groups",
        "local_disabled",
        "status",
        "role",
        "phone",
        "mfa_required",
    ] {
        assert!(
            scim().write_error(field).is_none(),
            "{field} must stay locally editable for a SCIM-managed user"
        );
    }
}

#[test]
fn a_scim_delete_is_refused_with_a_usable_remedy() {
    let msg = scim().delete_error();
    assert!(msg.contains("SCIM"), "{msg}");
    assert!(
        msg.contains("disable"),
        "the message must point at the supported alternative: {msg}"
    );
}

#[test]
fn the_two_authorities_are_told_apart_in_messages_and_audit() {
    // A source code is operator-chosen and `scim` is even a valid source *kind*,
    // so the codes have to stay distinguishable or a refusal would not say who
    // refused it.
    assert_eq!(directory().code(), "corp-ldap");
    assert_eq!(scim().code(), "scim");
    assert!(directory()
        .write_error("email")
        .unwrap()
        .contains("corp-ldap"));
    assert!(!scim().write_error("email").unwrap().contains("corp-ldap"));
}
