//! The OIDC `groups` claim and the local/directory split
//! (docs/directory-sync.md §6.5).
//!
//! Local groups and directory-sourced groups live in separate columns so a sync
//! cannot clobber a group an admin assigned by hand, but clients only ever see
//! one list. These tests pin the merge that produces it — the property that
//! matters is that the two sources are combined without duplicating a group that
//! appears in both.

use signet::models::effective_groups;

fn v(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn local_and_directory_groups_are_merged() {
    assert_eq!(
        effective_groups(&v(&["admins"]), &v(&["staff", "eng"])),
        v(&["admins", "eng", "staff"])
    );
}

/// A group present in both columns must appear once: a client authorizing on the
/// claim should not have to deduplicate it, and a duplicate would look like two
/// memberships to anything doing a count.
#[test]
fn a_group_in_both_columns_appears_once() {
    assert_eq!(
        effective_groups(&v(&["staff", "ops"]), &v(&["staff"])),
        v(&["ops", "staff"])
    );
}

/// The claim is emitted on every token and userinfo response, and clients
/// commonly diff it to drive authorization. Postgres does not preserve `TEXT[]`
/// order across an `UPDATE`, so the output must be canonical regardless of the
/// order in either column.
#[test]
fn the_claim_is_canonical_regardless_of_stored_order() {
    let a = effective_groups(&v(&["b", "a"]), &v(&["d", "c"]));
    let b = effective_groups(&v(&["a", "b"]), &v(&["c", "d"]));
    assert_eq!(
        a, b,
        "the claim must not change when only storage order does"
    );
    assert_eq!(a, v(&["a", "b", "c", "d"]));
}

#[test]
fn empty_and_blank_entries_do_not_leak_into_the_claim() {
    // A blank group is not a membership, and emitting `""` would put a nameless
    // entry in front of every client.
    assert_eq!(
        effective_groups(&v(&["  ", ""]), &v(&[" staff "])),
        v(&["staff"])
    );
    assert_eq!(effective_groups(&[], &[]), Vec::<String>::new());
}

/// Group sync can be turned off per source (`sync_groups`), in which case only
/// local groups exist and the claim must still work.
#[test]
fn a_user_with_only_local_groups_keeps_its_claim() {
    assert_eq!(effective_groups(&v(&["admins"]), &[]), v(&["admins"]));
}

/// Conversely, a directory-provisioned user has no local groups: the claim must
/// still reflect what the directory assigned.
#[test]
fn a_user_with_only_directory_groups_gets_a_claim() {
    assert_eq!(effective_groups(&[], &v(&["staff"])), v(&["staff"]));
}
