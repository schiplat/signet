//! SCIM PATCH operation semantics.
//!
//! These are pure: interpreting `op`/`path` is deliberately separated from the
//! SQL that applies it (`scim::user_attrs_from_patch`,
//! `scim::group_member_changes`), so the part that was wrong can be pinned down
//! without a database.
//!
//! What went wrong before, and why each test exists:
//!
//! * `op` was not deserialized at all, so every operation was applied as a
//!   write. On the group route a `remove` therefore **added** the member.
//! * A path-qualified operation carries a scalar `value` (Entra's shape), while a
//!   pathless one carries an object (Okta's). Only the object form was read, so
//!   Entra's `{"op":"Replace","path":"active","value":false}` was answered `200`
//!   and ignored — a deprovisioning request that silently did nothing.

use serde_json::{json, Value};
use signet::scim::{
    group_member_changes, group_member_changes_from_body, user_attrs_from_body,
    user_attrs_from_patch, GroupMemberChange, GroupPatchOp, PatchGroupBody, PatchOp, PatchUserBody,
    UserAttrs,
};
use uuid::Uuid;

fn user_ops(value: Value) -> Vec<PatchOp> {
    serde_json::from_value(value).expect("a list of user operations")
}

fn group_ops(value: Value) -> Vec<GroupPatchOp> {
    serde_json::from_value(value).expect("a list of group operations")
}

fn interpreted(value: Value) -> UserAttrs {
    user_attrs_from_patch(&user_ops(value)).expect("the operations should be accepted")
}

// ─── The body's field names ───────────────────────────────────────────────
//
// These go through the *body* types rather than straight to the interpreter,
// which is the layer the earlier tests missed. Every operation above can be
// interpreted perfectly while the route still ignores the request, because the
// list that holds them is deserialised from a name the client did not use.

#[test]
fn the_spelling_real_clients_send_is_read() {
    // `Operations`, capitalised, is what RFC 7644's examples and the IdPs
    // surveyed send. Accepting only `operations` meant the body deserialised to
    // an empty list — no error, because the field is `#[serde(default)]` — and
    // the route answered 200 with the user unchanged.
    let body: PatchUserBody = serde_json::from_value(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{ "op": "replace", "path": "active", "value": false }]
    }))
    .expect("a realistic body");

    assert_eq!(
        user_attrs_from_body(body).expect("accepted").active,
        Some(false),
        "a capitalised `Operations` must not deserialise to nothing"
    );
}

#[test]
fn the_lowercase_spelling_still_works() {
    let body: PatchUserBody = serde_json::from_value(json!({
        "operations": [{ "op": "replace", "path": "active", "value": false }]
    }))
    .expect("a body");

    assert_eq!(
        user_attrs_from_body(body).expect("accepted").active,
        Some(false)
    );
}

#[test]
fn a_group_body_keeps_its_operations_too() {
    let body: PatchGroupBody = serde_json::from_value(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            { "op": "remove", "path": format!("members[value eq \"{}\"]", one_id()) }
        ]
    }))
    .expect("a realistic body");

    assert_eq!(
        group_member_changes_from_body(body).expect("accepted"),
        vec![GroupMemberChange::Remove(vec![one_id()])],
        "the capitalised spelling must reach the interpreter"
    );
}

// ─── Users: reading `path` ────────────────────────────────────────────────

#[test]
fn the_pathless_object_form_is_read() {
    // Okta's shape: no `path`, the attributes are keys of `value`.
    let attrs = interpreted(json!([
        { "op": "replace", "value": { "active": false, "displayName": "Ada L" } }
    ]));

    assert_eq!(attrs.active, Some(false));
    assert_eq!(attrs.display_name.as_deref(), Some("Ada L"));
}

#[test]
fn the_path_qualified_scalar_form_is_read() {
    // Entra's shape, capitalised op included. This is the case that used to be
    // accepted and ignored: `value` is a bare boolean, and reading
    // `op.value.get("active")` on a boolean yields nothing.
    let attrs = interpreted(json!([
        { "op": "Replace", "path": "active", "value": false }
    ]));

    assert_eq!(attrs.active, Some(false));
}

#[test]
fn removing_active_deprovisions_the_user() {
    // One of the standard ways an IdP deactivates a user. It carries no `value`,
    // so before this the operation did nothing at all — the account stayed
    // active while the client was told it succeeded.
    let attrs = interpreted(json!([{ "op": "remove", "path": "active" }]));

    assert_eq!(
        attrs.active,
        Some(false),
        "removing `active` cannot mean \"activate\": the attribute's default is true"
    );
}

#[test]
fn a_schema_qualified_path_resolves_to_its_attribute() {
    let attrs = interpreted(json!([
        {
            "op": "replace",
            "path": "urn:ietf:params:scim:schemas:core:2.0:User:active",
            "value": false
        }
    ]));

    assert_eq!(attrs.active, Some(false));
}

#[test]
fn a_sub_attribute_path_resolves_to_its_leading_attribute() {
    // `emails[type eq "work"].value` must not be mistaken for a top-level
    // attribute named after the filter, and must not error either.
    let attrs = interpreted(json!([
        { "op": "replace", "path": "emails[type eq \"work\"].value", "value": "a@b.c" }
    ]));

    assert_eq!(attrs, UserAttrs::default());
}

#[test]
fn display_name_can_be_set_but_a_remove_leaves_it_alone() {
    let set = interpreted(json!([
        { "op": "replace", "path": "displayName", "value": "  Grace Hopper  " }
    ]));
    assert_eq!(set.display_name.as_deref(), Some("Grace Hopper"), "trimmed");

    // `users.display_name` is NOT NULL: there is nothing to unassign, and
    // failing an IdP's sync over that would be worse than ignoring it.
    let removed = interpreted(json!([{ "op": "remove", "path": "displayName" }]));
    assert_eq!(removed.display_name, None, "None means \"leave as it is\"");
}

#[test]
fn a_partial_patch_leaves_the_attributes_it_omits_alone() {
    // `None` is not "set to empty": the handler falls back to the stored value.
    // Reading an omitted attribute as a default is how a PATCH turns into a PUT.
    let attrs = interpreted(json!([
        { "op": "replace", "value": { "displayName": "Only This" } }
    ]));

    assert_eq!(attrs.active, None);
    assert_eq!(attrs.display_name.as_deref(), Some("Only This"));
}

#[test]
fn no_operations_change_nothing() {
    assert_eq!(interpreted(json!([])), UserAttrs::default());
}

#[test]
fn an_empty_op_name_is_treated_as_a_replace() {
    // Some clients omit `op`. Defaulting is safer than rejecting, and `replace`
    // is what a bare value means.
    let attrs = interpreted(json!([{ "value": { "active": false } }]));

    assert_eq!(attrs.active, Some(false));
}

// ─── Users: refusing to guess ─────────────────────────────────────────────

#[test]
fn an_unrecognised_op_is_rejected_rather_than_guessed() {
    let err = user_attrs_from_patch(&user_ops(json!([
        { "op": "frobnicate", "path": "active", "value": false }
    ])))
    .expect_err("an unknown op must not be interpreted as something else");

    assert!(err.to_string().contains("frobnicate"), "got: {err}");
}

#[test]
fn a_non_boolean_active_is_rejected() {
    // The alternative is coercing `"yes"` or `{}` into a status, which is how a
    // user ends up activated by a typo.
    let err = user_attrs_from_patch(&user_ops(json!([
        { "op": "replace", "path": "active", "value": "yes" }
    ])))
    .expect_err("`yes` is not a boolean");

    assert!(err.to_string().contains("active"), "got: {err}");
}

#[test]
fn the_string_spellings_of_a_boolean_are_accepted() {
    let attrs = interpreted(json!([
        { "op": "replace", "path": "active", "value": "false" }
    ]));

    assert_eq!(attrs.active, Some(false));
}

#[test]
fn attributes_with_no_column_are_ignored_rather_than_failing_the_sync() {
    // A PATCH routinely carries attributes Signet does not store. 400ing would
    // fail the whole operation, including the parts we do support.
    let attrs = interpreted(json!([
        { "op": "replace", "path": "name.givenName", "value": "Ada" },
        { "op": "replace", "path": "active", "value": false }
    ]));

    assert_eq!(attrs.active, Some(false));
}

// ─── Groups ───────────────────────────────────────────────────────────────

fn one_id() -> Uuid {
    Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap()
}

#[test]
fn removing_a_member_from_a_group_removes_them() {
    // The headline bug: every operation was applied as an add, so this request
    // put the named user *into* the group. Inverted, and silent.
    let changes = group_member_changes(&group_ops(json!([
        {
            "op": "remove",
            "path": format!("members[value eq \"{}\"]", one_id())
        }
    ])))
    .expect("accepted");

    assert_eq!(changes, vec![GroupMemberChange::Remove(vec![one_id()])]);
}

#[test]
fn a_filter_only_removal_names_exactly_one_member() {
    // Okta sends no `value` array here. Not reading the filter would make this
    // indistinguishable from "remove every member" — dropping the group's whole
    // membership instead of one person's.
    let changes = group_member_changes(&group_ops(json!([
        { "op": "remove", "path": format!("members[value eq \"{}\"]", one_id()) }
    ])))
    .expect("accepted");

    match &changes[..] {
        [GroupMemberChange::Remove(ids)] => assert_eq!(ids.len(), 1, "not everyone"),
        other => panic!("expected one removal, got {other:?}"),
    }
}

#[test]
fn a_remove_with_nothing_selected_clears_the_membership() {
    let changes = group_member_changes(&group_ops(json!([{ "op": "remove", "path": "members" }])))
        .expect("accepted");

    assert_eq!(changes, vec![GroupMemberChange::Remove(Vec::new())]);
}

#[test]
fn replace_becomes_a_replace_not_an_add() {
    // `replace` on the members attribute means "the membership is now this list",
    // so members not named have to go.
    let changes = group_member_changes(&group_ops(json!([
        { "op": "replace", "path": "members", "value": [{ "value": one_id() }] }
    ])))
    .expect("accepted");

    assert_eq!(changes, vec![GroupMemberChange::Replace(vec![one_id()])]);
}

#[test]
fn add_still_adds() {
    let changes = group_member_changes(&group_ops(json!([
        { "op": "Add", "path": "members", "value": [{ "value": one_id() }] }
    ])))
    .expect("accepted");

    assert_eq!(changes, vec![GroupMemberChange::Add(vec![one_id()])]);
}

#[test]
fn several_group_operations_keep_their_order() {
    // Order matters: the handler applies them in sequence, so a remove followed
    // by an add must not be reordered into an add followed by a remove.
    let other = Uuid::parse_str("99999999-8888-7777-6666-555555555555").unwrap();
    let changes = group_member_changes(&group_ops(json!([
        { "op": "remove", "path": format!("members[value eq \"{}\"]", one_id()) },
        { "op": "add", "path": "members", "value": [{ "value": other }] }
    ])))
    .expect("accepted");

    assert_eq!(
        changes,
        vec![
            GroupMemberChange::Remove(vec![one_id()]),
            GroupMemberChange::Add(vec![other]),
        ]
    );
}

#[test]
fn an_unrecognised_group_op_is_rejected() {
    let err = group_member_changes(&group_ops(json!([
        { "op": "merge", "path": "members", "value": [{ "value": one_id() }] }
    ])))
    .expect_err("an unknown op must not be applied as an add");

    assert!(err.to_string().contains("merge"), "got: {err}");
}
