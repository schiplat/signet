//! Contract tests for the mapping preview (§13).
//!
//! The preview is pure — no database, no network — so these run everywhere and
//! pin down the three things that make it worth having:
//!
//! 1. It reads the sample through the *same* code the sync uses, so it cannot
//!    promise something a run would not do.
//! 2. It names the row that is wrong, not just "the config is invalid".
//! 3. It never turns an unverifiable check into a silent pass: "no sample" and
//!    "best-effort groups" are reported as such rather than shown as success.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

use base64::Engine;
use serde_json::json;
use signet::directory::mapping::{
    preview, PreviewRequest, MAX_SAMPLE_BYTES, ROW_DISPLAY_NAME, ROW_EMAIL, ROW_EXTERNAL_ID,
    ROW_GROUPS, ROW_SCOPE, ROW_USERNAME,
};

fn ldap_config() -> serde_json::Value {
    json!({
        "url": "ldaps://ldap.corp.example:636",
        "bind_dn": "cn=svc,ou=svc,dc=corp,dc=example",
        "base_dn": "ou=people,dc=corp,dc=example",
        "username_attribute": "uid",
        "email_attribute": "mail",
        "display_name_attribute": "displayName",
        "external_id_attribute": "entryUUID",
        "group_base_dn": "ou=groups,dc=corp,dc=example"
    })
}

fn http_config() -> serde_json::Value {
    json!({
        "url": "https://api.corp.example/v1/users",
        "users_path": "data.users",
        "external_id_path": "id",
        "email_path": "email",
        "username_path": "login",
        "display_name_path": "name",
        "groups_path": "groups"
    })
}

fn ldap_request(sample: Option<&str>) -> PreviewRequest {
    PreviewRequest {
        kind: "ldap".into(),
        config: ldap_config(),
        sample: sample.map(str::to_string),
        sync_groups: Some(true),
        offset: None,
    }
}

fn http_request(sample: Option<&str>) -> PreviewRequest {
    PreviewRequest {
        kind: "http_json".into(),
        config: http_config(),
        sample: sample.map(str::to_string),
        sync_groups: Some(true),
        offset: None,
    }
}

/// The same request, asking for a later page of the row table.
fn http_page(sample: &str, offset: usize) -> PreviewRequest {
    PreviewRequest {
        offset: Some(offset),
        ..http_request(Some(sample))
    }
}

/// The LDAP equivalent of `http_page`.
fn ldap_page(sample: &str, offset: usize) -> PreviewRequest {
    PreviewRequest {
        offset: Some(offset),
        ..ldap_request(Some(sample))
    }
}

/// `n` user entries shaped like `ldapsearch -LLL` output.
///
/// `name_from` is the first index that carries a `displayName`, so a caller can
/// put the only instance of an attribute beyond the first page.
fn ldif_users(n: usize, name_from: Option<usize>) -> String {
    (0..n)
        .map(|i| {
            let name = match name_from {
                Some(from) if i >= from => format!("displayName: User {i}\n"),
                _ => String::new(),
            };
            format!(
                "dn: uid=user{i},ou=people,dc=corp,dc=example\n\
                 uid: user{i}\n\
                 mail: user{i}@corp.example\n\
                 entryUUID: 11111111-2222-3333-4444-{i:012}\n\
                 {name}\n"
            )
        })
        .collect()
}

/// Two users and one group, shaped like `ldapsearch -LLL` output.
const LDIF_USERS_AND_GROUP: &str = "\
dn: uid=ada,ou=people,dc=corp,dc=example
uid: ada
mail: Ada@Corp.Example
displayName: Ada Lovelace
entryUUID: 8f1c0b1e-3a2f-4d5e-9a7b-2c1d0e9f8a7b

dn: uid=grace,ou=people,dc=corp,dc=example
uid: grace
mail: grace@corp.example
entryUUID: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d

dn: cn=eng,ou=groups,dc=corp,dc=example
cn: eng
member: uid=ada,ou=people,dc=corp,dc=example
member: uid=grace,ou=people,dc=corp,dc=example
";

fn field<'a>(
    preview: &'a signet::directory::mapping::MappingPreview,
    row: &str,
) -> &'a signet::directory::mapping::PreviewField {
    preview
        .fields
        .iter()
        .find(|f| f.row == row)
        .unwrap_or_else(|| panic!("preview reported no `{row}` row"))
}

// ─── LDIF parsing ─────────────────────────────────────────────────────────

#[test]
fn a_wrapped_value_is_rejoined_rather_than_split_into_attributes() {
    // ldapsearch folds at 76 columns. An unhandled fold turns one long value
    // into a bogus attribute, which is the failure this parser exists to stop.
    let ldif = "\
dn: uid=ada,ou=people,dc=corp,dc=example
uid: ada
description: a value long enough that ldapsearch would wrap it at seventy-six
 columns and continue on the next line
entryUUID: 8f1c0b1e-3a2f-4d5e-9a7b-2c1d0e9f8a7b
";
    let req = ldap_request(Some(ldif));
    let preview = preview(&req).expect("preview");
    assert_eq!(preview.entry_count, 1);
    assert!(
        field(&preview, ROW_EXTERNAL_ID).ok,
        "the folded attribute must not disturb the following line"
    );
    // The folded attribute itself is visible as a single target.
    assert!(preview.targets.iter().any(|t| t.key == "description"));
    assert!(
        !preview.targets.iter().any(|t| t.key == "columns"),
        "the continuation line must not become its own attribute: {:?}",
        preview.targets.iter().map(|t| &t.key).collect::<Vec<_>>()
    );
}

#[test]
fn base64_text_values_are_decoded() {
    // `ldapsearch` base64-encodes any value with non-ASCII bytes.
    let ldif = "\
dn: uid=ada,ou=people,dc=corp,dc=example
uid: ada
displayName:: w4XDn8O2
entryUUID: 8f1c0b1e-3a2f-4d5e-9a7b-2c1d0e9f8a7b
";
    let preview = preview(&ldap_request(Some(ldif))).expect("preview");
    assert_eq!(preview.rows.len(), 1);
    assert_eq!(preview.rows[0].display_name, "Åßö");
}

#[test]
fn a_binary_attribute_still_renders_as_a_guid() {
    // AD hands back `objectGUID` as 16 raw bytes, which ldapsearch prints as
    // `objectGUID:: <base64>`. The preview has to decode it and run it through
    // the same GUID formatting the sync uses, or an AD admin would be shown a
    // base64 blob where a GUID is expected — and conclude their mapping is fine
    // when the stored id is not what they think.
    let bytes: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut config = ldap_config();
    config["external_id_attribute"] = json!("objectGUID");
    let ldif = format!(
        "dn: CN=Ada,OU=People,DC=corp,DC=example\n\
         sAMAccountName: ada\n\
         mail: ada@corp.example\n\
         objectGUID:: {encoded}\n"
    );
    let req = PreviewRequest {
        kind: "ldap".into(),
        config,
        sample: Some(ldif),
        sync_groups: Some(true),
        offset: None,
    };
    let preview = preview(&req).expect("preview");
    assert_eq!(preview.rows.len(), 1);
    // MS-DTYP stores the first three fields little-endian.
    assert_eq!(
        preview.rows[0].external_id,
        "04030201-0605-0807-090a-0b0c0d0e0f10"
    );
    assert!(field(&preview, ROW_EXTERNAL_ID).ok);
}

#[test]
fn comments_and_the_version_header_are_ignored() {
    let ldif = "\
version: 1
# an LDIF file header, not an attribute

dn: uid=ada,ou=people,dc=corp,dc=example
uid: ada
mail: ada@corp.example
entryUUID: 8f1c0b1e-3a2f-4d5e-9a7b-2c1d0e9f8a7b
";
    let preview = preview(&ldap_request(Some(ldif))).expect("preview");
    assert_eq!(preview.entry_count, 1);
    assert!(!preview.targets.iter().any(|t| t.key == "version"));
    assert!(!preview.targets.iter().any(|t| t.key.starts_with('#')));
}

#[test]
fn a_malformed_attribute_line_names_its_line_number() {
    let ldif = "\
dn: uid=ada,ou=people,dc=corp,dc=example
uid: ada
this line has no colon
";
    let err = preview(&ldap_request(Some(ldif))).expect_err("a malformed line must not be skipped");
    let message = err.to_string();
    assert!(message.contains("LDIF line 3"), "got: {message}");
}

#[test]
fn a_url_valued_attribute_is_refused_rather_than_shown_empty() {
    // `name:< file:///…` cannot be honoured from a paste, and rendering it as an
    // empty value would make the preview lie about what the attribute holds.
    let ldif = "\
dn: uid=ada,ou=people,dc=corp,dc=example
uid: ada
jpegPhoto:< file:///tmp/ada.jpg
";
    let err = preview(&ldap_request(Some(ldif))).expect_err("URL values must be refused");
    assert!(err.to_string().contains("URL-valued"));
}

#[test]
fn attribute_names_are_matched_case_insensitively() {
    // Servers do not reliably echo the casing that was requested.
    let ldif = "\
dn: uid=ada,ou=people,dc=corp,dc=example
UID: ada
MAIL: ada@corp.example
DISPLAYNAME: Ada Lovelace
entryuuid: 8f1c0b1e-3a2f-4d5e-9a7b-2c1d0e9f8a7b
";
    let preview = preview(&ldap_request(Some(ldif))).expect("preview");
    assert_eq!(preview.rows.len(), 1);
    assert_eq!(preview.rows[0].email, "ada@corp.example");
    assert_eq!(preview.rows[0].username.as_deref(), Some("ada"));
    assert_eq!(preview.rows[0].display_name, "Ada Lovelace");
    assert_eq!(
        preview.rows[0].external_id,
        "8f1c0b1e-3a2f-4d5e-9a7b-2c1d0e9f8a7b"
    );
}

#[test]
fn a_paste_without_a_trailing_blank_line_still_yields_its_entry() {
    let ldif = "\
dn: uid=ada,ou=people,dc=corp,dc=example
uid: ada
entryUUID: 8f1c0b1e-3a2f-4d5e-9a7b-2c1d0e9f8a7b";
    let preview = preview(&ldap_request(Some(ldif))).expect("preview");
    assert_eq!(preview.entry_count, 1);
}

// ─── LDAP preview ─────────────────────────────────────────────────────────

#[test]
fn an_ldap_preview_normalizes_the_rows_a_sync_would_write() {
    let preview = preview(&ldap_request(Some(LDIF_USERS_AND_GROUP))).expect("preview");
    // The group entry is not a user.
    assert_eq!(preview.entry_count, 2);
    assert_eq!(preview.rows.len(), 2);

    let ada = &preview.rows[0];
    assert_eq!(ada.email, "Ada@Corp.Example".to_lowercase());
    assert_eq!(ada.username.as_deref(), Some("ada"));
    assert_eq!(ada.display_name, "Ada Lovelace");
    assert_eq!(ada.groups, vec!["eng".to_string()]);
    assert_eq!(
        ada.external_dn.as_deref(),
        Some("uid=ada,ou=people,dc=corp,dc=example"),
        "the DN is what bind-through will use, so the preview must show it"
    );
}

#[test]
fn a_missing_external_id_attribute_reports_the_attributes_that_are_present() {
    let mut config = ldap_config();
    config["external_id_attribute"] = json!("objectGUID");
    let req = PreviewRequest {
        kind: "ldap".into(),
        config,
        sample: Some(LDIF_USERS_AND_GROUP.to_string()),
        sync_groups: Some(true),
        offset: None,
    };
    let preview = preview(&req).expect("preview");
    let row = field(&preview, ROW_EXTERNAL_ID);
    assert!(!row.ok);
    let error = row.error.as_deref().unwrap_or_default();
    // The message has to name the attribute that *is* there, or the admin has
    // nothing to act on but "attribute missing". Compared case-insensitively
    // because the point is that the attribute is named, not how the server
    // happened to spell it.
    assert!(error.contains("objectGUID"), "got: {error}");
    assert!(error.to_lowercase().contains("entryuuid"), "got: {error}");
    assert_eq!(row.resolved, Some(0));
    assert_eq!(row.total, Some(2));
}

#[test]
fn the_groups_column_is_flagged_as_best_effort_when_groups_were_pasted() {
    let preview = preview(&ldap_request(Some(LDIF_USERS_AND_GROUP))).expect("preview");
    assert_eq!(field(&preview, ROW_GROUPS).resolved, Some(2));
    assert!(
        preview.warnings.iter().any(|w| w.contains("best-effort")),
        "a reconstructed membership must not be presented as exact: {:?}",
        preview.warnings
    );
}

#[test]
fn a_sample_without_group_entries_says_the_groups_column_was_not_checked() {
    let users_only = "\
dn: uid=ada,ou=people,dc=corp,dc=example
uid: ada
mail: ada@corp.example
entryUUID: 8f1c0b1e-3a2f-4d5e-9a7b-2c1d0e9f8a7b
";
    let preview = preview(&ldap_request(Some(users_only))).expect("preview");
    assert_eq!(field(&preview, ROW_GROUPS).resolved, Some(0));
    assert!(
        preview.warnings.iter().any(|w| w.contains("group entries")),
        "got: {:?}",
        preview.warnings
    );
}

#[test]
fn a_paste_whose_dns_are_outside_the_base_dn_is_reported() {
    // `user_filter` is applied by the server and cannot be checked here, so the
    // base DN suffix is the one scope signal that *is* checkable.
    let mut config = ldap_config();
    config["base_dn"] = json!("ou=elsewhere,dc=corp,dc=example");
    let req = PreviewRequest {
        kind: "ldap".into(),
        config,
        sample: Some(LDIF_USERS_AND_GROUP.to_string()),
        sync_groups: Some(true),
        offset: None,
    };
    let preview = preview(&req).expect("preview");
    let row = field(&preview, ROW_SCOPE);
    assert!(!row.ok);
    let error = row.error.as_deref().unwrap_or_default();
    assert!(error.contains("ou=elsewhere"), "got: {error}");
    assert!(error.contains("user_filter"), "got: {error}");
}

#[test]
fn ldap_preview_without_a_sample_checks_only_the_configuration() {
    let preview = preview(&ldap_request(None)).expect("preview");
    assert!(preview.fields.is_empty());
    assert!(preview.rows.is_empty());
    assert_eq!(preview.entry_count, 0);
    assert!(
        preview.warnings.iter().any(|w| w.contains("No sample")),
        "an unchecked mapping must not look verified: {:?}",
        preview.warnings
    );
}

#[test]
fn ldap_targets_report_provenance_and_multiplicity() {
    let preview = preview(&ldap_request(Some(LDIF_USERS_AND_GROUP))).expect("preview");
    let member = preview
        .targets
        .iter()
        .find(|t| t.key == "member")
        .expect("the group member attribute must be offered as a target");
    assert_eq!(member.source, "group");
    assert_eq!(member.count, 2);
    assert!(member.multi);

    let mail = preview
        .targets
        .iter()
        .find(|t| t.key == "mail")
        .expect("a user attribute");
    assert_eq!(mail.source, "user");
    assert!(!mail.multi);
}

#[test]
fn ldap_targets_say_how_many_entries_carry_them() {
    // Choosing between `displayName` and `cn` is the choice this data exists for:
    // an attribute in every entry and one in a third of them look identical in a
    // bare attribute list, and picking the patchy one is how a mapping ends up
    // silently falling back for part of the directory.
    let sample = "\
dn: uid=ada,ou=people,dc=corp,dc=example
uid: ada
mail: ada@corp.example
displayName: Ada Lovelace

dn: uid=grace,ou=people,dc=corp,dc=example
uid: grace
mail: grace@corp.example
displayName: Grace Hopper

dn: uid=alan,ou=people,dc=corp,dc=example
uid: alan
mail: alan@corp.example

dn: cn=eng,ou=groups,dc=corp,dc=example
cn: eng
member: uid=ada,ou=people,dc=corp,dc=example
member: uid=grace,ou=people,dc=corp,dc=example
";
    let mut config = ldap_config();
    // Groups have to be separable for the provenance to be meaningful.
    config["group_base_dn"] = json!("ou=groups,dc=corp,dc=example");
    let req = PreviewRequest {
        kind: "ldap".into(),
        config,
        sample: Some(sample.to_string()),
        sync_groups: Some(true),
        offset: None,
    };
    let preview = preview(&req).expect("preview");
    assert_eq!(preview.entry_count, 3);

    let find = |key: &str| preview.targets.iter().find(|t| t.key == key).unwrap();
    // Every user has this one.
    assert_eq!(find("mail").user_entries, 3);
    // Only two of three: the amber badge the UI shows for this is the whole point.
    assert_eq!(find("displayName").user_entries, 2);
    // A group attribute, with its own count and no user entries.
    let member = find("member");
    assert_eq!(member.group_entries, 1);
    assert_eq!(member.user_entries, 0);
}

#[test]
fn targets_are_spelled_the_way_the_directory_spells_them() {
    // Lookup is case-insensitive, but the list is read by humans comparing it
    // against `ldapsearch` output. Lowercasing it (`entryuuid`, `objectclass`)
    // makes the list look like it came from somewhere other than their
    // directory, which is exactly what it is supposed to prove.
    let preview = preview(&ldap_request(Some(LDIF_USERS_AND_GROUP))).expect("preview");
    let keys: Vec<&str> = preview.targets.iter().map(|t| t.key.as_str()).collect();
    assert!(keys.contains(&"entryUUID"), "got: {keys:?}");
    assert!(keys.contains(&"displayName"), "got: {keys:?}");
}

#[test]
fn a_paste_of_only_group_entries_says_so_instead_of_reporting_failures() {
    let groups_only = "\
dn: cn=eng,ou=groups,dc=corp,dc=example
cn: eng
member: uid=ada,ou=people,dc=corp,dc=example
";
    let preview = preview(&ldap_request(Some(groups_only))).expect("preview");
    assert_eq!(preview.entry_count, 0);
    assert!(
        preview.warnings.iter().any(|w| w.contains("group entry")),
        "got: {:?}",
        preview.warnings
    );
}

// ─── HTTP JSON preview ────────────────────────────────────────────────────

const JSON_SAMPLE: &str = r#"{
  "data": {
    "users": [
      {"id": "u-1", "email": "Ada@Corp.Example", "login": "ada", "name": "Ada Lovelace",
       "groups": ["eng", "ops", "eng"]},
      {"id": "u-2", "email": "grace@corp.example", "login": "grace", "groups": ["ops"]}
    ]
  }
}"#;

#[test]
fn a_json_preview_reports_the_normalized_rows() {
    let preview = preview(&http_request(Some(JSON_SAMPLE))).expect("preview");
    assert_eq!(preview.entry_count, 2);
    assert_eq!(preview.rows.len(), 2);

    let ada = &preview.rows[0];
    assert_eq!(ada.email, "ada@corp.example", "emails are stored lowercase");
    assert_eq!(ada.display_name, "Ada Lovelace");
    assert_eq!(ada.groups, vec!["eng".to_string(), "ops".to_string()]);

    // The second entry has no display name, so the email local part is used —
    // exactly what the planner does, which is the whole point of previewing.
    let grace = &preview.rows[1];
    assert_eq!(grace.display_name, "grace");
    assert!(field(&preview, ROW_EMAIL).ok);
    assert!(field(&preview, ROW_USERNAME).ok);
    assert!(field(&preview, ROW_DISPLAY_NAME).ok);
}

#[test]
fn a_users_path_that_is_not_an_array_fails_the_whole_preview() {
    // This is the destructive one: a listing read as empty would disable every
    // user the source manages, so it must not be downgraded to a row warning.
    let sample = r#"{"data": {"users": {"u-1": {"email": "a@corp.example"}}}}"#;
    let err = preview(&http_request(Some(sample))).expect_err("must fail");
    assert!(err.to_string().contains("data.users"), "got: {err}");
}

#[test]
fn an_email_path_that_resolves_nowhere_fails_that_row() {
    let mut config = http_config();
    config["email_path"] = json!("emailAddress");
    let req = PreviewRequest {
        kind: "http_json".into(),
        config,
        sample: Some(JSON_SAMPLE.to_string()),
        sync_groups: Some(true),
        offset: None,
    };
    let preview = preview(&req).expect("preview");
    let row = field(&preview, ROW_EMAIL);
    assert!(!row.ok);
    assert_eq!(row.resolved, Some(0));
    assert_eq!(row.total, Some(2));
    assert!(row
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("emailAddress"));
}

#[test]
fn an_unset_optional_path_is_not_a_failure_but_a_dead_one_is() {
    // Leaving an optional row unset is a legitimate choice; configuring a path
    // that resolves for nobody is a mistake worth surfacing.
    let mut config = http_config();
    config["display_name_path"] = json!(null);
    let req = PreviewRequest {
        kind: "http_json".into(),
        config,
        sample: Some(JSON_SAMPLE.to_string()),
        sync_groups: Some(true),
        offset: None,
    };
    let unset = preview(&req).expect("preview");
    assert!(field(&unset, ROW_DISPLAY_NAME).ok);

    let mut dead = http_config();
    dead["display_name_path"] = json!("profile.name");
    let req = PreviewRequest {
        kind: "http_json".into(),
        config: dead,
        sample: Some(JSON_SAMPLE.to_string()),
        sync_groups: Some(true),
        offset: None,
    };
    let dead_preview = preview(&req).expect("preview");
    assert!(!field(&dead_preview, ROW_DISPLAY_NAME).ok);
}

#[test]
fn a_groups_path_with_sync_groups_off_is_warned_about() {
    // The mapping is right and the toggle says it will never be written. Without
    // this warning that combination looks like a working configuration.
    let req = PreviewRequest {
        kind: "http_json".into(),
        config: http_config(),
        sample: Some(JSON_SAMPLE.to_string()),
        sync_groups: Some(false),
        offset: None,
    };
    let off = preview(&req).expect("preview");
    assert!(
        off.warnings.iter().any(|w| w.contains("will not")),
        "got: {:?}",
        off.warnings
    );

    let mut config = http_config();
    config["groups_path"] = json!(null);
    let req = PreviewRequest {
        kind: "http_json".into(),
        config,
        sample: Some(JSON_SAMPLE.to_string()),
        sync_groups: Some(true),
        offset: None,
    };
    let without_groups = preview(&req).expect("preview");
    assert!(
        without_groups
            .warnings
            .iter()
            .any(|w| w.contains("groups_path is configured")),
        "got: {:?}",
        without_groups.warnings
    );
}

#[test]
fn a_sample_that_is_not_json_is_rejected() {
    let err = preview(&http_request(Some("dn: uid=ada"))).expect_err("must fail");
    assert!(err.to_string().contains("not valid JSON"), "got: {err}");
}

#[test]
fn verdicts_are_complete_even_though_the_row_table_is_paged() {
    // 60 entries, which is more than one page. Every field verdict must be
    // computed across all of them: the panel shows the header count and the
    // per-row denominators side by side, so the two disagreeing is a visible
    // contradiction, and the smaller denominator is the wrong direction —
    // it understates how patchy an attribute is.
    let entries: Vec<serde_json::Value> = (0..60)
        .map(|i| json!({"id": format!("u-{i}"), "email": format!("u{i}@corp.example")}))
        .collect();
    let sample = json!({ "data": { "users": entries } }).to_string();
    let preview = preview(&http_request(Some(&sample))).expect("preview");

    assert_eq!(preview.entry_count, 60);
    assert!(preview.rows.len() < 60, "the row table must be paged");
    assert!(preview.truncated, "more rows exist than this page carries");
    assert_eq!(preview.offset, 0);
    // The denominator is the whole paste, not the page.
    assert_eq!(field(&preview, ROW_EMAIL).total, Some(60));
    assert_eq!(field(&preview, ROW_EMAIL).resolved, Some(60));
    assert_eq!(field(&preview, ROW_EXTERNAL_ID).total, Some(60));
}

#[test]
fn a_later_page_returns_different_rows_without_changing_the_verdicts() {
    let entries: Vec<serde_json::Value> = (0..60)
        .map(|i| json!({"id": format!("u-{i}"), "email": format!("u{i}@corp.example")}))
        .collect();
    let sample = json!({ "data": { "users": entries } }).to_string();

    let first = preview(&http_request(Some(&sample))).expect("preview");
    let second = preview(&http_page(&sample, 25)).expect("preview");

    assert_eq!(second.offset, 25);
    assert_eq!(
        first.rows[0].external_id, "u-0",
        "the first page starts at the first entry"
    );
    assert_eq!(
        second.rows[0].external_id, "u-25",
        "the second page starts where the first stopped"
    );
    // Paging is a display concern: it must not move any verdict.
    assert_eq!(first.entry_count, second.entry_count);
    assert_eq!(
        field(&first, ROW_EMAIL).total,
        field(&second, ROW_EMAIL).total,
        "the denominator must not depend on which page was asked for"
    );
    assert_eq!(field(&second, ROW_EMAIL).resolved, Some(60));
}

#[test]
fn the_page_step_stays_aligned_on_a_short_final_page() {
    // 60 entries with a page size of 25: the last page spans 5 entries. If the
    // step were the number of *returned* rows, "previous" from that page would
    // land on 45 (60 − 15 is impossible; 50 − 5 = 45) and overlap the 25–49
    // window. The step has to be the page capacity for paging to be reversible.
    let entries: Vec<serde_json::Value> = (0..60)
        .map(|i| json!({"id": format!("u-{i}"), "email": format!("u{i}@corp.example")}))
        .collect();
    let sample = json!({ "data": { "users": entries } }).to_string();

    let first = preview(&http_request(Some(&sample))).expect("preview");
    let last = preview(&http_page(&sample, 50)).expect("preview");

    assert_eq!(last.offset, 50);
    assert_eq!(last.rows.len(), 10, "a partial final page");
    assert!(!last.truncated);
    assert_eq!(
        first.page_size, last.page_size,
        "the step must not shrink with the final page, or paging back would \
         overlap the previous window"
    );
    let back = preview(&http_page(&sample, last.offset - last.page_size)).expect("preview");
    assert_eq!(
        back.offset, 25,
        "previous page starts where this one should"
    );
    assert_eq!(back.rows[0].external_id, "u-25");
}

#[test]
fn rows_are_not_assumed_to_match_the_page_width() {
    // Two entries in three have no external id, so they yield no row. A caller
    // stepping by the row count would under-advance and re-show entries; the
    // reported page size is what makes the step correct.
    let entries: Vec<serde_json::Value> = (0..30)
        .map(|i| {
            if i % 3 == 0 {
                json!({ "id": format!("u-{i}"), "email": format!("u{i}@corp.example") })
            } else {
                json!({ "email": format!("u{i}@corp.example") })
            }
        })
        .collect();
    let sample = json!({ "data": { "users": entries } }).to_string();

    let preview = preview(&http_request(Some(&sample))).expect("preview");

    assert_eq!(
        preview.entry_count, 30,
        "the denominator counts every entry"
    );
    assert_eq!(
        preview.rows.len(),
        9,
        "the page spans 25 entries and only every third yields a row"
    );
    assert_eq!(
        preview.page_size, 25,
        "the page spans more entries than it has rows"
    );
    assert!(
        preview.rows.len() < preview.page_size,
        "a page can be narrower in rows than in entries — the caller must step by \
         `page_size`, not by `rows.len()`"
    );
    // The verdict counts stay entry-based, so they cover the entries that produced
    // no row as well.
    assert_eq!(field(&preview, ROW_EXTERNAL_ID).resolved, Some(10));
    assert_eq!(field(&preview, ROW_EXTERNAL_ID).total, Some(30));
}

#[test]
fn ldap_verdicts_are_complete_while_the_row_table_pages() {
    // The LDAP path was changed the same way as the JSON one, and needs its own
    // guard: `page_window` is shared, but the counters around it are separate
    // code, and an `entry_count` that disagrees with the denominators is exactly
    // the defect this replaced.
    let sample = ldif_users(60, Some(55));
    let preview = preview(&ldap_request(Some(&sample))).expect("preview");

    assert_eq!(preview.entry_count, 60);
    assert_eq!(preview.offset, 0);
    assert_eq!(preview.page_size, 25);
    assert!(preview.truncated);
    assert!(
        preview.rows.len() < 60,
        "the row table must not carry the whole directory in one response"
    );
    // Every denominator is the whole paste, and the displayName whose only
    // instance is entry 55 is still counted — past the first page.
    assert_eq!(field(&preview, ROW_EMAIL).total, Some(60));
    assert_eq!(field(&preview, ROW_EMAIL).resolved, Some(60));
    assert_eq!(field(&preview, ROW_DISPLAY_NAME).resolved, Some(5));
    assert_eq!(field(&preview, ROW_DISPLAY_NAME).total, Some(60));
    // The attribute list is likewise built from every entry, not the page.
    let display_name = preview
        .targets
        .iter()
        .find(|t| t.key == "displayName")
        .expect("displayName is offered");
    assert_eq!(display_name.user_entries, 5);
}

#[test]
fn ldap_a_later_page_returns_different_rows_with_unchanged_verdicts() {
    let sample = ldif_users(60, Some(55));

    let first = preview(&ldap_request(Some(&sample))).expect("preview");
    let second = preview(&ldap_page(&sample, 25)).expect("preview");

    assert_eq!(second.offset, 25);
    assert_eq!(
        first.rows[0].external_id,
        "11111111-2222-3333-4444-000000000000"
    );
    assert_eq!(
        second.rows[0].external_id, "11111111-2222-3333-4444-000000000025",
        "the second page starts where the first stopped"
    );
    assert_eq!(first.entry_count, second.entry_count);
    assert_eq!(
        field(&first, ROW_DISPLAY_NAME).total,
        field(&second, ROW_DISPLAY_NAME).total,
        "the denominator must not depend on the page"
    );
    assert_eq!(field(&second, ROW_DISPLAY_NAME).resolved, Some(5));
}

#[test]
fn an_offset_past_the_end_falls_back_to_the_last_page() {
    // Between two debounced runs the paste can shrink, leaving the dashboard
    // holding an offset beyond the end. An empty table would read as "this source
    // yields no users", which is a far more alarming and much less likely
    // conclusion than "your page number is stale".
    let entries: Vec<serde_json::Value> = (0..10)
        .map(|i| json!({"id": format!("u-{i}"), "email": format!("u{i}@corp.example")}))
        .collect();
    let sample = json!({ "data": { "users": entries } }).to_string();

    let preview = preview(&http_page(&sample, 9_999)).expect("preview");

    assert_eq!(preview.offset, 0, "10 entries is a single page");
    assert_eq!(preview.rows.len(), 10);
    assert!(!preview.truncated);
}

#[test]
fn a_multi_page_sample_still_verifies_every_entry() {
    // A field present in exactly one entry of a 60-entry paste. The point of the
    // count is to make this look as sparse as it is; capping the analysis at 50
    // reported it as 1/50 instead of 1/60, and would have reported 0/50 — a
    // passing verdict — if the one entry had been the 55th.
    let mut entries: Vec<serde_json::Value> = (0..60)
        .map(|i| json!({"id": format!("u-{i}"), "email": format!("u{i}@corp.example")}))
        .collect();
    // The fixture's `display_name_path` is `name`.
    entries[55]["name"] = json!("Late Arrival");
    let sample = json!({ "data": { "users": entries } }).to_string();

    let preview = preview(&http_request(Some(&sample))).expect("preview");

    assert_eq!(preview.entry_count, 60);
    assert_eq!(
        field(&preview, ROW_DISPLAY_NAME).resolved,
        Some(1),
        "the entry past the first page must still be counted"
    );
    assert_eq!(field(&preview, ROW_DISPLAY_NAME).total, Some(60));
}

#[test]
fn an_oversized_sample_is_refused_before_it_is_parsed() {
    let sample = "x".repeat(MAX_SAMPLE_BYTES + 1);
    let err = preview(&http_request(Some(&sample))).expect_err("must fail");
    assert!(err.to_string().contains("limit"), "got: {err}");
}

// ─── Shared behaviour ─────────────────────────────────────────────────────

#[test]
fn a_connection_setting_being_blank_does_not_block_the_mapping_check() {
    // The preview reads nothing over the network, so `url`/`bind_dn`/credentials
    // are irrelevant to it. Requiring them meant the attribute list for a pasted
    // LDIF stayed hidden until the *connection* was filled in — backwards for the
    // panel whose job is to help fill the form in.
    let mut config = ldap_config();
    config["url"] = json!("");
    config["bind_dn"] = json!("");
    let req = PreviewRequest {
        kind: "ldap".into(),
        config,
        sample: Some(LDIF_USERS_AND_GROUP.to_string()),
        sync_groups: Some(true),
        offset: None,
    };
    let ldap_preview = preview(&req).expect("a blank URL must not stop the mapping check");
    assert_eq!(ldap_preview.entry_count, 2);
    assert!(
        !ldap_preview.targets.is_empty(),
        "the attribute list must still be built"
    );

    let mut http = http_config();
    http["url"] = json!("");
    http["auth"] = json!("none");
    let req = PreviewRequest {
        kind: "http_json".into(),
        config: http,
        sample: Some(JSON_SAMPLE.to_string()),
        sync_groups: Some(true),
        offset: None,
    };
    let http_preview = preview(&req).expect("a blank URL must not stop the mapping check");
    assert_eq!(http_preview.entry_count, 2);
}

#[test]
fn an_unset_mapping_key_is_reported_as_unset_not_as_a_failed_mapping() {
    // "resolved for none of the entries" would send the admin looking at their
    // directory when the input is simply still empty.
    let mut config = http_config();
    config["email_path"] = json!("");
    let req = PreviewRequest {
        kind: "http_json".into(),
        config,
        sample: Some(JSON_SAMPLE.to_string()),
        sync_groups: Some(true),
        offset: None,
    };
    let preview = preview(&req).expect("preview");
    let row = field(&preview, ROW_EMAIL);
    assert!(!row.ok);
    assert_eq!(row.error.as_deref(), Some("`email_path` is not set yet"));
}

#[test]
fn an_unset_users_path_still_answers_with_what_can_be_checked() {
    let mut config = http_config();
    config["users_path"] = json!("");
    let req = PreviewRequest {
        kind: "http_json".into(),
        config,
        sample: Some(JSON_SAMPLE.to_string()),
        sync_groups: Some(true),
        offset: None,
    };
    let preview = preview(&req).expect("preview");
    assert_eq!(preview.entry_count, 0);
    let scope = field(&preview, ROW_SCOPE);
    assert!(!scope.ok);
    assert_eq!(scope.error.as_deref(), Some("`users_path` is not set yet"));
}

#[test]
fn an_ldap_paste_with_no_config_at_all_still_shows_its_attributes() {
    // The strongest form of the same point: nothing filled in, one paste. The
    // attribute list is the answer to "what do I even type here?".
    let req = PreviewRequest {
        kind: "ldap".into(),
        config: json!({}),
        sample: Some(LDIF_USERS_AND_GROUP.to_string()),
        sync_groups: Some(true),
        offset: None,
    };
    let preview = preview(&req).expect("preview");
    let keys: Vec<&str> = preview.targets.iter().map(|t| t.key.as_str()).collect();
    assert!(keys.contains(&"uid"), "got: {keys:?}");
    assert!(keys.contains(&"entryUUID"), "got: {keys:?}");
    // And the unset rows say so, rather than blaming the directory.
    assert_eq!(
        field(&preview, ROW_SCOPE).error.as_deref(),
        Some("`base_dn` is not set yet")
    );
}

#[test]
fn a_config_that_the_engine_would_refuse_never_previews() {
    // Saving is where the *whole* config is validated strictly. The preview
    // deliberately ignores the connection keys it does not read, so this pins the
    // part it does own: a kind with no mapping, and a config that is not an
    // object at all.
    let req = PreviewRequest {
        kind: "scim".into(),
        config: json!({}),
        sample: None,
        sync_groups: Some(true),
        offset: None,
    };
    // SCIM is push, not a configurable pull source, so it has no mapping to
    // preview and must say so rather than returning an empty success.
    let err = preview(&req).expect_err("scim has no mapping");
    assert!(err.to_string().contains("scim"), "got: {err}");

    let req = PreviewRequest {
        kind: "http_json".into(),
        config: json!("not an object"),
        sample: None,
        sync_groups: Some(true),
        offset: None,
    };
    assert!(preview(&req).is_err());

    // An unknown *mapping* key is not silently accepted as "unset": it cannot be
    // read as the key it was meant to be, so the row it was meant for reports
    // itself as unset — which the save path will reject outright.
    let mut config = http_config();
    config["users_path_typo"] = json!("data.users");
    config["users_path"] = json!(null);
    let req = PreviewRequest {
        kind: "http_json".into(),
        config,
        sample: Some(JSON_SAMPLE.to_string()),
        sync_groups: Some(true),
        offset: None,
    };
    let preview = preview(&req).expect("preview");
    assert!(!field(&preview, ROW_SCOPE).ok);
}

#[test]
fn every_row_the_dashboard_renders_is_reported_for_both_kinds() {
    // The dashboard builds its table from these ids; a kind that silently omits
    // one would render a row with no verdict.
    let expected = [
        ROW_SCOPE,
        ROW_EXTERNAL_ID,
        ROW_EMAIL,
        ROW_USERNAME,
        ROW_DISPLAY_NAME,
        ROW_GROUPS,
    ];
    let ldap = preview(&ldap_request(Some(LDIF_USERS_AND_GROUP))).expect("preview");
    let http = preview(&http_request(Some(JSON_SAMPLE))).expect("preview");
    for id in expected {
        assert!(
            ldap.fields.iter().any(|f| f.row == id),
            "ldap preview omitted `{id}`"
        );
        assert!(
            http.fields.iter().any(|f| f.row == id),
            "http_json preview omitted `{id}`"
        );
    }
}

// ─── The request contract ─────────────────────────────────────────────────

#[test]
fn the_body_the_dashboard_sends_deserializes_as_written() {
    // The panel posts this shape verbatim (`previewDirectoryMapping` in
    // `dashboard/src/lib/api.ts`). `PreviewRequest` refuses unknown fields, so a
    // renamed key on either side would turn every mapping edit into a 400 — a
    // failure that is invisible to the pure tests above and would only show up in
    // the browser.
    let body = serde_json::json!({
        "kind": "http_json",
        "config": {
            "url": "https://api.corp.example/v1/users",
            "method": "GET",
            "auth": "none",
            "users_path": "data.users",
            "external_id_path": "id",
            "email_path": "email",
            "username_path": "login",
            "display_name_path": "name",
            "groups_path": "groups",
            "pagination": { "mode": "none" }
        },
        "sample": JSON_SAMPLE,
        "sync_groups": true
    });
    let req: PreviewRequest =
        serde_json::from_value(body).expect("the documented request body must deserialize");
    let preview = preview(&req).expect("preview");
    assert_eq!(preview.entry_count, 2);
}

#[test]
fn a_request_with_an_unexpected_field_is_refused() {
    // Leniency here would be worse than strictness: a misspelled `sample_json`
    // would silently preview nothing and look like a passing check.
    let body = serde_json::json!({
        "kind": "ldap",
        "config": ldap_config(),
        "sample": LDIF_USERS_AND_GROUP,
        "sync_groups": true,
        "sample_json": "{ }"
    });
    assert!(serde_json::from_value::<PreviewRequest>(body).is_err());
}

// ─── Scope (§7) ───────────────────────────────────────────────────────────
//
// The scope can be checked from a paste, unlike the server-side `user_filter`,
// and this is the only place an admin can find out that a filter admits nobody
// *before* a run disables everyone the source already manages.

/// Three users: two in `corp.example` (one per department) and one elsewhere.
const LDIF_MIXED_DOMAINS: &str = "\
dn: uid=ada,ou=people,dc=corp,dc=example
uid: ada
mail: ada@corp.example
department: Engineering
entryUUID: 8f1c0b1e-3a2f-4d5e-9a7b-2c1d0e9f8a7b

dn: uid=bob,ou=people,dc=corp,dc=example
uid: bob
mail: bob@other.example
department: Engineering
entryUUID: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d

dn: uid=carol,ou=people,dc=corp,dc=example
uid: carol
mail: carol@corp.example
department: Sales
entryUUID: 2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
";

/// The JSON counterpart of `LDIF_MIXED_DOMAINS`, same three people.
const HTTP_MIXED_DOMAINS: &str = r#"{
  "data": { "users": [
    { "id": "1", "email": "ada@corp.example", "dept": "Engineering" },
    { "id": "2", "email": "bob@other.example", "dept": "Engineering" },
    { "id": "3", "email": "carol@corp.example", "dept": "Sales" }
  ] }
}"#;

/// `n` entries where only `in_domain_at` belongs to `corp.example`, so a scope can
/// be pointed at an entry that is not on the first page.
fn ldif_one_in_domain(n: usize, in_domain_at: usize) -> String {
    (0..n)
        .map(|i| {
            let domain = if i == in_domain_at {
                "corp.example"
            } else {
                "other.example"
            };
            format!(
                "dn: uid=user{i},ou=people,dc=corp,dc=example\n\
                 uid: user{i}\n\
                 mail: user{i}@{domain}\n\
                 entryUUID: 11111111-2222-3333-4444-{i:012}\n\n"
            )
        })
        .collect()
}

fn ldap_with(config: serde_json::Value, sample: &str) -> PreviewRequest {
    PreviewRequest {
        kind: "ldap".into(),
        config,
        sample: Some(sample.to_string()),
        sync_groups: Some(true),
        offset: None,
    }
}

fn http_with(config: serde_json::Value, sample: &str) -> PreviewRequest {
    PreviewRequest {
        kind: "http_json".into(),
        config,
        sample: Some(sample.to_string()),
        sync_groups: Some(true),
        offset: None,
    }
}

#[test]
fn a_domain_scope_reports_how_many_sampled_entries_it_admits() {
    let mut config = ldap_config();
    config["email_domains"] = json!(["corp.example"]);
    let preview = preview(&ldap_with(config, LDIF_MIXED_DOMAINS)).expect("preview");

    let scope = field(&preview, ROW_SCOPE);
    assert!(scope.ok, "error={:?}", scope.error);
    assert_eq!(scope.resolved, Some(2), "ada and carol, not bob");
    assert_eq!(scope.total, Some(3));
}

#[test]
fn a_scope_that_admits_nobody_fails_the_scope_row() {
    // The failure this row exists for. At run time a scope matching nothing does
    // not sync nobody — it disables everyone the source already manages, because
    // every linked user drops out of scope at once.
    let mut config = ldap_config();
    config["email_domains"] = json!(["nowhere.example"]);
    let preview = preview(&ldap_with(config, LDIF_MIXED_DOMAINS)).expect("preview");

    let scope = field(&preview, ROW_SCOPE);
    assert!(!scope.ok, "a scope that admits nobody must not pass");
    let error = scope.error.as_deref().unwrap_or_default();
    assert!(error.contains("nowhere.example"), "got: {error}");
    assert!(error.contains("disables every user"), "got: {error}");
    assert_eq!(scope.resolved, Some(0));
    assert_eq!(scope.total, Some(3));
}

#[test]
fn a_department_scope_reads_the_configured_attribute() {
    let mut config = ldap_config();
    config["department_attribute"] = json!("department");
    config["department_values"] = json!(["Engineering"]);
    let preview = preview(&ldap_with(config, LDIF_MIXED_DOMAINS)).expect("preview");

    let scope = field(&preview, ROW_SCOPE);
    assert!(scope.ok, "error={:?}", scope.error);
    assert_eq!(scope.resolved, Some(2), "ada and bob are in Engineering");
    assert_eq!(scope.total, Some(3));
}

#[test]
fn a_department_scope_over_an_attribute_nobody_has_admits_nobody() {
    // A wrong attribute name is the mistake that reads as "those departments are
    // empty", so the row has to fail rather than report a quiet zero.
    let mut config = ldap_config();
    config["department_attribute"] = json!("division");
    config["department_values"] = json!(["Engineering"]);
    let preview = preview(&ldap_with(config, LDIF_MIXED_DOMAINS)).expect("preview");

    let scope = field(&preview, ROW_SCOPE);
    assert!(!scope.ok);
    assert_eq!(scope.resolved, Some(0));
}

#[test]
fn domains_and_departments_intersect_in_the_preview_too() {
    // The preview has to agree with the planner about AND semantics, or it would
    // call a scope healthy that the run then treats as empty.
    let mut config = ldap_config();
    config["email_domains"] = json!(["corp.example"]);
    config["department_attribute"] = json!("department");
    config["department_values"] = json!(["Engineering"]);
    let preview = preview(&ldap_with(config, LDIF_MIXED_DOMAINS)).expect("preview");

    let scope = field(&preview, ROW_SCOPE);
    assert!(scope.ok, "error={:?}", scope.error);
    assert_eq!(scope.resolved, Some(1), "only ada is in both");
}

#[test]
fn the_scope_is_counted_over_the_whole_sample_not_the_displayed_page() {
    // The only in-scope entry is past the first page. Counting the window would
    // report "0 of 30" and fail a source that is configured correctly — the same
    // reason every other per-row counter is a full pass.
    let ldif = ldif_one_in_domain(30, 27);
    let mut config = ldap_config();
    config["email_domains"] = json!(["corp.example"]);
    let preview = preview(&ldap_with(config, &ldif)).expect("preview");

    let scope = field(&preview, ROW_SCOPE);
    assert!(scope.ok, "error={:?}", scope.error);
    assert_eq!(scope.resolved, Some(1));
    assert_eq!(scope.total, Some(30));
    assert!(
        !preview
            .rows
            .iter()
            .any(|row| row.email.starts_with("user27@")),
        "the in-scope entry has to be off-page for this test to mean anything"
    );
}

#[test]
fn an_unconfigured_ldap_scope_still_reports_the_base_dn_count() {
    // Backward compatibility for the row's earlier meaning: with no scope
    // configured, every entry under the base DN counts as resolved.
    let preview = preview(&ldap_request(Some(LDIF_USERS_AND_GROUP))).expect("preview");
    let scope = field(&preview, ROW_SCOPE);
    assert!(scope.ok);
    assert_eq!(scope.resolved, Some(2), "ada and grace, the group excluded");
    assert_eq!(scope.total, Some(2));
}

#[test]
fn an_unconfigured_http_scope_still_reports_the_sample_size() {
    let preview = preview(&http_request(Some(HTTP_MIXED_DOMAINS))).expect("preview");
    let scope = field(&preview, ROW_SCOPE);
    assert!(scope.ok);
    assert_eq!(scope.resolved, Some(3));
    assert_eq!(scope.total, Some(3));
}

#[test]
fn an_http_domain_scope_reports_how_many_sampled_entries_it_admits() {
    let mut config = http_config();
    config["email_domains"] = json!(["corp.example"]);
    let preview = preview(&http_with(config, HTTP_MIXED_DOMAINS)).expect("preview");

    let scope = field(&preview, ROW_SCOPE);
    assert!(scope.ok, "error={:?}", scope.error);
    assert_eq!(scope.resolved, Some(2));
    assert_eq!(scope.total, Some(3));
}

#[test]
fn an_http_department_scope_reads_the_configured_path() {
    let mut config = http_config();
    config["department_path"] = json!("dept");
    config["department_values"] = json!(["Sales"]);
    let preview = preview(&http_with(config, HTTP_MIXED_DOMAINS)).expect("preview");

    let scope = field(&preview, ROW_SCOPE);
    assert!(scope.ok, "error={:?}", scope.error);
    assert_eq!(scope.resolved, Some(1), "only carol is in Sales");
}

#[test]
fn an_http_scope_that_admits_nobody_fails_the_scope_row() {
    let mut config = http_config();
    config["department_path"] = json!("dept");
    config["department_values"] = json!(["Marketing"]);
    let preview = preview(&http_with(config, HTTP_MIXED_DOMAINS)).expect("preview");

    let scope = field(&preview, ROW_SCOPE);
    assert!(!scope.ok);
    let error = scope.error.as_deref().unwrap_or_default();
    assert!(error.contains("Marketing"), "got: {error}");
}
