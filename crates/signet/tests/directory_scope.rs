//! Contract tests for the source scope (docs/directory-sync.md §7): email
//! domains and departments.
//!
//! The scope is deliberately two things at once, and both need pinning:
//!
//! 1. A pure predicate over a normalized entry, which is what lets the mapping
//!    preview report on it from a paste alone.
//! 2. A rule inside the planner that decides ownership — so an entry that fails
//!    the predicate is not merely skipped, it is *not owned*, and a linked user
//!    who drops out is disabled.
//!
//! Point 2 is the dangerous half, and the reason the reason-string tests exist:
//! "the directory deleted them" and "they moved department" produce the same
//! disable, and an operator reading the run history has to be able to tell which
//! one happened.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

use serde_json::json;
use signet::directory::plan::{
    plan, Change, LinkSnapshot, LocalState, Outcome, PlanOptions, ScopeFilter, SyncPlan,
    UpstreamUser, UserIndexEntry, UserSnapshot, REASON_ABSENT_UPSTREAM, REASON_OUT_OF_SCOPE,
};
use signet::directory::source::{HttpJsonConfig, LdapConfig, SourceConfig};
use std::collections::HashMap;
use uuid::Uuid;

const SOURCE: &str = "corp-ldap";

// ─── The predicate ────────────────────────────────────────────────────────

fn scope(email_domains: &[&str], department_values: &[&str]) -> ScopeFilter {
    ScopeFilter {
        email_domains: email_domains.iter().map(|s| s.to_string()).collect(),
        department_values: department_values.iter().map(|s| s.to_string()).collect(),
    }
}

fn user(external_id: &str, email: &str, department: Option<&str>) -> UpstreamUser {
    UpstreamUser {
        external_id: external_id.into(),
        external_dn: None,
        email: email.into(),
        username: Some(external_id.into()),
        display_name: None,
        department: department.map(str::to_string),
        groups: vec![],
    }
}

#[test]
fn an_unconfigured_scope_admits_everything() {
    // The backward-compatibility contract: a source saved before scoping existed
    // owns exactly what it owned, including entries with no parseable email.
    let filter = ScopeFilter::default();
    assert!(filter.is_empty());
    assert!(filter.allows(&user("a", "a@corp.example", Some("Engineering"))));
    assert!(filter.allows(&user("a", "", None)));
    assert!(filter.allows(&user("a", "not-an-address", None)));
}

#[test]
fn a_configured_scope_is_not_empty_even_with_one_list() {
    assert!(!scope(&["corp.example"], &[]).is_empty());
    assert!(!scope(&[], &["Engineering"]).is_empty());
}

#[test]
fn a_domain_matches_itself_and_its_subdomains() {
    let filter = scope(&["corp.example"], &[]);
    assert!(filter.allows(&user("a", "a@corp.example", None)));
    assert!(
        filter.allows(&user("a", "a@mail.corp.example", None)),
        "a subdomain is part of the domain"
    );
}

#[test]
fn a_domain_that_merely_ends_with_the_same_letters_does_not_match() {
    // The failure this guards against is the whole reason the comparison is on
    // label boundaries: a plain suffix test admits `evilcorp.example` for
    // `corp.example`, which turns a domain filter into a way in rather than a
    // way to narrow.
    let filter = scope(&["corp.example"], &[]);
    assert!(!filter.allows(&user("a", "a@evilcorp.example", None)));
    assert!(!filter.allows(&user("a", "a@notcorp.example", None)));
    assert!(!filter.allows(&user("a", "a@corp.example.evil.example", None)));
}

#[test]
fn domains_and_addresses_are_matched_case_insensitively() {
    // The stored email is lowercased by the planner, and a directory will happily
    // hold `A@Corp.Example`, so neither side may be case-sensitive.
    let filter = scope(&["Corp.Example"], &[]);
    assert!(filter.allows(&user("a", "A@CORP.EXAMPLE", None)));
    assert!(filter.allows(&user("a", "  a@corp.example  ", None)));
}

#[test]
fn a_leading_dot_in_a_configured_domain_is_tolerated() {
    let filter = scope(&[".corp.example"], &[]);
    assert!(filter.allows(&user("a", "a@corp.example", None)));
    assert!(filter.allows(&user("a", "a@mail.corp.example", None)));
}

#[test]
fn any_one_of_the_configured_domains_admits_an_entry() {
    let filter = scope(&["corp.example", "partner.example"], &[]);
    assert!(filter.allows(&user("a", "a@partner.example", None)));
    assert!(!filter.allows(&user("a", "a@elsewhere.example", None)));
}

#[test]
fn an_address_the_domain_cannot_be_read_from_is_not_in_scope() {
    // "Cannot be shown to belong" has to mean "does not belong": treating an
    // unparseable address as a match would quietly admit entries the admin
    // excluded, which is the opposite of what a scope is for.
    let filter = scope(&["corp.example"], &[]);
    for address in ["", "   ", "no-at-sign", "trailing@", "@other.example"] {
        assert!(
            !filter.allows(&user("a", address, None)),
            "`{address}` must not be in scope"
        );
    }
}

#[test]
fn the_scope_reads_the_domain_and_does_not_police_the_address() {
    // A blank local part still names a domain, and deciding whether an address is
    // usable belongs to the email row (and to the planner), not here. Keeping the
    // two separate is what stops one row's verdict from being reported twice.
    let filter = scope(&["corp.example"], &[]);
    assert!(filter.allows(&user("a", "@corp.example", None)));
}

#[test]
fn the_last_at_sign_decides_the_domain() {
    // An address with an `@` in the local part is unusual but legal, and taking
    // the first one would read the domain as `corp.example` in the second case.
    let filter = scope(&["corp.example"], &[]);
    assert!(filter.allows(&user("a", "weird@name@corp.example", None)));
}

#[test]
fn a_department_must_be_listed_exactly() {
    let filter = scope(&[], &["Engineering"]);
    assert!(filter.allows(&user("a", "a@corp.example", Some("Engineering"))));
    assert!(
        filter.allows(&user("a", "a@corp.example", Some(" engineering "))),
        "surrounding whitespace and case must not decide membership"
    );
    assert!(
        !filter.allows(&user("a", "a@corp.example", Some("Engineer"))),
        "a prefix is not a match; there is no pattern language here"
    );
}

#[test]
fn an_entry_without_a_department_cannot_be_in_a_department() {
    let filter = scope(&[], &["Engineering"]);
    assert!(!filter.allows(&user("a", "a@corp.example", None)));
    assert!(!filter.allows(&user("a", "a@corp.example", Some("   "))));
}

#[test]
fn domains_and_departments_must_both_pass() {
    // Both lists are constraints, not alternatives. An admin who sets both is
    // asking for the intersection, and the preview shows exactly this.
    let filter = scope(&["corp.example"], &["Engineering"]);
    assert!(filter.allows(&user("a", "a@corp.example", Some("Engineering"))));
    assert!(!filter.allows(&user("a", "a@corp.example", Some("Sales"))));
    assert!(!filter.allows(&user("a", "a@other.example", Some("Engineering"))));
}

fn described() -> String {
    let filter = scope(&["corp.example"], &["Engineering", "Platform"]);
    filter.describe()
}

#[test]
fn the_scope_describes_itself_for_operator_messages() {
    // The preview and the run report quote this, so it has to name both halves
    // rather than saying "the scope".
    assert_eq!(
        described(),
        "domains corp.example; departments Engineering, Platform"
    );
    assert_eq!(ScopeFilter::default().describe(), "nothing configured");
}

// ─── The planner rule ─────────────────────────────────────────────────────

fn opts_with(scope: ScopeFilter) -> PlanOptions {
    PlanOptions {
        sync_groups: true,
        reconcile: true,
        scope,
    }
}

fn change<'a>(plan: &'a SyncPlan, external_id: &str) -> &'a Change {
    plan.changes
        .iter()
        .find(|c| c.external_id == external_id)
        .unwrap_or_else(|| panic!("no change planned for {external_id}"))
}

/// The disable planned for an external id, if any.
///
/// One entry can produce two changes: the classification from the listing pass
/// (a `Skip` saying it is out of scope) and the action from the absent pass. The
/// planner already behaves this way for an entry it cannot interpret, so tests
/// about the disable have to ask for it by outcome rather than by id.
fn disable<'a>(plan: &'a SyncPlan, external_id: &str) -> Option<&'a Change> {
    plan.changes
        .iter()
        .find(|c| c.external_id == external_id && c.outcome == Outcome::Disable)
}

fn empty_local() -> LocalState {
    LocalState {
        source_code: SOURCE.into(),
        ..Default::default()
    }
}

/// Local state where this source owns one user, seen upstream before.
fn linked_local(external_id: &str, id: Uuid, email: &str) -> LocalState {
    LocalState {
        source_code: SOURCE.into(),
        links: vec![LinkSnapshot {
            external_id: external_id.into(),
            user_id: id,
            source_hash: None,
        }],
        linked_users: vec![UserSnapshot {
            id,
            email: email.into(),
            username: Some(external_id.into()),
            display_name: "Someone".into(),
            status: "active".into(),
            directory_groups: vec![],
            directory_disabled: false,
        }],
        index: vec![UserIndexEntry {
            id,
            email: email.into(),
            username: Some(external_id.into()),
        }],
        managing: HashMap::from([(id, SOURCE.to_string())]),
    }
}

#[test]
fn an_entry_outside_the_scope_is_never_created() {
    let upstream = vec![
        user("in", "in@corp.example", None),
        user("out", "out@other.example", None),
    ];
    let result = plan(
        &upstream,
        &empty_local(),
        opts_with(scope(&["corp.example"], &[])),
    );

    assert_eq!(change(&result, "in").outcome, Outcome::Create);
    assert_eq!(change(&result, "out").outcome, Outcome::Skip);
    assert_eq!(change(&result, "out").reason, REASON_OUT_OF_SCOPE);
    assert_eq!(
        result.counts().created,
        1,
        "only the in-scope entry is written"
    );
}

#[test]
fn an_in_scope_entry_still_updates_normally() {
    // The filter must not be so eager that it stops ordinary work: a linked user
    // inside the scope whose name changed is still an update.
    let id = Uuid::new_v4();
    let local = linked_local("u-1", id, "one@corp.example");
    let mut entry = user("u-1", "one@corp.example", Some("Engineering"));
    entry.display_name = Some("New Name".into());

    let result = plan(&[entry], &local, opts_with(scope(&[], &["Engineering"])));
    assert_eq!(change(&result, "u-1").outcome, Outcome::Update);
}

#[test]
fn a_linked_user_who_leaves_the_scope_is_disabled() {
    // The deliberate consequence of scoping: the directory still lists this
    // person, but this source no longer owns them, so the account is disabled
    // exactly as if they had been deleted (§7).
    let id = Uuid::new_v4();
    let local = linked_local("u-1", id, "one@corp.example");
    let upstream = vec![user("u-1", "one@corp.example", Some("Sales"))];

    let result = plan(&upstream, &local, opts_with(scope(&[], &["Engineering"])));

    // Two changes for one entry: the listing pass classifies it, the absent pass
    // acts on it. Both say the same thing, and neither is `absent_upstream`.
    assert_eq!(change(&result, "u-1").outcome, Outcome::Skip);
    assert_eq!(change(&result, "u-1").reason, REASON_OUT_OF_SCOPE);

    let planned = disable(&result, "u-1").expect("leaving the scope must disable the account");
    assert_eq!(planned.reason, REASON_OUT_OF_SCOPE);
    assert_eq!(result.counts().disabled, 1);
}

#[test]
fn a_transfer_is_distinguishable_from_a_departure_in_the_same_run() {
    // The headline requirement behind the reason strings: two identical disables
    // in one run, one caused by a department move and one by a deletion, and the
    // run history has to say which is which.
    let transfer_id = Uuid::new_v4();
    let gone_id = Uuid::new_v4();
    let local = LocalState {
        source_code: SOURCE.into(),
        links: vec![
            LinkSnapshot {
                external_id: "u-transfer".into(),
                user_id: transfer_id,
                source_hash: None,
            },
            LinkSnapshot {
                external_id: "u-gone".into(),
                user_id: gone_id,
                source_hash: None,
            },
        ],
        linked_users: vec![
            UserSnapshot {
                id: transfer_id,
                email: "transfer@corp.example".into(),
                username: Some("transfer".into()),
                display_name: "Transfer".into(),
                status: "active".into(),
                directory_groups: vec![],
                directory_disabled: false,
            },
            UserSnapshot {
                id: gone_id,
                email: "gone@corp.example".into(),
                username: Some("gone".into()),
                display_name: "Gone".into(),
                status: "active".into(),
                directory_groups: vec![],
                directory_disabled: false,
            },
        ],
        index: vec![
            UserIndexEntry {
                id: transfer_id,
                email: "transfer@corp.example".into(),
                username: Some("transfer".into()),
            },
            UserIndexEntry {
                id: gone_id,
                email: "gone@corp.example".into(),
                username: Some("gone".into()),
            },
        ],
        managing: HashMap::from([
            (transfer_id, SOURCE.to_string()),
            (gone_id, SOURCE.to_string()),
        ]),
    };

    // `u-transfer` is still listed, now in Sales. `u-gone` is not listed at all.
    let upstream = vec![user("u-transfer", "transfer@corp.example", Some("Sales"))];
    let result = plan(&upstream, &local, opts_with(scope(&[], &["Engineering"])));

    assert_eq!(change(&result, "u-transfer").reason, REASON_OUT_OF_SCOPE);
    assert_eq!(change(&result, "u-gone").reason, REASON_ABSENT_UPSTREAM);
    assert_eq!(
        disable(&result, "u-transfer").map(|c| c.reason.as_str()),
        Some(REASON_OUT_OF_SCOPE)
    );
    assert_eq!(
        disable(&result, "u-gone").map(|c| c.reason.as_str()),
        Some(REASON_ABSENT_UPSTREAM),
        "a deletion must not be reported as a transfer"
    );
    assert_eq!(result.counts().disabled, 2);
}

#[test]
fn a_scope_only_disables_users_the_source_already_owns() {
    // An out-of-scope entry that was never linked is not a disable target: the
    // absent pass walks links, so somebody the source never owned is left alone.
    let upstream = vec![user("u-out", "out@other.example", None)];
    let result = plan(
        &upstream,
        &empty_local(),
        opts_with(scope(&["corp.example"], &[])),
    );

    assert_eq!(result.counts().disabled, 0);
    assert_eq!(change(&result, "u-out").outcome, Outcome::Skip);
}

#[test]
fn a_limited_run_disables_nobody_when_the_scope_moves() {
    // `--limit` fetches a prefix, so its snapshot is not evidence of anything.
    // The scope must not become a back door around that: an out-of-scope entry is
    // skipped, never disabled, because the run reconciles nothing at all.
    let id = Uuid::new_v4();
    let local = linked_local("u-1", id, "one@corp.example");
    let upstream = vec![user("u-1", "one@corp.example", Some("Sales"))];

    let result = plan(
        &upstream,
        &local,
        PlanOptions {
            sync_groups: true,
            reconcile: false,
            scope: scope(&[], &["Engineering"]),
        },
    );

    assert_eq!(change(&result, "u-1").outcome, Outcome::Skip);
    assert_eq!(result.counts().disabled, 0);
}

#[test]
fn an_out_of_scope_entry_returned_twice_is_not_a_duplicate_error() {
    // The duplicate check exists to stop two accounts being created for one
    // external id. An entry this run declines to own creates nothing, so
    // reporting it as a broken source would be noise pointing at the wrong thing.
    let upstream = vec![
        user("out", "out@other.example", None),
        user("out", "out@other.example", None),
    ];
    let result = plan(
        &upstream,
        &empty_local(),
        opts_with(scope(&["corp.example"], &[])),
    );

    assert_eq!(result.counts().errors, 0);
    assert_eq!(result.counts().skipped, 2);
}

#[test]
fn an_entry_with_no_email_keeps_its_own_reason_over_the_scope_one() {
    // Order matters for diagnosis: a malformed entry is skipped for being
    // malformed, which tells the operator far more than "not in scope".
    let upstream = vec![user("u-blank", "", Some("Engineering"))];
    let result = plan(
        &upstream,
        &empty_local(),
        opts_with(scope(&[], &["Engineering"])),
    );

    let planned = change(&result, "u-blank");
    assert_eq!(planned.outcome, Outcome::Skip);
    assert!(
        planned.reason.contains("no usable email"),
        "reason was `{}`",
        planned.reason
    );
}

// ─── Config: the scope fields are validated at save time ──────────────────

fn ldap_config() -> serde_json::Value {
    json!({
        "url": "ldaps://ldap.corp.example:636",
        "bind_dn": "cn=svc,dc=corp,dc=example",
        "base_dn": "ou=people,dc=corp,dc=example",
        "username_attribute": "uid",
        "email_attribute": "mail",
        "external_id_attribute": "entryUUID"
    })
}

fn http_config() -> serde_json::Value {
    json!({
        "url": "https://api.corp.example/v1/users",
        "users_path": "data.users",
        "external_id_path": "id",
        "email_path": "email"
    })
}

#[test]
fn a_scope_that_reads_well_is_accepted_by_both_kinds() {
    let mut ldap = ldap_config();
    ldap["email_domains"] = json!(["corp.example"]);
    ldap["department_attribute"] = json!("department");
    ldap["department_values"] = json!(["Engineering"]);
    assert!(LdapConfig::parse(&ldap).is_ok());

    let mut http = http_config();
    http["email_domains"] = json!(["corp.example"]);
    http["department_path"] = json!("dept");
    http["department_values"] = json!(["Engineering"]);
    assert!(HttpJsonConfig::parse(&http).is_ok());
}

#[test]
fn department_values_with_nowhere_to_read_them_from_are_refused() {
    // Otherwise the filter matches nobody, which at run time is indistinguishable
    // from "the directory has no such departments" — and disables everyone the
    // source already manages.
    for mut raw in [ldap_config(), http_config()] {
        raw["department_values"] = json!(["Engineering"]);
        let err = SourceConfig::parse(
            if raw.get("users_path").is_some() {
                "http_json"
            } else {
                "ldap"
            },
            &raw,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("department_values needs department_"),
            "unexpected error for {raw}: {err}"
        );
    }
}

#[test]
fn a_wildcard_in_email_domains_is_refused() {
    // There is no pattern language on purpose: it could not be verified in the
    // preview, and one typo in a pattern silently widens or empties a source.
    for mut raw in [ldap_config(), http_config()] {
        raw["email_domains"] = json!(["*.corp.example"]);
        let kind = if raw.get("users_path").is_some() {
            "http_json"
        } else {
            "ldap"
        };
        let err = SourceConfig::parse(kind, &raw).unwrap_err().to_string();
        assert!(err.contains("no wildcards"), "unexpected error: {err}");
    }
}

#[test]
fn an_address_pasted_into_email_domains_is_refused() {
    // `bob@corp.example` would never match anything, because the comparison is on
    // the domain part alone. Refusing it names the mistake instead of letting the
    // admin conclude the directory has no users.
    for mut raw in [ldap_config(), http_config()] {
        raw["email_domains"] = json!(["bob@corp.example"]);
        let kind = if raw.get("users_path").is_some() {
            "http_json"
        } else {
            "ldap"
        };
        let err = SourceConfig::parse(kind, &raw).unwrap_err().to_string();
        assert!(
            err.contains("domains, not addresses"),
            "unexpected error: {err}"
        );
    }
}

#[test]
fn empty_scope_entries_are_refused() {
    for mut raw in [ldap_config(), http_config()] {
        raw["email_domains"] = json!(["corp.example", "   "]);
        let kind = if raw.get("users_path").is_some() {
            "http_json"
        } else {
            "ldap"
        };
        let err = SourceConfig::parse(kind, &raw).unwrap_err().to_string();
        assert!(
            err.contains("email_domains must not contain an empty entry"),
            "unexpected error: {err}"
        );
    }
}

#[test]
fn a_blank_department_attribute_is_refused() {
    let mut raw = ldap_config();
    raw["department_attribute"] = json!("  ");
    let err = LdapConfig::parse(&raw).unwrap_err().to_string();
    assert!(
        err.contains("department_attribute"),
        "unexpected error: {err}"
    );
}

#[test]
fn the_source_config_hands_the_scope_to_the_planner() {
    // The engine reads the scope through `SourceConfig`, so a field that parses
    // but never reaches the filter would be invisible: the sync would quietly
    // ignore the admin's scope.
    let mut ldap = ldap_config();
    ldap["email_domains"] = json!(["corp.example"]);
    ldap["department_attribute"] = json!("department");
    ldap["department_values"] = json!(["Engineering", "Platform"]);
    let scope = SourceConfig::parse("ldap", &ldap).unwrap().scope();
    assert_eq!(scope.email_domains, vec!["corp.example".to_string()]);
    assert_eq!(
        scope.department_values,
        vec!["Engineering".to_string(), "Platform".to_string()]
    );

    let mut http = http_config();
    http["email_domains"] = json!(["partner.example"]);
    let scope = SourceConfig::parse("http_json", &http).unwrap().scope();
    assert_eq!(scope.email_domains, vec!["partner.example".to_string()]);
    assert!(scope.department_values.is_empty());

    // A source with no scope at all stays empty, which is what keeps every
    // existing source behaving as it did.
    assert!(SourceConfig::parse("ldap", &ldap_config())
        .unwrap()
        .scope()
        .is_empty());
}
