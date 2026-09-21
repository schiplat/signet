//! Contract tests for the sync planner (docs/directory-sync.md §6.2–§6.4).
//!
//! The planner is a pure function, which is what makes the §16 acceptance
//! criterion "a second run reports `updated = 0`" testable without a directory
//! or a database: feed it the state a first run would have produced and assert
//! it decides to change nothing.

use signet::directory::plan::{
    fingerprint, normalize_groups, plan, LinkSnapshot, LocalState, ManagedFields, Outcome,
    PlanOptions, ScopeFilter, UpstreamUser, UserIndexEntry, UserSnapshot,
};
use std::collections::HashMap;
use uuid::Uuid;

const SOURCE: &str = "corp-ldap";

fn opts() -> PlanOptions {
    PlanOptions {
        allowed_email_domains: Vec::new(),
        sync_groups: true,
        reconcile: true,
        scope: ScopeFilter::default(),
    }
}

fn upstream(external_id: &str, email: &str) -> UpstreamUser {
    UpstreamUser {
        external_id: external_id.into(),
        external_dn: Some(format!("uid={external_id},ou=people,dc=corp")),
        email: email.into(),
        username: Some(external_id.into()),
        display_name: Some(format!("{external_id} Example")),
        department: None,
        groups: vec!["staff".into()],
    }
}

fn index(id: Uuid, email: &str, username: &str) -> UserIndexEntry {
    UserIndexEntry {
        id,
        email: email.into(),
        username: Some(username.into()),
    }
}

/// One of each `Outcome` from a single mixed upstream set, so the classification
/// rules are pinned in one place.
#[test]
fn classifies_new_linked_absent_and_colliding_entries() {
    let linked_id = Uuid::new_v4();
    let local_id = Uuid::new_v4();
    let gone_id = Uuid::new_v4();
    let rival_id = Uuid::new_v4();
    let rival_gone_id = Uuid::new_v4();

    let local = LocalState {
        source_code: SOURCE.into(),
        links: vec![
            LinkSnapshot {
                external_id: "u-linked".into(),
                user_id: linked_id,
                source_hash: None,
            },
            LinkSnapshot {
                external_id: "u-gone".into(),
                user_id: gone_id,
                source_hash: None,
            },
            LinkSnapshot {
                external_id: "u-elsewhere".into(),
                user_id: rival_id,
                source_hash: None,
            },
            LinkSnapshot {
                external_id: "u-rival-gone".into(),
                user_id: rival_gone_id,
                source_hash: None,
            },
        ],
        linked_users: vec![
            UserSnapshot {
                id: linked_id,
                email: "linked@corp.com".into(),
                username: Some("linked".into()),
                display_name: "stale name".into(),
                status: "active".into(),
                directory_groups: vec![],
                directory_disabled: false,
            },
            UserSnapshot {
                id: gone_id,
                email: "gone@corp.com".into(),
                username: Some("gone".into()),
                display_name: "Gone".into(),
                status: "active".into(),
                directory_groups: vec![],
                directory_disabled: false,
            },
            UserSnapshot {
                id: rival_id,
                email: "elsewhere@corp.com".into(),
                username: Some("elsewhere".into()),
                display_name: "Elsewhere".into(),
                status: "active".into(),
                directory_groups: vec![],
                directory_disabled: false,
            },
            UserSnapshot {
                id: rival_gone_id,
                email: "rival-gone@corp.com".into(),
                username: Some("rival-gone".into()),
                display_name: "Rival Gone".into(),
                status: "active".into(),
                directory_groups: vec![],
                directory_disabled: false,
            },
        ],
        index: vec![
            index(linked_id, "linked@corp.com", "linked"),
            index(gone_id, "gone@corp.com", "gone"),
            index(rival_id, "elsewhere@corp.com", "elsewhere"),
            index(rival_gone_id, "rival-gone@corp.com", "rival-gone"),
            index(local_id, "taken@corp.com", "taken"),
        ],
        managing: HashMap::from([
            (linked_id, SOURCE.to_string()),
            (gone_id, SOURCE.to_string()),
            // Higher-priority source owns these two (§4.1).
            (rival_id, "hr-ldap".to_string()),
            (rival_gone_id, "hr-ldap".to_string()),
        ]),
    };

    let upstream = vec![
        upstream("u-linked", "linked@corp.com"), // linked, name changed -> Update
        upstream("u-new", "new@corp.com"),       // no link, free address -> Create
        upstream("u-takeover", "taken@corp.com"), // collides with a local user
        upstream("u-elsewhere", "elsewhere@corp.com"), // owned by another source
        upstream("u-blank", ""),                 // unusable entry -> Skip
                                                 // u-gone and u-rival-gone are absent upstream.
    ];

    let result = plan(&upstream, &local, opts());
    let outcome_of = |id: &str| {
        result
            .changes
            .iter()
            .find(|c| c.external_id == id)
            .unwrap_or_else(|| panic!("no change planned for {id}"))
            .outcome
    };

    assert_eq!(outcome_of("u-linked"), Outcome::Update);
    assert_eq!(outcome_of("u-new"), Outcome::Create);
    assert_eq!(outcome_of("u-takeover"), Outcome::Conflict);
    assert_eq!(outcome_of("u-blank"), Outcome::Skip);

    assert_eq!(
        outcome_of("u-gone"),
        Outcome::Disable,
        "we own it, it is gone"
    );
    // `u-elsewhere` and `u-rival-gone` are owned by `hr-ldap`, which outranks
    // this source: it neither rewrites their attributes nor disables them.
    assert_eq!(outcome_of("u-elsewhere"), Outcome::Skip);
    assert_eq!(outcome_of("u-rival-gone"), Outcome::Skip);

    let disable_count = result
        .changes
        .iter()
        .filter(|c| c.outcome == Outcome::Disable)
        .count();
    assert_eq!(
        disable_count, 1,
        "a lower-precedence source must not disable a user another source manages"
    );

    // Counters must stay consistent with the classifications.
    let counts = result.counts();
    assert_eq!(
        (
            counts.created,
            counts.updated,
            counts.conflicts,
            counts.skipped
        ),
        (1, 1, 1, 3)
    );
    assert_eq!(counts.disabled, 1);
}

/// The §16 acceptance criterion: re-running over unchanged data is a no-op.
#[test]
fn rerun_after_a_successful_apply_plans_no_writes() {
    let linked_id = Uuid::new_v4();
    let entry = upstream("u-1", "one@corp.com");
    let fields = ManagedFields::from_upstream(&entry);
    let groups = vec!["staff".to_string()];
    let hash = fingerprint(&fields, Some(&groups));

    let local = LocalState {
        source_code: SOURCE.into(),
        links: vec![LinkSnapshot {
            external_id: "u-1".into(),
            user_id: linked_id,
            // Exactly what the apply step would have stored.
            source_hash: Some(hash),
        }],
        linked_users: vec![UserSnapshot {
            id: linked_id,
            email: fields.email.clone(),
            username: fields.username.clone(),
            display_name: fields.display_name.clone(),
            status: "active".into(),
            directory_groups: groups,
            directory_disabled: false,
        }],
        index: vec![index(linked_id, &fields.email, "u-1")],
        managing: HashMap::from([(linked_id, SOURCE.to_string())]),
    };

    let result = plan(&[entry], &local, opts());
    assert_eq!(result.changes.len(), 1);
    assert_eq!(result.changes[0].outcome, Outcome::Unchanged);
    assert_eq!(result.counts().updated, 0);
}

/// A fingerprint that matches must not hide a corrupted `directory_groups`: the
/// group check re-writes rather than trusting the hash.
#[test]
fn drifting_groups_are_rewritten_even_when_the_hash_matches() {
    let linked_id = Uuid::new_v4();
    let entry = upstream("u-1", "one@corp.com");
    let fields = ManagedFields::from_upstream(&entry);
    let hash = fingerprint(&fields, Some(&["staff".to_string()]));

    let local = LocalState {
        source_code: SOURCE.into(),
        links: vec![LinkSnapshot {
            external_id: "u-1".into(),
            user_id: linked_id,
            source_hash: Some(hash),
        }],
        linked_users: vec![UserSnapshot {
            id: linked_id,
            email: fields.email.clone(),
            username: fields.username.clone(),
            display_name: fields.display_name.clone(),
            status: "active".into(),
            directory_groups: vec!["someone-elses-group".into()],
            directory_disabled: false,
        }],
        index: vec![index(linked_id, &fields.email, "u-1")],
        managing: HashMap::from([(linked_id, SOURCE.to_string())]),
    };

    let result = plan(&[entry], &local, opts());
    assert_eq!(result.changes[0].outcome, Outcome::Update);
}

/// A `--limit` run must never disable the entries it did not fetch.
#[test]
fn limited_runs_do_not_disable_anything() {
    let known_id = Uuid::new_v4();
    let beyond_limit_id = Uuid::new_v4();
    let entry = upstream("u-1", "one@corp.com");
    let fields = ManagedFields::from_upstream(&entry);
    let hash = fingerprint(&fields, Some(&["staff".to_string()]));
    let local = LocalState {
        source_code: SOURCE.into(),
        links: vec![
            LinkSnapshot {
                external_id: "u-1".into(),
                user_id: known_id,
                source_hash: Some(hash),
            },
            LinkSnapshot {
                external_id: "u-2".into(),
                user_id: beyond_limit_id,
                source_hash: None,
            },
        ],
        linked_users: vec![
            UserSnapshot {
                id: known_id,
                email: fields.email.clone(),
                username: fields.username.clone(),
                display_name: fields.display_name.clone(),
                status: "active".into(),
                directory_groups: vec!["staff".into()],
                directory_disabled: false,
            },
            UserSnapshot {
                id: beyond_limit_id,
                email: "two@corp.com".into(),
                username: Some("two".into()),
                display_name: "Two".into(),
                status: "active".into(),
                directory_groups: vec![],
                directory_disabled: false,
            },
        ],
        index: vec![
            index(known_id, "one@corp.com", "one"),
            index(beyond_limit_id, "two@corp.com", "two"),
        ],
        managing: HashMap::from([
            (known_id, SOURCE.to_string()),
            (beyond_limit_id, SOURCE.to_string()),
        ]),
    };

    let result = plan(
        &[entry],
        &local,
        PlanOptions {
            allowed_email_domains: Vec::new(),
            sync_groups: true,
            reconcile: false,
            scope: ScopeFilter::default(),
        },
    );
    assert!(!result.reconciled);
    assert_eq!(result.counts().disabled, 0);
    assert_eq!(result.counts().skipped, 1, "u-1 is unchanged");
}

/// Reconciling the full set disables what the source no longer returns.
#[test]
fn absent_entries_are_disabled_but_never_deleted() {
    let gone_id = Uuid::new_v4();
    let already_disabled_id = Uuid::new_v4();
    let local = LocalState {
        source_code: SOURCE.into(),
        links: vec![
            LinkSnapshot {
                external_id: "u-gone".into(),
                user_id: gone_id,
                source_hash: None,
            },
            LinkSnapshot {
                external_id: "u-disabled".into(),
                user_id: already_disabled_id,
                source_hash: None,
            },
        ],
        linked_users: vec![
            UserSnapshot {
                id: gone_id,
                email: "gone@corp.com".into(),
                username: Some("gone".into()),
                display_name: "Gone".into(),
                status: "active".into(),
                directory_groups: vec![],
                directory_disabled: false,
            },
            UserSnapshot {
                id: already_disabled_id,
                email: "disabled@corp.com".into(),
                username: Some("disabled".into()),
                display_name: "Disabled".into(),
                status: "disabled".into(),
                directory_groups: vec![],
                directory_disabled: false,
            },
        ],
        index: vec![
            index(gone_id, "gone@corp.com", "gone"),
            index(already_disabled_id, "disabled@corp.com", "disabled"),
        ],
        managing: HashMap::from([
            (gone_id, SOURCE.to_string()),
            (already_disabled_id, SOURCE.to_string()),
        ]),
    };

    let result = plan(&[], &local, opts());
    assert_eq!(
        result.counts().disabled,
        1,
        "only the active one is disabled"
    );
    assert_eq!(
        result.counts().skipped,
        1,
        "the disabled one is already settled"
    );

    let disable = result
        .changes
        .iter()
        .find(|c| c.outcome == Outcome::Disable)
        .expect("one disable");
    assert_eq!(disable.user_id, Some(gone_id));
    assert_eq!(disable.reason, "absent_upstream");
}

#[test]
fn duplicate_upstream_emails_do_not_create_two_accounts() {
    let result = plan(
        &[
            upstream("u-1", "same@corp.com"),
            upstream("u-2", "same@corp.com"),
        ],
        &LocalState {
            source_code: SOURCE.into(),
            ..Default::default()
        },
        opts(),
    );
    assert_eq!(result.counts().created, 1);
    assert_eq!(result.counts().conflicts, 1);
    assert!(result
        .changes
        .iter()
        .any(|c| c.outcome == Outcome::Conflict && c.reason.contains("u-1")));
}

/// A repeated external id means the source is broken; it must not be treated as
/// two different people.
#[test]
fn a_repeated_external_id_is_an_error_not_a_second_user() {
    let result = plan(
        &[
            upstream("u-1", "one@corp.com"),
            upstream("u-1", "two@corp.com"),
        ],
        &LocalState {
            source_code: SOURCE.into(),
            ..Default::default()
        },
        opts(),
    );
    assert_eq!(result.counts().created, 1);
    assert_eq!(result.counts().errors, 1);
}

#[test]
fn display_name_falls_back_to_the_email_local_part() {
    let entry = UpstreamUser {
        external_id: "u-1".into(),
        external_dn: None,
        email: "Someone@Corp.com".into(),
        username: None,
        display_name: Some("   ".into()),
        department: None,
        groups: vec![],
    };
    let fields = ManagedFields::from_upstream(&entry);
    // Email is normalized, and the fallback must match the JIT-provisioning
    // behaviour in `federation/link.rs`.
    assert_eq!(fields.email, "someone@corp.com");
    assert_eq!(fields.display_name, "someone");
    assert_eq!(fields.username, None);
}

#[test]
fn opting_out_of_group_sync_leaves_groups_alone() {
    let entry = upstream("u-1", "one@corp.com");
    let result = plan(
        &[entry],
        &LocalState {
            source_code: SOURCE.into(),
            ..Default::default()
        },
        PlanOptions {
            allowed_email_domains: Vec::new(),
            sync_groups: false,
            reconcile: true,
            scope: ScopeFilter::default(),
        },
    );
    assert_eq!(result.changes[0].outcome, Outcome::Create);
    assert!(
        result.changes[0].groups.is_none(),
        "groups must not be owned when sync_groups is off"
    );
}

#[test]
fn fingerprint_normalizes_groups_and_encodes_presence() {
    let fields = ManagedFields {
        username: None,
        email: "a@b".into(),
        display_name: "A".into(),
    };

    let raw_a = vec!["b".to_string(), "a".to_string()];
    let raw_b = vec!["a".to_string(), "b".to_string()];
    let hash_a = fingerprint(&fields, Some(&normalize_groups(&raw_a)));
    let hash_b = fingerprint(&fields, Some(&normalize_groups(&raw_b)));
    // Normalization is what buys order independence: the hash itself is
    // order-sensitive, so the planner must sort before hashing.
    assert_eq!(hash_a, hash_b);
    assert_ne!(fingerprint(&fields, Some(&raw_a)), hash_a);

    // `None` (groups not owned) must differ from an empty owned list, otherwise
    // turning group sync off would look like "no groups".
    assert_ne!(fingerprint(&fields, None), fingerprint(&fields, Some(&[])));
    // Presence tag: an absent username differs from an empty one.
    assert_ne!(
        fingerprint(&fields, None),
        fingerprint(
            &ManagedFields {
                username: Some(String::new()),
                ..fields.clone()
            },
            None
        )
    );
}
