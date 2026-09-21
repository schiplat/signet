//! DB-backed tests for the sync engine's writes (docs/directory-sync.md §6, §16).
//!
//! The planner is covered by `directory_plan.rs` without a database. What is left
//! for these tests is exactly the part a pure test cannot reach: that the SQL is
//! correct against the real schema, and that the §16 acceptance criterion — "a
//! second run reports `updated = 0`" — holds when the second run is planned from
//! what the first run actually stored, rather than from a hand-written fixture.
//!
//! `apply_plan` is the seam used here instead of `run_source`: it takes the plan
//! the real loaders produced, so no LDAP server is needed, and it is the same
//! function production code calls. Each test namespaces its data with its own
//! source code and cleans up through [`common::scoped`], so the suite is safe to
//! run against a shared development database.

mod common;

use signet::directory::engine::apply_plan;
use signet::directory::model::load_local_state;
use signet::directory::plan::{plan, Counts, Outcome, PlanOptions, ScopeFilter, UpstreamUser};
use signet::directory::source::SourceRow;
use signet::state::AppState;
use sqlx::PgPool;
use uuid::Uuid;

/// Emails and usernames are derived from the source code so two tests — or a
/// leftover from a previously failed run — cannot collide in a shared database.
fn email_of(source: &SourceRow, external_id: &str) -> String {
    format!("{external_id}@{}.test", source.code)
}

fn username_of(source: &SourceRow, external_id: &str) -> String {
    format!("{}/{external_id}", source.code)
}

/// One upstream person, with the managed fields the planner reads.
fn person(source: &SourceRow, external_id: &str, name: &str, groups: &[&str]) -> UpstreamUser {
    UpstreamUser {
        external_id: external_id.into(),
        external_dn: Some(format!("uid={external_id},ou=people,dc=corp")),
        email: email_of(source, external_id),
        username: Some(username_of(source, external_id)),
        display_name: Some(name.into()),
        department: None,
        groups: groups.iter().map(|g| g.to_string()).collect(),
    }
}

/// Runs the real load → plan pipeline for one source and applies it.
///
/// Production reaches the same two calls through `engine::run_source`; going
/// through the loaders (rather than constructing a plan by hand) is what makes
/// the idempotence assertions meaningful — the second plan is derived from the
/// database the first apply produced.
async fn sync(
    state: &AppState,
    source: &SourceRow,
    upstream: &[UpstreamUser],
    run_id: Uuid,
) -> signet::directory::plan::SyncPlan {
    let local = load_local_state(&state.pool, source.id, &source.code)
        .await
        .expect("snapshot local state");
    let planned = plan(
        upstream,
        &local,
        PlanOptions {
            allowed_email_domains: Vec::new(),
            sync_groups: source.sync_groups,
            reconcile: true,
            scope: ScopeFilter::default(),
        },
    );
    apply_plan(state, source, run_id, &planned, None)
        .await
        .expect("apply the plan");
    planned
}

/// A user provisioned by the sync, as stored. Mirrors the columns the engine
/// writes rather than the full `User` struct, so the test does not break when an
/// unrelated column is added.
#[derive(Debug, sqlx::FromRow)]
struct StoredUser {
    id: Uuid,
    sub: String,
    email: String,
    username: Option<String>,
    display_name: String,
    password_hash: String,
    status: String,
    role: String,
    provisioned_via: Option<String>,
    local_disabled: bool,
    directory_disabled: bool,
    scim_disabled: bool,
    directory_groups: Vec<String>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

async fn stored(pool: &PgPool, source_id: Uuid, external_id: &str) -> Option<StoredUser> {
    sqlx::query_as::<_, StoredUser>(
        r#"
        SELECT u.id, u.sub, u.email, u.username, u.display_name, u.password_hash, u.status,
               u.role, u.provisioned_via, u.local_disabled, u.directory_disabled, u.scim_disabled,
               u.directory_groups, u.updated_at
        FROM directory_entries e JOIN users u ON u.id = e.user_id
        WHERE e.source_id = $1 AND e.external_id = $2
        "#,
    )
    .bind(source_id)
    .bind(external_id)
    .fetch_optional(pool)
    .await
    .expect("read the linked user")
}

/// The whole create → re-run → update → disable lifecycle against a real schema.
#[tokio::test]
async fn create_rerun_update_and_disable_round_trip() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        let run_id = common::begin_run(&state.pool, source.id).await;

        let upstream = vec![
            person(&source, "e-1", "One Person", &["staff", "eng"]),
            person(&source, "e-2", "Two Person", &["staff"]),
        ];

        // ── Create ──────────────────────────────────────────────────────
        let first = sync(&state, &source, &upstream, run_id).await;
        assert_eq!(first.counts().created, 2, "changes={:#?}", first.changes);
        assert_eq!(first.counts().updated, 0);

        let one = stored(&state.pool, source.id, "e-1")
            .await
            .expect("e-1 must have been provisioned");
        // The email is normalized and the groups land in `directory_groups`,
        // kept apart from the locally-managed `groups`.
        assert_eq!(one.email, email_of(&source, "e-1"));
        assert_eq!(
            one.username.as_deref(),
            Some(username_of(&source, "e-1").as_str())
        );
        assert_eq!(one.display_name, "One Person");
        assert_eq!(one.directory_groups, vec!["eng", "staff"]);
        assert_eq!(one.status, "active");
        assert_eq!(one.role, "member");
        assert_eq!(one.provisioned_via.as_deref(), Some("ldap"));
        assert_eq!(
            one.password_hash, "",
            "a directory user has no local password: an empty hash makes password login impossible"
        );
        assert!(
            Uuid::parse_str(&one.sub).is_ok(),
            "providers expect a UUID-shaped subject, got {}",
            one.sub
        );

        // ── Re-run: nothing changes ─────────────────────────────────────
        // The §16 acceptance criterion. `updated_at` is the proof of the write:
        // the planner classifies and the SQL must genuinely skip the row, not
        // rewrite it with identical values.
        let second = sync(&state, &source, &upstream, run_id).await;
        assert_eq!(
            second.counts(),
            Counts {
                created: 0,
                updated: 0,
                disabled: 0,
                skipped: 2,
                conflicts: 0,
                errors: 0,
            },
            "changes={:#?}",
            second.changes
        );
        let after = stored(&state.pool, source.id, "e-1").await.unwrap();
        assert_eq!(
            after.updated_at, one.updated_at,
            "an unchanged user must not be rewritten"
        );

        // ── Update: a changed directory name propagates ──────────────────
        let renamed = vec![
            person(&source, "e-1", "One Renamed", &["staff", "eng", "ops"]),
            person(&source, "e-2", "Two Person", &["staff"]),
        ];
        let third = sync(&state, &source, &renamed, run_id).await;
        assert_eq!(third.counts().updated, 1);
        assert_eq!(third.counts().skipped, 1);
        let one = stored(&state.pool, source.id, "e-1").await.unwrap();
        assert_eq!(one.display_name, "One Renamed");
        assert_eq!(one.directory_groups, vec!["eng", "ops", "staff"]);

        // Group drift alone must also be repaired, even though the managed
        // fields are untouched: `directory_groups` is part of what the source
        // owns, and a hash that matches must not hide a tampered column.
        sqlx::query("UPDATE users SET directory_groups = '{}' WHERE id = $1")
            .bind(one.id)
            .execute(&state.pool)
            .await
            .unwrap();
        let repaired = sync(&state, &source, &renamed, run_id).await;
        assert_eq!(repaired.counts().updated, 1);
        assert_eq!(
            stored(&state.pool, source.id, "e-1")
                .await
                .unwrap()
                .directory_groups,
            vec!["eng", "ops", "staff"]
        );

        // ── Absent upstream: disabled, never deleted ─────────────────────
        let shrunk = vec![person(&source, "e-2", "Two Person", &["staff"])];
        let fourth = sync(&state, &source, &shrunk, run_id).await;
        assert_eq!(fourth.counts().disabled, 1, "changes={:#?}", fourth.changes);
        let one = stored(&state.pool, source.id, "e-1").await.unwrap();
        assert_eq!(one.status, "disabled");
        assert_eq!(
            one.email,
            email_of(&source, "e-1"),
            "the row survives: disabling is reversible, deleting is not"
        );
    })
    .await;
}

/// D3: a user the directory stops returning is disabled and their sessions are
/// revoked, so a departing employee does not keep browsing.
#[tokio::test]
async fn absent_entries_are_disabled_and_sessions_revoked() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        let run_id = common::begin_run(&state.pool, source.id).await;

        let upstream = vec![
            person(&source, "e-1", "One", &[]),
            person(&source, "e-2", "Two", &[]),
        ];
        sync(&state, &source, &upstream, run_id).await;

        let one = stored(&state.pool, source.id, "e-1").await.unwrap();
        sqlx::query(
            "INSERT INTO sessions (id, user_id, token_hash, expires_at) \
             VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour')",
        )
        .bind(Uuid::new_v4())
        .bind(one.id)
        .bind(format!("test-token-{}", Uuid::new_v4()))
        .execute(&state.pool)
        .await
        .expect("insert a session for the departing user");

        // `e-1` disappears from the directory.
        let shrunk = vec![person(&source, "e-2", "Two", &[])];
        let planned = sync(&state, &source, &shrunk, run_id).await;
        assert_eq!(planned.counts().disabled, 1);

        assert_eq!(
            stored(&state.pool, source.id, "e-1").await.unwrap().status,
            "disabled"
        );
        let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
            .bind(one.id)
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(sessions, 0, "a disabled user must not keep a live session");

        // Running again is a no-op: the disable already happened.
        let again = sync(&state, &source, &shrunk, run_id).await;
        assert_eq!(again.counts().disabled, 0);
        assert!(
            !again.changes.iter().any(|c| c.outcome == Outcome::Disable),
            "a settled disable must not be repeated"
        );
    })
    .await;
}

/// A local disable intent outlives the directory: `local_disabled` is only
/// cleared by an admin enable, so a user who is still present upstream does not
/// silently come back (§4.2).
#[tokio::test]
async fn local_disable_intent_survives_an_upstream_update() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        let run_id = common::begin_run(&state.pool, source.id).await;

        let upstream = vec![person(&source, "e-1", "One", &[])];
        sync(&state, &source, &upstream, run_id).await;

        let one = stored(&state.pool, source.id, "e-1").await.unwrap();
        // What `admin::set_status` writes when an admin disables a managed user.
        sqlx::query("UPDATE users SET status = 'disabled', local_disabled = TRUE WHERE id = $1")
            .bind(one.id)
            .execute(&state.pool)
            .await
            .unwrap();

        // The user is still in the directory, and the directory now reports a
        // new name. The update must be applied — but the account must stay
        // disabled.
        let changed = vec![person(&source, "e-1", "One Renamed", &[])];
        let planned = sync(&state, &source, &changed, run_id).await;
        assert_eq!(planned.counts().updated, 1);

        let one = stored(&state.pool, source.id, "e-1").await.unwrap();
        assert!(one.local_disabled, "the local intent must be preserved");
        assert_eq!(one.status, "disabled");
        assert_eq!(one.display_name, "One Renamed");
    })
    .await;
}

/// A limited run (`--limit`) only saw part of the directory, so it must never
/// disable anyone. This is the difference between a "sample" run and a
/// destructive mistake.
#[tokio::test]
async fn a_limited_run_does_not_disable_the_entries_it_did_not_fetch() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        let run_id = common::begin_run(&state.pool, source.id).await;

        let upstream = vec![
            person(&source, "e-1", "One", &[]),
            person(&source, "e-2", "Two", &[]),
        ];
        sync(&state, &source, &upstream, run_id).await;

        // Planned the way `run_source` plans a limited run: it passes the
        // fetched prefix of the directory, and the limit makes reconciliation
        // opt-out.
        let local = load_local_state(&state.pool, source.id, &source.code)
            .await
            .unwrap();
        let limited = plan(
            &upstream[..1],
            &local,
            PlanOptions {
                allowed_email_domains: Vec::new(),
                sync_groups: true,
                reconcile: false,
                scope: ScopeFilter::default(),
            },
        );
        assert!(!limited.reconciled);
        apply_plan(&state, &source, run_id, &limited, None)
            .await
            .unwrap();

        assert_eq!(
            stored(&state.pool, source.id, "e-2").await.unwrap().status,
            "active",
            "an entry the limit skipped is not evidence of deletion"
        );
    })
    .await;
}

/// An enable is a *transition*, and only the directory's own claim is released.
///
/// Both halves matter. Without the first, "when did this account come back"
/// has no answer; without the second, every routine update of an active user
/// would claim to have re-enabled them, and the event would say nothing.
#[tokio::test]
async fn a_returning_user_is_audited_as_enabled() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        let enabled = |pool: PgPool, code: String| async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_logs WHERE action = 'directory.user.enabled' \
                 AND detail ->> 'source' = $1",
            )
            .bind(code)
            .fetch_one(&pool)
            .await
            .expect("count the enable events")
        };

        let upstream = vec![person(&source, "e-1", "One", &[])];
        let run_id = common::begin_run(&state.pool, source.id).await;
        sync(&state, &source, &upstream, run_id).await;
        common::close_run(&state.pool, run_id).await;

        // An ordinary update of a user who was never disabled.
        let run_id = common::begin_run(&state.pool, source.id).await;
        let renamed = vec![person(&source, "e-1", "One Renamed", &[])];
        sync(&state, &source, &renamed, run_id).await;
        common::close_run(&state.pool, run_id).await;
        assert_eq!(
            stored(&state.pool, source.id, "e-1").await.unwrap().status,
            "active"
        );
        assert_eq!(
            enabled(state.pool.clone(), source.code.clone()).await,
            0,
            "updating an active user is not an enable"
        );

        // Gone upstream: the source disables the account.
        let run_id = common::begin_run(&state.pool, source.id).await;
        sync(&state, &source, &[], run_id).await;
        common::close_run(&state.pool, run_id).await;
        let gone = stored(&state.pool, source.id, "e-1").await.unwrap();
        assert_eq!(gone.status, "disabled");
        assert!(gone.directory_disabled, "the claim is the source's");

        // Back upstream: the claim is released and the account returns.
        let run_id = common::begin_run(&state.pool, source.id).await;
        sync(&state, &source, &upstream, run_id).await;
        let back = stored(&state.pool, source.id, "e-1").await.unwrap();
        assert_eq!(back.status, "active");
        assert!(!back.directory_disabled);
        assert_eq!(
            enabled(state.pool.clone(), source.code.clone()).await,
            1,
            "the return is recorded exactly once"
        );
    })
    .await;
}

/// A local claim outlives the directory's, so the source releasing its own is
/// not an enable.
///
/// This is the case that makes "the user is active now" the wrong thing to log
/// on: the account does not come back, and an audit entry saying it did would
/// send an operator looking for a user who is still locked out.
#[tokio::test]
async fn a_source_enable_under_a_local_claim_is_not_an_enable() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        let upstream = vec![person(&source, "e-1", "One", &[])];
        let run_id = common::begin_run(&state.pool, source.id).await;
        sync(&state, &source, &upstream, run_id).await;
        common::close_run(&state.pool, run_id).await;

        // Absent: the directory takes the account down and holds it.
        let run_id = common::begin_run(&state.pool, source.id).await;
        sync(&state, &source, &[], run_id).await;
        common::close_run(&state.pool, run_id).await;
        assert!(
            stored(&state.pool, source.id, "e-1")
                .await
                .unwrap()
                .directory_disabled
        );

        // The admin adds a hold of their own on top. Only now are both claims in
        // play, which is what the next run has to tell apart.
        let id = stored(&state.pool, source.id, "e-1").await.unwrap().id;
        sqlx::query("UPDATE users SET local_disabled = TRUE, status = 'disabled' WHERE id = $1")
            .bind(id)
            .execute(&state.pool)
            .await
            .expect("put a local hold on the account");

        // Back upstream: the directory releases its own claim, the account stays
        // down, and nothing happened that an operator can see.
        let run_id = common::begin_run(&state.pool, source.id).await;
        sync(&state, &source, &upstream, run_id).await;
        common::close_run(&state.pool, run_id).await;

        let user = stored(&state.pool, source.id, "e-1").await.unwrap();
        assert!(!user.directory_disabled, "the source let go");
        assert!(
            user.local_disabled,
            "but the admin's hold is not the source's to release"
        );
        assert_eq!(user.status, "disabled", "so the account stays disabled");

        let events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'directory.user.enabled' \
             AND detail ->> 'source' = $1",
        )
        .bind(&source.code)
        .fetch_one(&state.pool)
        .await
        .expect("count the enable events");
        assert_eq!(
            events, 0,
            "nothing an operator can see changed, so nothing may be recorded"
        );
    })
    .await;
}

/// The audit trail an operator relies on: a create is recorded per user (it is
/// low-volume and security-relevant) and excluded from webhook fan-out, while
/// the run summary is the event that gets delivered (§11.1).
#[tokio::test]
async fn provisioning_is_audited_without_fanning_out_per_entry() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        let run_id = common::begin_run(&state.pool, source.id).await;

        let upstream = vec![person(&source, "e-1", "One", &[])];
        sync(&state, &source, &upstream, run_id).await;

        let created: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'directory.user.created' \
             AND detail ->> 'source' = $1",
        )
        .bind(&source.code)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(created, 1);

        assert!(
            signet::directory::is_summary_only_action("directory.user.created"),
            "per-entry sync events must be excluded from webhook fan-out"
        );
        assert!(
            !signet::directory::is_summary_only_action("directory.sync.finished"),
            "the run summary is the event that IS delivered"
        );
    })
    .await;
}

/// Two sources: the higher-priority one keeps its authority, so the other cannot
/// rewrite the user or disable them (§4.1).
#[tokio::test]
async fn a_lower_priority_source_does_not_override_the_owner() {
    let Some(state) = common::state().await else {
        return;
    };
    let owner = common::create_source(&state.pool).await;
    let rival = common::create_source(&state.pool).await;
    // The second source outranks the first (lower priority number wins). Both
    // list the same person, which is why they must use the same email.
    let shared_email = format!("shared@{}x.test", owner.code);
    sqlx::query("UPDATE directory_sources SET priority = 10 WHERE id = $1")
        .bind(rival.id)
        .execute(&state.pool)
        .await
        .unwrap();
    let rival = signet::directory::source::get_by_code(&state.pool, &rival.code)
        .await
        .unwrap();

    common::run_scoped(
        state,
        vec![owner, rival],
        move |state, sources| async move {
            let owner = sources[0].clone();
            let rival = sources[1].clone();
            let owner_run = common::begin_run(&state.pool, owner.id).await;
            let rival_run = common::begin_run(&state.pool, rival.id).await;

            let entry = |external_id: &str, name: &str| UpstreamUser {
                external_id: external_id.into(),
                external_dn: None,
                email: shared_email.clone(),
                username: None,
                display_name: Some(name.into()),
                department: None,
                groups: vec![],
            };

            // The rival provisions the person first, so it owns them.
            sync(&state, &rival, &[entry("e-1", "Owned By Rival")], rival_run).await;
            let user = stored(&state.pool, rival.id, "e-1").await.unwrap();

            // The same person now appears in the lower-priority directory under a
            // different external id, with a different name. The account belongs to
            // the rival, so the planner neither claims it by email nor rewrites it:
            // the higher-priority source owns those attributes (§4.1). It is a skip,
            // not a conflict — a conflict is the *unowned* local account, which is
            // the account-takeover case that needs a human.
            let planned = sync(&state, &owner, &[entry("other-id", "Renamed")], owner_run).await;
            assert_eq!(
                planned.counts().skipped,
                1,
                "changes={:#?}",
                planned.changes
            );
            assert_eq!(planned.counts().conflicts, 0);
            assert_eq!(planned.counts().created, 0);
            assert!(
                planned.changes[0].reason.contains(&rival.code),
                "the report must name the source that owns the user, got {:?}",
                planned.changes[0].reason
            );

            let after = stored(&state.pool, rival.id, "e-1").await.unwrap();
            assert_eq!(after.id, user.id);
            assert_eq!(
                after.display_name, "Owned By Rival",
                "the owner's data must be untouched"
            );

            // Once both sources link the same person, the *lower*-precedence source
            // losing sight of them must not disable an account the owner still
            // manages (§4.1).
            sqlx::query(
                "INSERT INTO directory_entries (id, source_id, external_id, external_dn, user_id) \
             VALUES ($1, $2, 'other-id', NULL, $3)",
            )
            .bind(Uuid::new_v4())
            .bind(owner.id)
            .bind(user.id)
            .execute(&state.pool)
            .await
            .expect("link the user to the lower-priority source too");

            let planned = sync(&state, &owner, &[], owner_run).await;
            assert_eq!(
                planned.counts().disabled,
                0,
                "changes={:#?}",
                planned.changes
            );
            assert_eq!(planned.counts().skipped, 1);
            assert_eq!(
                stored(&state.pool, rival.id, "e-1").await.unwrap().status,
                "active",
                "the source that no longer lists the user is not the one that owns them"
            );
        },
    )
    .await;
}

/// `--dry-run` must be a genuine no-op: it plans and reports without writing, so
/// the report can be trusted before anything is applied.
#[tokio::test]
async fn a_dry_run_writes_nothing() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        // `run_source` returns before `open_run` when `dry_run` is set, so
        // planning really is all that happens — which is what this reproduces.
        let local = load_local_state(&state.pool, source.id, &source.code)
            .await
            .unwrap();
        let dry = plan(
            &[person(&source, "e-1", "One", &[])],
            &local,
            PlanOptions {
                allowed_email_domains: Vec::new(),
                sync_groups: true,
                reconcile: true,
                scope: ScopeFilter::default(),
            },
        );
        assert_eq!(dry.counts().created, 1, "changes={:#?}", dry.changes);
        assert!(stored(&state.pool, source.id, "e-1").await.is_none());
    })
    .await;
}

/// The sync must not release a disable the IdP asked for.
///
/// The sync's update path re-derives `status` whenever a managed field changes,
/// and before migration `026` that meant writing `'active'` over a SCIM
/// deactivation: the IdP disabled someone, they changed their display name, and
/// the account came back. Each authority now records its own claim, so the sync
/// releases only its own.
#[tokio::test]
async fn the_sync_does_not_release_an_idp_disable() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        let run_id = common::begin_run(&state.pool, source.id).await;
        sync(
            &state,
            &source,
            &[person(&source, "e-1", "One Person", &["staff"])],
            run_id,
        )
        .await;

        let id = stored(&state.pool, source.id, "e-1")
            .await
            .expect("e-1 must have been provisioned")
            .id;
        sqlx::query(
            "UPDATE users SET scim_disabled = TRUE, status = 'disabled', updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(id)
        .execute(&state.pool)
        .await
        .expect("the IdP deactivates the account");

        // A managed field changes, which is what made the old update path run.
        let applied = sync(
            &state,
            &source,
            &[person(&source, "e-1", "Renamed Person", &["staff"])],
            run_id,
        )
        .await;
        assert!(
            applied.counts().updated >= 1,
            "the update path must have run: {:#?}",
            applied.changes
        );

        let after = stored(&state.pool, source.id, "e-1")
            .await
            .expect("e-1 is still linked");
        assert_eq!(
            after.display_name, "Renamed Person",
            "the sync still manages its own fields"
        );
        assert_eq!(after.status, "disabled", "the IdP's claim must survive");
        assert!(after.scim_disabled, "and must not be cleared");
        assert!(
            !after.directory_disabled,
            "the sync releases only its own claim"
        );
    })
    .await;
}

/// A user who reappears upstream is re-enabled even with nothing else changed.
///
/// Absence disables the account and sets the sync's claim, but an account that
/// comes back identical has no managed-field change to notice — so without the
/// claim being part of the comparison the planner reports `Unchanged`, writes
/// nothing, and the account stays disabled for good.
#[tokio::test]
async fn a_reappearing_user_is_re_enabled_without_a_field_change() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;

    common::scoped(state, source, |state, source| async move {
        let run_id = common::begin_run(&state.pool, source.id).await;
        let upstream = [person(&source, "e-1", "One Person", &["staff"])];
        sync(&state, &source, &upstream, run_id).await;

        // ── Absent upstream: disabled, and the sync holds the claim ─────
        let gone = sync(&state, &source, &[], run_id).await;
        assert_eq!(gone.counts().disabled, 1, "changes={:#?}", gone.changes);
        let disabled = stored(&state.pool, source.id, "e-1")
            .await
            .expect("the account is kept, not deleted");
        assert_eq!(disabled.status, "disabled");
        assert!(disabled.directory_disabled, "the sync should claim it");

        // ── Back, with every managed field identical ────────────────────
        let back = sync(&state, &source, &upstream, run_id).await;
        assert_eq!(
            back.counts().updated,
            1,
            "reappearing must be an update, not `unchanged`: {:#?}",
            back.changes
        );

        let after = stored(&state.pool, source.id, "e-1")
            .await
            .expect("e-1 is still linked");
        assert!(!after.directory_disabled, "the claim must be released");
        assert_eq!(after.status, "active", "and the account usable again");
    })
    .await;
}
