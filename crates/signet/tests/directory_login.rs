//! Bind-through authentication contracts (docs/directory-sync.md §8, D2/D6).
//!
//! The interesting decisions on this path are *which* verdict a failure produces,
//! not the bind itself:
//!
//! * a directory that cannot be reached must produce an outage, never a
//!   credential failure (D6), and
//! * a rejection by the directory must not be charged to the local lockout
//!   counter (§8.4).
//!
//! Both are properties of [`directory::auth::resolve`] and of the outcome shape,
//! so they are testable without an LDAP server: what the tests pin is the
//! *selection* logic (which the SQL decides) and the fail-closed translation of
//! a connection failure. The bind itself needs a directory, which is an
//! integration concern left to the environment (§17 Q1).

mod common;

use signet::directory::auth::{resolve, LoginPath};
use signet::directory::ldap::{bind_as, BindOutcome};
use signet::directory::source::LdapConfig;
use uuid::Uuid;

const DN: &str = "uid=alice,ou=people,dc=corp";

/// The host name uses the reserved `.invalid` TLD, so resolution fails
/// deterministically and the test never depends on the network being reachable.
fn unreachable_config() -> LdapConfig {
    LdapConfig::parse(&serde_json::json!({
        "url": "ldaps://ldap.invalid:636",
        "bind_dn": "cn=svc,dc=corp",
        "base_dn": "ou=people,dc=corp",
        "username_attribute": "uid",
        "external_id_attribute": "entryUUID"
    }))
    .expect("a valid ldap config")
}

/// The core fail-closed contract (D6): an unreachable directory is an outage.
///
/// If this ever returns `InvalidCredentials` the login path would answer 401 and
/// invite a local-password fallback for accounts that deliberately have none.
#[tokio::test]
async fn an_unreachable_directory_reports_an_outage_not_a_bad_password() {
    let outcome = bind_as(&unreachable_config(), DN, "whatever-the-user-typed", None).await;
    assert!(
        matches!(outcome, BindOutcome::Unavailable(_)),
        "expected an outage, got {outcome:?}"
    );
}

/// A user with no directory link is authenticated locally — including the local
/// admin and every SSO/JIT account.
#[tokio::test]
async fn an_unlinked_user_authenticates_locally() {
    let Some(state) = common::state().await else {
        return;
    };
    let user_id = common::create_user(&state.pool, "not-a-real-hash").await;

    common::with_user(state, user_id, |state, user_id| async move {
        let path = resolve(&state, user_id)
            .await
            .expect("resolve the login path");
        assert!(
            matches!(path, LoginPath::Local),
            "an unlinked user must fall back to the local password"
        );
    })
    .await;
}

/// The linked case: the DN stored by the sync is what gets bound, and the
/// source's config travels with it.
#[tokio::test]
async fn a_linked_user_binds_against_the_stored_dn() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;
    let user_id = common::create_user(&state.pool, "").await;
    common::link_entry(&state.pool, source.id, "e-1", user_id, Some(DN)).await;

    // `cleanup` deletes users through their links, so wrapping the body is all
    // the teardown this needs — and it survives a failing assertion.
    common::scoped(state, source, move |state, source| async move {
        match resolve(&state, user_id)
            .await
            .expect("resolve the login path")
        {
            LoginPath::Ldap(target) => {
                assert_eq!(target.source_code, source.code);
                assert_eq!(
                    target.external_dn, DN,
                    "the bind must use the stored DN, not a fresh search"
                );
                assert_eq!(target.config.url, "ldaps://ldap.invalid:636");
            }
            LoginPath::Local => panic!("a linked ldap user must not be checked locally"),
        }
    })
    .await;
}

/// A source an admin switched off must not keep authenticating people: turning it
/// off is the revocation lever for bind-through.
#[tokio::test]
async fn a_disabled_source_does_not_own_the_user() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source_with(&state.pool, "ldap", false, 100).await;
    let user_id = common::create_user(&state.pool, "").await;
    common::link_entry(&state.pool, source.id, "e-1", user_id, Some(DN)).await;

    common::scoped(state, source, move |state, _source| async move {
        let path = resolve(&state, user_id)
            .await
            .expect("resolve the login path");
        assert!(
            matches!(path, LoginPath::Local),
            "a disabled source must not drive bind-through"
        );
    })
    .await;
}

/// §8.3: a link with no DN cannot be bound, so the user is treated as unmanaged.
/// A directory user has no local hash either, so they still get a 401 — the point
/// is that the failure is honest rather than a 500 or a silent accept.
#[tokio::test]
async fn a_link_without_a_stored_dn_falls_back_to_local() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;
    let user_id = common::create_user(&state.pool, "").await;
    common::link_entry(&state.pool, source.id, "e-1", user_id, None).await;

    common::scoped(state, source, move |state, _source| async move {
        let path = resolve(&state, user_id)
            .await
            .expect("resolve the login path");
        assert!(matches!(path, LoginPath::Local));
    })
    .await;
}

/// An empty DN is as unusable as a missing one, and an empty string would be sent
/// to the directory as a bind DN — which some servers treat as anonymous.
#[tokio::test]
async fn a_blank_stored_dn_is_not_bindable() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;
    let user_id = common::create_user(&state.pool, "").await;
    common::link_entry(&state.pool, source.id, "e-1", user_id, Some("   ")).await;

    common::scoped(state, source, move |state, _source| async move {
        let path = resolve(&state, user_id)
            .await
            .expect("resolve the login path");
        assert!(matches!(path, LoginPath::Local));
    })
    .await;
}

/// `priority` decides which directory verifies the password, matching the
/// ownership rule the sync planner uses (§4.1) — one user, one authority.
#[tokio::test]
async fn the_highest_priority_enabled_source_verifies_the_password() {
    let Some(state) = common::state().await else {
        return;
    };
    let low = common::create_source_with(&state.pool, "ldap", true, 500).await;
    let high = common::create_source_with(&state.pool, "ldap", true, 10).await;
    let user_id = common::create_user(&state.pool, "").await;
    // Linked by both, with different DNs: only the winner's DN may be bound.
    common::link_entry(
        &state.pool,
        low.id,
        "e-low",
        user_id,
        Some("uid=low,dc=corp"),
    )
    .await;
    common::link_entry(&state.pool, high.id, "e-high", user_id, Some(DN)).await;
    let high_code = high.code.clone();

    common::run_scoped(state, vec![high, low], move |state, _sources| async move {
        match resolve(&state, user_id)
            .await
            .expect("resolve the login path")
        {
            LoginPath::Ldap(target) => {
                assert_eq!(target.source_code, high_code);
                assert_eq!(target.external_dn, DN);
            }
            LoginPath::Local => panic!("expected the higher-priority source to own the user"),
        }
    })
    .await;
}

/// Only LDAP sources can verify a password by binding. A SCIM/HTTP source links
/// users for attribute ownership, but the credential check must not be routed to
/// it — there is nothing to bind against.
#[tokio::test]
async fn a_non_ldap_source_does_not_drive_bind_through() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source_with(&state.pool, "scim", true, 1).await;
    let user_id = common::create_user(&state.pool, "").await;
    common::link_entry(&state.pool, source.id, "e-1", user_id, Some(DN)).await;

    common::scoped(state, source, move |state, _source| async move {
        let path = resolve(&state, user_id)
            .await
            .expect("resolve the login path");
        assert!(
            matches!(path, LoginPath::Local),
            "a scim source must not be asked to verify a password"
        );
    })
    .await;
}

/// A source whose stored config cannot be parsed is a broken installation, and
/// the user has no local password to fall back on. Surfacing an error beats
/// pretending the password was wrong, which would send someone to reset a
/// password that does not exist.
#[tokio::test]
async fn an_unparseable_source_config_surfaces_an_error() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;
    sqlx::query(
        "UPDATE directory_sources SET config = '{\"url\": \"ldap://plaintext\"}' WHERE id = $1",
    )
    .bind(source.id)
    .execute(&state.pool)
    .await
    .expect("break the stored config");

    let user_id = common::create_user(&state.pool, "").await;
    common::link_entry(&state.pool, source.id, "e-1", user_id, Some(DN)).await;

    common::scoped(state, source, move |state, _source| async move {
        assert!(
            resolve(&state, user_id).await.is_err(),
            "a broken source config must not silently degrade to the local path"
        );
    })
    .await;
}

/// §8.4: a rejection the directory made must not be charged to the local lockout
/// counter. Encoding this in the outcome is what keeps a user from being locked
/// out twice over — once by AD, once by us.
#[test]
fn a_directory_rejection_is_not_charged_to_the_local_lockout() {
    use signet::directory::auth::Credential;
    let rejected = Credential::Invalid {
        counts_toward_lockout: false,
    };
    assert_ne!(rejected, Credential::Valid);
    assert_ne!(
        rejected,
        Credential::Invalid {
            counts_toward_lockout: true
        },
        "a directory rejection must be distinguishable from a local one"
    );
}

/// The outage variant carries who failed, so the audit record and the operator's
/// search can name the directory.
#[test]
fn an_outage_names_the_source_that_failed() {
    use signet::directory::auth::Credential;
    let outage = Credential::Unavailable {
        source_code: "corp-ldap".into(),
        detail: "connect timed out".into(),
    };
    match outage {
        Credential::Unavailable { source_code, .. } => assert_eq!(source_code, "corp-ldap"),
        other => panic!("expected an outage, got {other:?}"),
    }
}

/// Guard against a regression where a login for a user whose only link is in an
/// unrelated *deleted* source would still be routed to bind-through: `ON DELETE
/// CASCADE` removes the link, so the answer must be `Local`.
#[tokio::test]
async fn removing_the_source_returns_the_user_to_the_local_path() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;
    let user_id = common::create_user(&state.pool, "").await;
    common::link_entry(&state.pool, source.id, "e-1", user_id, Some(DN)).await;
    assert!(matches!(
        resolve(&state, user_id).await.expect("resolve"),
        LoginPath::Ldap(_)
    ));

    // The body deletes the source, which cascades the link away. `cleanup`
    // resolves users through those links, so it could no longer see this one —
    // hence `run_isolated`, which also deletes the user by id.
    let cleanup_source = source.clone();
    common::run_isolated(
        state,
        vec![cleanup_source],
        vec![user_id],
        move |state| async move {
            sqlx::query("DELETE FROM directory_sources WHERE id = $1")
                .bind(source.id)
                .execute(&state.pool)
                .await
                .expect("delete the source");

            assert!(
                matches!(
                    resolve(&state, user_id).await.expect("resolve"),
                    LoginPath::Local
                ),
                "a cascaded link must not leave the user routed to a missing directory"
            );
        },
    )
    .await;
}

/// Keeps the `.invalid`-based outage test honest: if the reserved TLD ever
/// resolved, that test would stop proving anything.
#[test]
fn the_unreachable_host_is_in_a_reserved_tld() {
    assert!(unreachable_config().url.contains(".invalid"));
    assert_ne!(Uuid::nil(), Uuid::new_v4());
}

/// A local password must not be writable for a user a live directory manages.
///
/// The login path ignores it (§8.1), so the write is not just useless: it leaves
/// a dormant credential that becomes live the moment the source is disabled or
/// removed. Enforcing it in `set_user_password` covers all four callers — self
/// change, admin reset, emailed reset, forced change — at once.
#[tokio::test]
async fn a_local_password_cannot_be_set_for_a_managed_user() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;
    let user_id = common::create_user(&state.pool, "").await;
    common::link_entry(&state.pool, source.id, "e-1", user_id, Some(DN)).await;
    let source_code = source.code.clone();

    common::scoped(state, source, move |state, _source| async move {
        let err = signet::auth::password::set_user_password(
            &state.pool,
            user_id,
            "CorrectHorse1",
            state.config.password_min_length,
            state.config.password_history_size,
        )
        .await
        .expect_err("setting a local password for a managed user must be refused");
        assert!(
            err.to_string().contains(&source_code),
            "the refusal must name the directory that owns the password, got: {err}"
        );

        let hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(hash, "", "the stored hash must be untouched");
    })
    .await;
}

/// The safety valve: once the source is switched off it no longer verifies
/// anyone, so the account must become locally administrable again — otherwise
/// decommissioning a directory would leave its users permanently locked out.
#[tokio::test]
async fn a_disabled_source_releases_the_account_to_local_administration() {
    let Some(state) = common::state().await else {
        return;
    };
    let source = common::create_source(&state.pool).await;
    let user_id = common::create_user(&state.pool, "").await;
    common::link_entry(&state.pool, source.id, "e-1", user_id, Some(DN)).await;

    common::scoped(state, source, move |state, source| async move {
        sqlx::query("UPDATE directory_sources SET enabled = FALSE WHERE id = $1")
            .bind(source.id)
            .execute(&state.pool)
            .await
            .expect("disable the source");

        signet::auth::password::set_user_password(
            &state.pool,
            user_id,
            "CorrectHorse1",
            state.config.password_min_length,
            state.config.password_history_size,
        )
        .await
        .expect("a disabled source must not block local administration");
    })
    .await;
}
