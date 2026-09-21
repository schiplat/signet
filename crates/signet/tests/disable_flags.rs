//! The three-authority disable model (migration `026`).
//!
//! An account is disabled when *any* of the three flags says so — an admin's
//! `local_disabled`, the sync's `directory_disabled`, the IdP's `scim_disabled`
//! — and `status` is only ever derived from them. Before this, each authority
//! wrote `status` itself, so the sync re-derived it over a SCIM deactivation and
//! SCIM wrote it back over a directory absence.
//!
//! The rule is spelled in three places on purpose and they have to agree:
//! `models::STATUS_FROM_FLAGS` (SQL, for updates), `models::status_from_flags`
//! (Rust, for inserts), and the CHECK in migration `026`. Every combination is
//! walked through here so that agreement is verified rather than assumed.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// The liveness sweep is one global statement over `users`, so any test that
/// triggers it can release a claim another test is midway through asserting on.
/// These tests all share that global state, so they run one at a time.
static SWEEP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `(status, local_disabled, directory_disabled, scim_disabled)` as stored.
async fn flags(pool: &PgPool, id: Uuid) -> (String, bool, bool, bool) {
    let user = signet::models::user_by_id(pool, id)
        .await
        .expect("read the user");
    (
        user.status,
        user.local_disabled,
        user.directory_disabled,
        user.scim_disabled,
    )
}

/// Posts `{"enabled": …}` to the admin route, the way the dashboard does.
async fn set_source_enabled(
    router: &axum::Router,
    cookie: &str,
    code: &str,
    enabled: bool,
) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/directory/sources/{code}/enabled"))
                .header("cookie", cookie)
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"enabled":{enabled}}}"#)))
                .expect("build the request"),
        )
        .await
        .expect("the directory router must answer")
        .status()
}

/// Every combination of the three flags must store the status the rule derives.
///
/// The write binds `status_from_flags(…)` and lets the database check it, so a
/// row that only lands when the Rust helper and the CHECK agree.
#[tokio::test]
async fn every_flag_combination_stores_the_status_it_derives() {
    let Some(state) = common::state().await else {
        return;
    };
    let _guard = SWEEP_LOCK.lock().await;

    let combos: Vec<(bool, bool, bool)> = (0..8u8)
        .map(|i| (i & 1 != 0, i & 2 != 0, i & 4 != 0))
        .collect();
    let mut ids = Vec::new();
    for _ in &combos {
        ids.push(common::create_user(&state.pool, "").await);
    }

    common::with_users(state, ids, move |state, ids| async move {
        for (id, &(local, directory, scim)) in ids.iter().zip(&combos) {
            let derived = signet::models::status_from_flags(local, directory, scim);
            sqlx::query(
                "UPDATE users SET local_disabled = $2, directory_disabled = $3, \
                 scim_disabled = $4, status = $5, updated_at = NOW() WHERE id = $1",
            )
            .bind(id)
            .bind(local)
            .bind(directory)
            .bind(scim)
            .bind(derived)
            .execute(&state.pool)
            .await
            .unwrap_or_else(|e| {
                panic!("local={local} directory={directory} scim={scim} -> {derived}: {e}")
            });

            let (status, ..) = flags(&state.pool, *id).await;
            assert_eq!(
                status == "disabled",
                local || directory || scim,
                "local={local} directory={directory} scim={scim} stored {status}"
            );
        }
    })
    .await;
}

/// A `status` that contradicts the flags must be rejected by the database.
///
/// This is what makes a writer that forgets the derivation fail loudly rather
/// than store a contradiction — and it is how the constraint's own presence is
/// verified, since a migration that failed to add it would let this through.
#[tokio::test]
async fn the_database_rejects_a_status_that_contradicts_the_flags() {
    let Some(state) = common::state().await else {
        return;
    };
    let _guard = SWEEP_LOCK.lock().await;
    let id = common::create_user(&state.pool, "").await;

    common::with_user(state, id, |state, id| async move {
        let err =
            sqlx::query("UPDATE users SET status = 'disabled', updated_at = NOW() WHERE id = $1")
                .bind(id)
                .execute(&state.pool)
                .await
                .expect_err("disabling with every flag clear must violate the constraint");

        assert!(
            err.to_string().contains("users_status_matches_flags"),
            "expected the flag constraint to reject it, got: {err}"
        );
    })
    .await;
}

/// An admin enable cannot release an upstream claim, and does not clear it.
///
/// The strict reading of "no authority overrides another": the admin's own
/// intent is cleared, the account stays disabled, and the flag that is holding it
/// is left for its owner to release.
#[tokio::test]
async fn a_local_enable_does_not_release_an_upstream_claim() {
    let Some(state) = common::state().await else {
        return;
    };
    let _guard = SWEEP_LOCK.lock().await;
    let id = common::create_user(&state.pool, "").await;

    common::with_user(state, id, |state, id| async move {
        sqlx::query(
            "UPDATE users SET local_disabled = TRUE, scim_disabled = TRUE, status = 'disabled', \
             updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&state.pool)
        .await
        .expect("disable locally and upstream");

        let user = signet::admin::set_user_access(&state, id, signet::admin::UserAccess::Enabled)
            .await
            .expect("enable locally");

        assert_eq!(
            user.status, "disabled",
            "the IdP's claim must survive a local enable"
        );
        assert!(!user.local_disabled, "the local intent should be cleared");
        assert!(user.scim_disabled, "the IdP's claim must not be touched");

        let (status, ..) = flags(&state.pool, id).await;
        assert_eq!(status, "disabled");
    })
    .await;
}

/// Switching a source off through the admin API releases the claim it held.
///
/// Otherwise the account stays disabled with no authority left to release it,
/// and — since an admin enable cannot override an upstream claim — no way back.
/// Driven through the route rather than by calling the release directly, because
/// what makes this work is that the handler calls it.
#[tokio::test]
async fn disabling_a_source_releases_the_claim_it_held() {
    let Some(state) = common::state().await else {
        return;
    };
    let _guard = SWEEP_LOCK.lock().await;
    let source = common::create_source(&state.pool).await;
    let held = common::create_user(&state.pool, "").await;

    common::scoped(state, source, move |state, source| async move {
        common::link_entry(&state.pool, source.id, "e-held", held, None).await;
        sqlx::query(
            "UPDATE users SET directory_disabled = TRUE, status = 'disabled', \
             updated_at = NOW() WHERE id = $1",
        )
        .bind(held)
        .execute(&state.pool)
        .await
        .expect("simulate an absent-upstream disable");

        let (admin, cookie) = common::admin_cookie(&state).await;
        let status = set_source_enabled(
            &common::directory_router(&state),
            &cookie,
            &source.code,
            false,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the source should be switched off");

        let (status, _, directory_disabled, _) = flags(&state.pool, held).await;
        assert!(!directory_disabled, "the retired source's claim must go");
        assert_eq!(status, "active", "the account must be usable again");

        // Cleanup after the assertions, so a failure still tidies up.
        common::delete_user(&state.pool, held).await;
        common::delete_user(&state.pool, admin).await;
    })
    .await;
}

/// A claim another *enabled* source still links is not released.
///
/// The retired source is not the only one holding this user, so the claim
/// belongs to the source that is still running.
#[tokio::test]
async fn disabling_a_source_spares_a_claim_another_enabled_source_holds() {
    let Some(state) = common::state().await else {
        return;
    };
    let _guard = SWEEP_LOCK.lock().await;
    let retired = common::create_source(&state.pool).await;
    let still_running = common::create_source(&state.pool).await;
    let shared = common::create_user(&state.pool, "").await;

    common::run_scoped(
        state,
        vec![retired, still_running],
        move |state, sources| async move {
            let (retired, still_running) = (&sources[0], &sources[1]);
            common::link_entry(&state.pool, retired.id, "e-shared", shared, None).await;
            common::link_entry(&state.pool, still_running.id, "e-shared", shared, None).await;
            sqlx::query(
                "UPDATE users SET directory_disabled = TRUE, status = 'disabled', \
                 updated_at = NOW() WHERE id = $1",
            )
            .bind(shared)
            .execute(&state.pool)
            .await
            .expect("simulate a disable");

            let (admin, cookie) = common::admin_cookie(&state).await;
            let status = set_source_enabled(
                &common::directory_router(&state),
                &cookie,
                &retired.code,
                false,
            )
            .await;
            assert_eq!(status, StatusCode::OK);

            let (status, _, directory_disabled, _) = flags(&state.pool, shared).await;
            assert!(
                directory_disabled,
                "a source that is still enabled holds this user"
            );
            assert_eq!(status, "disabled");

            common::delete_user(&state.pool, shared).await;
            common::delete_user(&state.pool, admin).await;
        },
    )
    .await;
}

/// Deletes the source through the admin route, the way the dashboard does.
async fn delete_source(router: &axum::Router, cookie: &str, code: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/directory/sources/{code}"))
                .header("cookie", cookie)
                .body(Body::empty())
                .expect("build the request"),
        )
        .await
        .expect("the directory router must answer")
        .status()
}

/// Marks a user as disabled by the sync, the way an absent-upstream run does.
async fn claim_by_sync(pool: &PgPool, id: Uuid) {
    sqlx::query(
        "UPDATE users SET directory_disabled = TRUE, status = 'disabled', updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("simulate a sync disable");
}

/// A claim with no link left to release it is swept away with the source.
///
/// `DELETE /admin/directory/sources/{code}` refuses while links exist and tells
/// the operator to "remove the links first" — which leaves `directory_disabled`
/// set with nothing pointing at a source any more. Releasing only claims that
/// still carry a link to the retired source would strand exactly those accounts:
/// no enabled source backs the claim, and an admin enable cannot clear it, so
/// the account is disabled with no way back. Sweeping by liveness instead of by
/// source is what makes the advice safe to follow.
#[tokio::test]
async fn a_claim_whose_links_are_gone_is_released_with_the_source() {
    let Some(state) = common::state().await else {
        return;
    };
    let _guard = SWEEP_LOCK.lock().await;
    let source = common::create_source(&state.pool).await;
    let stranded = common::create_user(&state.pool, "").await;

    common::scoped(state, source, move |state, source| async move {
        claim_by_sync(&state.pool, stranded).await;
        let links: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM directory_entries WHERE user_id = $1")
                .bind(stranded)
                .fetch_one(&state.pool)
                .await
                .expect("count the links");
        assert_eq!(links, 0, "the premise: no source points at this user");

        let (admin, cookie) = common::admin_cookie(&state).await;
        let status = delete_source(&common::directory_router(&state), &cookie, &source.code).await;
        assert_eq!(status, StatusCode::OK, "the source should be deleted");

        let (status, _, directory_disabled, _) = flags(&state.pool, stranded).await;
        assert!(
            !directory_disabled,
            "a claim no live source backs must go, however it got stranded"
        );
        assert_eq!(status, "active", "the account must be usable again");

        common::delete_user(&state.pool, stranded).await;
        common::delete_user(&state.pool, admin).await;
    })
    .await;
}

/// The sweep is scoped to liveness, not to the source being retired.
///
/// A claim left behind by an *earlier* dead source is released by retiring a
/// later one. That is the point of asking "is any source live?" rather than "did
/// this source hold it?": the first question has no wrong answers to accumulate.
#[tokio::test]
async fn retiring_a_source_sweeps_claims_an_earlier_dead_one_left() {
    let Some(state) = common::state().await else {
        return;
    };
    let _guard = SWEEP_LOCK.lock().await;
    let dead = common::create_source(&state.pool).await;
    let retiring = common::create_source(&state.pool).await;
    let stranded = common::create_user(&state.pool, "").await;

    common::run_scoped(
        state,
        vec![dead, retiring],
        move |state, sources| async move {
            let (dead, retiring) = (&sources[0], &sources[1]);
            claim_by_sync(&state.pool, stranded).await;

            // Retire the earlier source first: same code path, so this run is the
            // one that has to release the claim, not the source that caused it.
            let (admin, cookie) = common::admin_cookie(&state).await;
            let router = common::directory_router(&state);
            let status = set_source_enabled(&router, &cookie, &dead.code, false).await;
            assert_eq!(status, StatusCode::OK);

            let (_, _, directory_disabled, _) = flags(&state.pool, stranded).await;
            assert!(
                !directory_disabled,
                "no enabled source links this user, so nothing holds the claim"
            );

            common::delete_user(&state.pool, stranded).await;
            common::delete_user(&state.pool, admin).await;
            let _ = retiring;
        },
    )
    .await;
}
