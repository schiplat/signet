//! Pins `models::insert_user` as the single write path for local, admin and
//! SCIM accounts.
//!
//! Nothing else covers this: the paths it replaced (`setup`, `admin::
//! create_user`, `scim::create_user`) are HTTP handlers and the suite has no
//! router-level test, so `insert_user` is reached here directly.
//!
//! The tests are written as a round trip — write through `insert_user`, read
//! back through `models::user_by_id`. That is deliberate: `USER_COLS` and the
//! INSERT carry two independent column lists, and a value written by one but
//! missing from the other surfaces as a silently wrong or missing field, not as
//! an error. The round trip fails when the two lists disagree.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use signet::models::{insert_user, user_by_id, NewUser};
use uuid::Uuid;

/// The minimum a caller must supply: the `NOT NULL` columns with no default.
fn minimal(id: Uuid, tag: &str) -> (String, String, String, String) {
    (
        id.to_string(),
        format!("{tag}@insert.test"),
        format!("Insert {tag}"),
        "hash-not-a-real-password".to_string(),
    )
}

/// A phone number and username unique to this run.
///
/// Both columns are unique, so fixed values would make a test depend on global
/// database state: one row leaked by an earlier failed run was enough to fail
/// every later run with a constraint violation.
fn unique_contacts(tag: &str) -> (String, String) {
    (
        format!("insert-{}", &tag[..8]),
        format!("+852{:08}", Uuid::new_v4().as_u128() % 100_000_000),
    )
}

#[tokio::test]
async fn a_minimal_insert_lands_with_the_documented_defaults() {
    let Some(state) = common::state().await else {
        return;
    };
    let id = Uuid::new_v4();
    let tag = Uuid::new_v4().simple().to_string();
    let (sub, email, display_name, password_hash) = minimal(id, &tag);

    common::with_user(state, id, move |state, id| async move {
        let new = NewUser::new(id, &sub, &email, &display_name, &password_hash);
        let written = insert_user(&state.pool, &new)
            .await
            .expect("insert a minimal user");

        assert_eq!(written.id, id);
        assert_eq!(written.email, email);
        assert_eq!(written.status, "active");
        assert_eq!(written.role, "member");
        assert_eq!(written.username, None);
        assert_eq!(written.phone, None);
        assert!(
            written.groups.is_empty(),
            "groups defaults to an empty array"
        );
        assert_eq!(written.external_id, None);
        assert!(!written.must_change_password);
        // Both columns are `NOW()` in one statement, so they must agree; this is
        // what catches a `created_at`/`updated_at` that is never populated.
        assert_eq!(
            written.created_at, written.updated_at,
            "created_at and updated_at come from the same NOW()"
        );

        // The read path must agree with the write path.
        let read = user_by_id(&state.pool, id).await.expect("read it back");
        assert_eq!(read.status, "active");
        assert_eq!(read.role, "member");
        assert_eq!(read.password_hash, password_hash);
        assert_eq!(read.external_id, None);
    })
    .await;
}

#[tokio::test]
async fn every_optional_field_survives_the_round_trip() {
    let Some(state) = common::state().await else {
        return;
    };
    let id = Uuid::new_v4();
    let tag = Uuid::new_v4().simple().to_string();
    let (sub, email, display_name, password_hash) = minimal(id, &tag);
    let groups = vec!["staff".to_string(), "on-call".to_string()];
    let (username, phone) = unique_contacts(&tag);

    common::with_user(state, id, move |state, id| async move {
        let mut new = NewUser::new(id, &sub, &email, &display_name, &password_hash);
        new.username = Some(&username);
        new.phone = Some(&phone);
        new.groups = &groups;
        new.external_id = Some("upstream-42");
        new.must_change_password = true;
        new.role = "admin";

        let written = insert_user(&state.pool, &new)
            .await
            .expect("insert a fully specified user");

        assert_eq!(written.username.as_deref(), Some(username.as_str()));
        assert_eq!(written.phone.as_deref(), Some(phone.as_str()));
        assert_eq!(written.groups, groups);
        assert_eq!(written.external_id.as_deref(), Some("upstream-42"));
        assert!(written.must_change_password);
        assert_eq!(written.role, "admin");

        // Read back as well: `external_id` is the field that had to be added to
        // `USER_COLS` for SCIM to see the id it provisioned, so it is the one
        // most likely to go missing from one of the two lists.
        let read = user_by_id(&state.pool, id).await.expect("read it back");
        assert_eq!(read.external_id.as_deref(), Some("upstream-42"));
        assert_eq!(read.groups, vec!["staff", "on-call"]);
        assert!(read.must_change_password);
    })
    .await;
}

#[tokio::test]
async fn status_is_settable_because_scim_provisions_disabled_accounts() {
    let Some(state) = common::state().await else {
        return;
    };
    let id = Uuid::new_v4();
    let tag = Uuid::new_v4().simple().to_string();
    let (sub, email, display_name, password_hash) = minimal(id, &tag);

    common::with_user(state, id, move |state, id| async move {
        let mut new = NewUser::new(id, &sub, &email, &display_name, &password_hash);
        new.status = "disabled";

        let written = insert_user(&state.pool, &new)
            .await
            .expect("insert a disabled user");
        assert_eq!(written.status, "disabled");

        // `active_user_by_id` must refuse it while `user_by_id` still returns
        // it: SCIM can create a disabled account, and nothing may mint a
        // credential for one.
        assert!(user_by_id(&state.pool, id).await.is_ok());
        assert!(
            signet::models::active_user_by_id(&state.pool, id)
                .await
                .is_err(),
            "a SCIM-provisioned disabled account must not pass the active check"
        );
    })
    .await;
}

#[tokio::test]
async fn a_unique_violation_is_returned_raw_for_the_caller_to_describe() {
    let Some(state) = common::state().await else {
        return;
    };
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let tag = Uuid::new_v4().simple().to_string();
    let (sub, email, display_name, password_hash) = minimal(first, &tag);

    common::with_users(state, vec![first, second], move |state, users| async move {
        let (first, second) = (users[0], users[1]);
        insert_user(
            &state.pool,
            &NewUser::new(first, &sub, &email, &display_name, &password_hash),
        )
        .await
        .expect("insert the first user");

        let conflict = insert_user(
            &state.pool,
            &NewUser::new(
                second,
                &second.to_string(),
                &email,
                &display_name,
                &password_hash,
            ),
        )
        .await
        .expect_err("the same email must not insert twice");

        // Un-mapped on purpose: each surface names the conflict in its own
        // vocabulary (SCIM's `userName`, the admin API's `username`), so the
        // constraint must survive to the caller.
        match conflict {
            sqlx::Error::Database(db) => assert_eq!(
                db.constraint(),
                Some("users_email_key"),
                "the constraint name is what callers match on"
            ),
            other => panic!("expected a database error, got {other:?}"),
        }
    })
    .await;
}

#[tokio::test]
async fn the_bootstrap_path_can_insert_through_its_transaction() {
    let Some(state) = common::state().await else {
        return;
    };
    let id = Uuid::new_v4();
    let tag = Uuid::new_v4().simple().to_string();
    let (sub, email, display_name, password_hash) = minimal(id, &tag);

    common::with_user(state, id, move |state, id| async move {
        // `setup` passes `&mut *tx`; this is the only other executor shape the
        // generic parameter has to accept.
        let mut tx = state.pool.begin().await.expect("begin a transaction");
        let mut new = NewUser::new(id, &sub, &email, &display_name, &password_hash);
        new.role = "admin";
        let written = insert_user(&mut *tx, &new)
            .await
            .expect("insert inside the transaction");
        assert_eq!(written.role, "admin");
        tx.commit().await.expect("commit");

        let read = user_by_id(&state.pool, id).await.expect("read it back");
        assert_eq!(read.role, "admin");
    })
    .await;
}
