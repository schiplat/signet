//! Ownership of a SCIM-provisioned account: an IdP that pushes a user owns the
//! attributes it manages, and the account stops being the local admin's to edit
//! or remove (migration `027`).
//!
//! The counterpart of the directory tests in `directory_policy.rs` and
//! `directory_ownership.rs`: the directory link answers "who owns this" there,
//! `users.scim_managed` answers it here. Both feed the same guards, so both
//! directions need proving — a user wrongly left unowned can be hard-deleted,
//! and one wrongly owned can no longer be fixed by the admin who is looking at
//! the problem.
//!
//! Driven through the real routers because the earlier gap was the wiring: the
//! guards read the directory link and found nothing for a SCIM user.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// Pushes a user through `PUT /scim/v2/Users/{id}`, the IdP's provisioning call.
async fn scim_put(router: &axum::Router, token: &str, user: Uuid, name: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/scim/v2/Users/{user}"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
                        "userName":"{name}","displayName":"{name}",
                        "emails":[{{"value":"{name}@example.com","primary":true}}]}}"#
                )))
                .expect("build the request"),
        )
        .await
        .expect("the SCIM router must answer")
        .status()
}

/// Drives an admin route with a session cookie and returns the status.
async fn admin_call(
    router: &axum::Router,
    cookie: &str,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(match body {
            Some(json) => Body::from(json.to_string()),
            None => Body::empty(),
        })
        .expect("build the request");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the admin router must answer");
    let status = response.status();
    let text = response
        .into_body()
        .collect()
        .await
        .expect("read the response body")
        .to_bytes();
    (status, String::from_utf8_lossy(&text).into_owned())
}

async fn scim_managed(pool: &PgPool, user: Uuid) -> bool {
    signet::models::user_by_id(pool, user)
        .await
        .expect("read the user")
        .scim_managed
}

async fn email_of(pool: &PgPool, user: Uuid) -> String {
    signet::models::user_by_id(pool, user)
        .await
        .expect("read the user")
        .email
}

async fn user_exists(pool: &PgPool, user: Uuid) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count the user")
        > 0
}

/// One test, because the SCIM token is a singleton row and two tests in this
/// binary would race on it. Each section asks a separate question of the same
/// claimed account.
#[tokio::test]
async fn an_idp_taking_over_an_account_makes_it_read_only() {
    let Some(state) = common::state().await else {
        return;
    };

    // A pre-existing *local* account: the IdP knows about it and starts pushing.
    let user = common::create_user(&state.pool, "").await;

    common::with_user(state, user, |state, user| async move {
        common::with_scim_token(state, move |state, token| async move {
            let scim = common::scim_router(&state);
            let admin = common::admin_router(&state);
            let (admin_id, cookie) = common::admin_cookie(&state).await;

            assert!(
                !scim_managed(&state.pool, user).await,
                "a locally created account starts unowned"
            );

            // ── A SCIM write claims the account ─────────────────────────────
            let name = format!("pushed-{}", Uuid::new_v4().simple());
            let status = scim_put(&scim, &token, user, &name).await;
            assert!(status.is_success(), "the push should succeed, got {status}");
            assert!(
                scim_managed(&state.pool, user).await,
                "any SCIM write takes ownership, not just creation"
            );

            // ── Its managed attributes are read-only locally ────────────────
            let before = email_of(&state.pool, user).await;
            let (status, body) = admin_call(
                &admin,
                &cookie,
                "PUT",
                &format!("/admin/users/{user}"),
                Some(serde_json::json!({ "email": "attacker@example.com" })),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "an admin must not overwrite a SCIM-owned email, got {status}: {body}"
            );
            assert!(
                body.contains("SCIM"),
                "the refusal must say who owns the field: {body}"
            );
            assert_eq!(
                email_of(&state.pool, user).await,
                before,
                "the refused write must not have landed"
            );

            // ── And it cannot be hard-deleted ───────────────────────────────
            let (status, body) = admin_call(
                &admin,
                &cookie,
                "DELETE",
                &format!("/admin/users/{user}"),
                None,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a SCIM-owned account must not be deletable, got {status}: {body}"
            );
            assert!(
                user_exists(&state.pool, user).await,
                "the refused delete must not have removed the account"
            );

            // ── Fields SCIM does not own stay editable ──────────────────────
            // Without this half, a guard that refused *every* write would pass
            // everything above.
            let (status, body) = admin_call(
                &admin,
                &cookie,
                "PUT",
                &format!("/admin/users/{user}"),
                Some(serde_json::json!({ "role": "admin" })),
            )
            .await;
            assert!(
                status.is_success(),
                "role is locally owned and must stay writable, got {status}: {body}"
            );

            common::delete_user(&state.pool, admin_id).await;
        })
        .await;
    })
    .await;
}

/// Provenance and ownership answer different questions, so a takeover records
/// only the second.
///
/// `provisioned_via` is how the account was *first* created and must not be
/// rewritten by a later IdP push; `scim_managed` is who owns its attributes now.
/// Conflating them would make an IdP that merely adopts a local account look like
/// the account's creator, which is what an operator reads the field for.
#[tokio::test]
async fn provenance_records_creation_not_takeover() {
    let Some(state) = common::state().await else {
        return;
    };

    let user = common::create_user(&state.pool, "").await;

    common::with_user(state, user, |state, user| async move {
        let before = signet::models::user_by_id(&state.pool, user)
            .await
            .expect("read the user");
        assert_eq!(before.provisioned_via, None, "created locally");

        common::with_scim_token(state, move |state, token| async move {
            let scim = common::scim_router(&state);

            let name = format!("adopted-{}", Uuid::new_v4().simple());
            let status = scim_put(&scim, &token, user, &name).await;
            assert!(status.is_success(), "the push should succeed, got {status}");

            let after = signet::models::user_by_id(&state.pool, user)
                .await
                .expect("read the user");
            assert!(after.scim_managed, "the push owns the account");
            assert_eq!(
                after.provisioned_via, before.provisioned_via,
                "a takeover must not rewrite how the account was created"
            );
        })
        .await;
    })
    .await;
}

/// A SCIM *creation* records both, since SCIM is then both cause and owner.
#[tokio::test]
async fn a_scim_creation_records_provenance() {
    let Some(state) = common::state().await else {
        return;
    };

    common::with_scim_token(state, move |state, token| async move {
        let name = format!("born-{}", Uuid::new_v4().simple());
        let id = scim_create_via_token(&state, &token, &name).await;

        let user = signet::models::user_by_id(&state.pool, id)
            .await
            .expect("read the user");
        assert_eq!(
            user.provisioned_via.as_deref(),
            Some("scim"),
            "a SCIM-created account says so"
        );
        assert!(user.scim_managed, "and SCIM owns it");

        common::delete_user(&state.pool, id).await;
    })
    .await;
}

/// `POST /scim/v2/Users`, returning the created id.
async fn scim_create_via_token(state: &signet::state::AppState, token: &str, name: &str) -> Uuid {
    let response = common::scim_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/scim/v2/Users")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
                        "userName":"{name}","displayName":"{name}",
                        "emails":[{{"value":"{name}@example.com","primary":true}}]}}"#
                )))
                .expect("build the request"),
        )
        .await
        .expect("the SCIM router must answer");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("read the response body")
        .to_bytes();
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).expect("the create response is JSON");
    assert!(status.is_success(), "create failed: {parsed}");
    Uuid::parse_str(parsed["id"].as_str().expect("a created id")).expect("the id is a UUID")
}
