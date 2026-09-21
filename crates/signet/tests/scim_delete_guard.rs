//! An upstream delete must never remove data: D3 says it disables, and that has
//! to hold however the request arrives.
//!
//! Driven through the real router rather than by calling a helper, because what
//! keeps being wrong is the wiring. A test of an extracted predicate would keep
//! passing after someone changed the call site, which is exactly the regression
//! worth catching.
//!
//! The damage from getting it wrong is not a lost row but a changed identity:
//! the account's id is referenced by `directory_entries.user_id` and by the
//! IdP's `externalId`, so deleting it means the next push provisions a *new*
//! account for the same person, and the old one's sessions and audit attribution
//! (`audit_logs.actor_user_id` is `ON DELETE SET NULL`) do not follow them.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DN: &str = "uid=alice,ou=people,dc=corp";

/// Issues `DELETE /scim/v2/Users/{id}` and returns the status and body.
async fn scim_delete(router: &axum::Router, token: &str, user: Uuid) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/scim/v2/Users/{user}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
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
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// Provisions a user through the SCIM API, so it is genuinely SCIM-owned.
async fn scim_create(router: &axum::Router, token: &str, name: &str) -> Uuid {
    let response = router
        .clone()
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
    // `is_success` rather than a specific code: this route answers `200` where
    // RFC 7644 §3.3 asks for `201`, which is a conformance nit of its own and
    // not what this test is about.
    assert!(
        response.status().is_success(),
        "SCIM create must succeed, got {}",
        response.status()
    );
    let body = response
        .into_body()
        .collect()
        .await
        .expect("read the response body")
        .to_bytes();
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).expect("the create response is JSON");
    Uuid::parse_str(parsed["id"].as_str().expect("a created id")).expect("the id is a UUID")
}

async fn user_exists(pool: &PgPool, user: Uuid) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count the user")
        > 0
}

/// The link is the thing that makes the loss of identity permanent: while it
/// exists, the next sync recognises the account instead of creating a new one.
async fn link_exists(pool: &PgPool, user: Uuid) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM directory_entries WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count the link")
        > 0
}

/// `(status, scim_disabled, scim_managed)` as stored.
async fn state_of(pool: &PgPool, user: Uuid) -> (String, bool, bool) {
    let user = signet::models::user_by_id(pool, user)
        .await
        .expect("read the user");
    (user.status, user.scim_disabled, user.scim_managed)
}

/// A delete from the IdP deactivates the account and keeps every row.
///
/// Three users in one test on purpose: the SCIM token is a singleton row, and
/// each case asks a different question. A directory-managed account must keep its
/// link (or identity is lost); a SCIM-provisioned one must be protected by its
/// own ownership flag, which is the half that used to be missing; and a plain
/// local account must not be quietly adopted by the delete.
#[tokio::test]
async fn a_scim_delete_deactivates_rather_than_removes() {
    let Some(state) = common::state().await else {
        return;
    };

    let source = common::create_source(&state.pool).await;
    let managed = common::create_user(&state.pool, "").await;
    common::link_entry(&state.pool, source.id, "e-1", managed, Some(DN)).await;
    let plain = common::create_user(&state.pool, "").await;

    common::run_isolated(
        state,
        vec![source],
        vec![managed, plain],
        move |state| async move {
            common::with_scim_token(state, move |state, token| async move {
                let router = common::scim_router(&state);

                // ── A directory-managed account ─────────────────────────────
                let (status, body) = scim_delete(&router, &token, managed).await;
                assert_eq!(
                    status,
                    StatusCode::NO_CONTENT,
                    "the delete should be accepted and acted on, got {status} with body: {body}"
                );
                assert!(
                    user_exists(&state.pool, managed).await,
                    "the account must survive its own delete"
                );
                assert!(
                    link_exists(&state.pool, managed).await,
                    "the link must survive, or the next sync creates a new identity"
                );
                let (status, scim_disabled, _) = state_of(&state.pool, managed).await;
                assert_eq!(status, "disabled", "the delete means deactivated");
                assert!(scim_disabled, "recorded as SCIM's own intent");

                // ── A SCIM-provisioned account ──────────────────────────────
                let scim_user = scim_create(
                    &router,
                    &token,
                    &format!("owned-{}", Uuid::new_v4().simple()),
                )
                .await;
                let (_, _, managed_flag) = state_of(&state.pool, scim_user).await;
                assert!(
                    managed_flag,
                    "SCIM provisioning an account makes it SCIM-owned"
                );

                let (status, body) = scim_delete(&router, &token, scim_user).await;
                assert_eq!(status, StatusCode::NO_CONTENT, "body: {body}");
                assert!(
                    user_exists(&state.pool, scim_user).await,
                    "a SCIM-owned account must survive its own delete too"
                );
                let (status, scim_disabled, _) = state_of(&state.pool, scim_user).await;
                assert_eq!(status, "disabled");
                assert!(scim_disabled);

                // ── A plain local account ───────────────────────────────────
                let (status, body) = scim_delete(&router, &token, plain).await;
                assert_eq!(status, StatusCode::NO_CONTENT, "body: {body}");
                assert!(
                    user_exists(&state.pool, plain).await,
                    "no delete path may remove a row"
                );
                let (status, _, managed_flag) = state_of(&state.pool, plain).await;
                assert_eq!(status, "disabled");
                assert!(
                    !managed_flag,
                    "a delete must not adopt the account: the local admin would lose \
                     the ability to delete or edit it on the way out"
                );

                common::delete_user(&state.pool, scim_user).await;
            })
            .await;
        },
    )
    .await;
}
