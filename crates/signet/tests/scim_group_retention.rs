//! A group delete from the IdP marks the group instead of removing it.
//!
//! `delete_group` used to drop the `scim_groups` row and strip the name from
//! every user's `groups`, with nothing left behind. An IdP that deleted a group
//! by mistake destroyed both the record that the group existed and the record of
//! who was in it.
//!
//! Two properties have to hold at once, and they pull in opposite directions:
//!
//! * the membership must stop granting — `users.groups` is what the `groups`
//!   claim is built from, so a deleted group must not keep admitting people;
//! * the membership must survive somewhere, or the delete is unrecoverable.
//!
//! So the name comes out of `users.groups` and the member list goes onto the
//! tombstone.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// Drives a SCIM request and returns the status and body.
async fn scim_call(
    router: &axum::Router,
    token: &str,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
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
        .expect("the SCIM router must answer");
    let status = response.status();
    let text = response
        .into_body()
        .collect()
        .await
        .expect("read the response body")
        .to_bytes();
    (status, String::from_utf8_lossy(&text).into_owned())
}

/// Creates a group and returns its id.
async fn create_group(router: &axum::Router, token: &str, name: &str) -> Uuid {
    let (status, body) = scim_call(
        router,
        token,
        "POST",
        "/scim/v2/Groups",
        Some(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": name,
        })),
    )
    .await;
    assert!(status.is_success(), "group create failed: {status} {body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    Uuid::parse_str(parsed["id"].as_str().expect("a created id")).expect("the id is a UUID")
}

async fn group_exists(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scim_groups WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count the group")
        > 0
}

async fn group_is_live(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM scim_groups WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("count the live group")
        > 0
}

async fn members_at_delete(pool: &PgPool, id: Uuid) -> Option<Vec<Uuid>> {
    sqlx::query_scalar("SELECT members_at_delete FROM scim_groups WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read the tombstone")
}

async fn user_groups(pool: &PgPool, user: Uuid) -> Vec<String> {
    signet::models::user_by_id(pool, user)
        .await
        .expect("read the user")
        .groups
}

/// The whole lifecycle in one test, because the SCIM token is a singleton row
/// and two tests in this binary would race on it.
#[tokio::test]
async fn a_group_delete_marks_and_retains() {
    let Some(state) = common::state().await else {
        return;
    };

    let member = common::create_user(&state.pool, "").await;

    common::with_user(state, member, |state, member| async move {
        common::with_scim_token(state, move |state, token| async move {
            let router = common::scim_router(&state);
            let name = format!("eng-{}", Uuid::new_v4().simple());
            let group = create_group(&router, &token, &name).await;

            let (status, body) = scim_call(
                &router,
                &token,
                "PATCH",
                &format!("/scim/v2/Groups/{group}"),
                Some(serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": [{ "op": "add", "path": "members",
                                     "value": [{ "value": member.to_string() }] }],
                })),
            )
            .await;
            assert!(status.is_success(), "member add failed: {status} {body}");
            assert_eq!(
                user_groups(&state.pool, member).await,
                vec![name.clone()],
                "the member carries the group"
            );

            // ── The delete ──────────────────────────────────────────────────
            let (status, body) = scim_call(
                &router,
                &token,
                "DELETE",
                &format!("/scim/v2/Groups/{group}"),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::NO_CONTENT, "body: {body}");

            assert!(
                group_exists(&state.pool, group).await,
                "the row must survive its own delete"
            );
            assert!(
                !group_is_live(&state.pool, group).await,
                "and must stop being listed as a live group"
            );
            assert_eq!(
                members_at_delete(&state.pool, group).await,
                Some(vec![member]),
                "the membership must be recoverable from the tombstone"
            );
            assert!(
                user_groups(&state.pool, member).await.is_empty(),
                "but it must stop granting: `groups` is what the claim is built from"
            );

            // A deleted group is gone as far as the API is concerned.
            let (status, _) = scim_call(
                &router,
                &token,
                "GET",
                &format!("/scim/v2/Groups/{group}"),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);

            // ── Re-creating the same name must not collide ──────────────────
            // The tombstone holds the name, so uniqueness has to be over the
            // live rows only, or a mistake here would block the IdP forever.
            let again = create_group(&router, &token, &name).await;
            assert!(group_is_live(&state.pool, again).await);
            assert_ne!(again, group, "the re-created group is its own row");

            sqlx::query("DELETE FROM scim_groups WHERE id IN ($1, $2)")
                .bind(group)
                .bind(again)
                .execute(&state.pool)
                .await
                .expect("clean up the group rows");
        })
        .await;
    })
    .await;
}
