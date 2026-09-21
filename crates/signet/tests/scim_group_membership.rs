//! The SCIM group membership paths, at more than one member.
//!
//! Both of these used to be per-member loops, and both were rewritten into a
//! single statement per operation:
//!
//! * a PATCH `replace` is now one `clear_group` plus one `UPDATE … WHERE id =
//!   ANY(...)`, inside a transaction;
//! * `GET /scim/v2/Groups` is now one `LEFT JOIN` for every group's members
//!   instead of one query per group.
//!
//! Batching is the kind of change that passes every single-member test and
//! quietly gets an off-by-one wrong on a set — an `ANY` bound to the wrong
//! array, a `replace` that clears without re-adding, a `LEFT JOIN` that drops
//! the groups with no members. So these tests use several members and more than
//! one group, and assert on the resulting membership rather than on the calls.
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

/// PATCHes one operation onto a group and asserts it was accepted.
async fn patch_members(
    router: &axum::Router,
    token: &str,
    group: Uuid,
    operation: serde_json::Value,
) -> serde_json::Value {
    let (status, body) = scim_call(
        router,
        token,
        "PATCH",
        &format!("/scim/v2/Groups/{group}"),
        Some(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [operation],
        })),
    )
    .await;
    assert!(status.is_success(), "group patch failed: {status} {body}");
    serde_json::from_str(&body).expect("the patch answers with the group")
}

/// The users carrying `name`, as the database sees it.
async fn carriers(pool: &PgPool, name: &str) -> Vec<Uuid> {
    sqlx::query_scalar("SELECT id FROM users WHERE groups @> ARRAY[$1::text] ORDER BY email")
        .bind(name)
        .fetch_all(pool)
        .await
        .expect("read the membership")
}

/// Sorts a set of ids, so that two reads of the same membership compare equal
/// even though one is ordered by email and the other by uuid.
fn sorted(mut ids: Vec<Uuid>) -> Vec<Uuid> {
    ids.sort();
    ids
}

/// The ids in a SCIM `members` array, sorted for comparison.
fn member_ids(resource: &serde_json::Value) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = resource["members"]
        .as_array()
        .expect("a members array")
        .iter()
        .map(|m| Uuid::parse_str(m["value"].as_str().expect("a member value")).expect("a UUID"))
        .collect();
    ids.sort();
    ids
}

/// The `members` of one group out of a ListResponse.
fn members_in_list(body: &str, name: &str) -> Vec<Uuid> {
    let parsed: serde_json::Value = serde_json::from_str(body).expect("JSON");
    let resource = parsed["Resources"]
        .as_array()
        .expect("a Resources array")
        .iter()
        .find(|r| r["displayName"] == name)
        .unwrap_or_else(|| panic!("group {name} must be listed"));
    member_ids(resource)
}

/// A `replace` is the two-statement path — clear, then add the new set — so it
/// is where a batching mistake shows up as either a dropped member or a
/// survivor from the previous membership.
#[tokio::test]
async fn a_replace_swaps_the_whole_membership() {
    let Some(state) = common::state().await else {
        return;
    };

    let users: Vec<Uuid> = {
        let mut users = Vec::new();
        for _ in 0..4 {
            users.push(common::create_user(&state.pool, "").await);
        }
        users
    };

    common::with_users(state, users, |state, users| async move {
        common::with_scim_token(state, move |state, token| async move {
            let router = common::scim_router(&state);
            let name = format!("swap-{}", Uuid::new_v4().simple());
            let group = create_group(&router, &token, &name).await;

            // Three members in, through the `add` path.
            let first = vec![users[0], users[1], users[2]];
            let resource = patch_members(
                &router,
                &token,
                group,
                serde_json::json!({
                    "op": "add",
                    "path": "members",
                    "value": first.iter().map(|u| serde_json::json!({ "value": u.to_string() }))
                        .collect::<Vec<_>>(),
                }),
            )
            .await;
            let expected = sorted(first.clone());
            assert_eq!(member_ids(&resource), expected, "all three must be added");
            assert_eq!(
                sorted(carriers(&state.pool, &name).await),
                expected,
                "so must the database"
            );

            // Replace with a single different member. Every one of the three
            // must lose the group, and the new member must have it.
            let replacement = vec![users[3]];
            let resource = patch_members(
                &router,
                &token,
                group,
                serde_json::json!({
                    "op": "replace",
                    "path": "members",
                    "value": [{ "value": users[3].to_string() }],
                }),
            )
            .await;
            assert_eq!(member_ids(&resource), replacement);
            assert_eq!(
                sorted(carriers(&state.pool, &name).await),
                replacement,
                "a replace must not leave anyone from the previous set behind"
            );

            // And a removal of one of two leaves exactly the other.
            patch_members(
                &router,
                &token,
                group,
                serde_json::json!({
                    "op": "add",
                    "path": "members",
                    "value": [{ "value": users[0].to_string() }],
                }),
            )
            .await;
            let resource = patch_members(
                &router,
                &token,
                group,
                serde_json::json!({
                    "op": "remove",
                    "path": format!("members[value eq \"{}\"]", users[3]),
                }),
            )
            .await;
            assert_eq!(member_ids(&resource), vec![users[0]]);
            assert_eq!(sorted(carriers(&state.pool, &name).await), vec![users[0]]);

            sqlx::query("DELETE FROM scim_groups WHERE id = $1")
                .bind(group)
                .execute(&state.pool)
                .await
                .expect("clean up the group row");
            // The membership rides on the users, which `with_users` removes.
        })
        .await;
    })
    .await;
}

/// Group listing reads every group's members in one query now, which makes the
/// mapping from rows back to groups the part that can be wrong: a group with no
/// members produces no membership rows at all.
#[tokio::test]
async fn listing_groups_reports_each_groups_own_members() {
    let Some(state) = common::state().await else {
        return;
    };

    let users: Vec<Uuid> = {
        let mut users = Vec::new();
        for _ in 0..3 {
            users.push(common::create_user(&state.pool, "").await);
        }
        users
    };

    common::with_users(state, users, |state, users| async move {
        common::with_scim_token(state, move |state, token| async move {
            let router = common::scim_router(&state);
            let suffix = Uuid::new_v4().simple();
            let filled = format!("full-{suffix}");
            let empty = format!("empty-{suffix}");

            let filled_group = create_group(&router, &token, &filled).await;
            let empty_group = create_group(&router, &token, &empty).await;

            // Two of the three belong to the filled group; the third belongs to
            // nothing, so it must not be attributed to any group.
            patch_members(
                &router,
                &token,
                filled_group,
                serde_json::json!({
                    "op": "add",
                    "path": "members",
                    "value": [
                        { "value": users[0].to_string() },
                        { "value": users[2].to_string() },
                    ],
                }),
            )
            .await;

            let (status, body) = scim_call(&router, &token, "GET", "/scim/v2/Groups", None).await;
            assert_eq!(status, StatusCode::OK, "body: {body}");

            let expected = sorted(vec![users[0], users[2]]);
            assert_eq!(
                members_in_list(&body, &filled),
                expected,
                "the filled group must list exactly its own members"
            );
            assert!(
                members_in_list(&body, &empty).is_empty(),
                "a group with no members must be listed with none, not omitted or mis-attributed"
            );

            for group in [filled_group, empty_group] {
                sqlx::query("DELETE FROM scim_groups WHERE id = $1")
                    .bind(group)
                    .execute(&state.pool)
                    .await
                    .expect("clean up the group rows");
            }
        })
        .await;
    })
    .await;
}
