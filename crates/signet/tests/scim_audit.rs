//! Every SCIM write leaves a trace, and the trace says what was asked for.
//!
//! The gaps this covers were all the same shape: a route that changed something
//! and recorded nothing. `PUT`/`PATCH` wrote no audit at all, so an IdP that
//! deactivated 500 accounts with `{"op":"remove","path":"active"}` left nothing
//! behind — and the three standard spellings of "deactivate this account" were
//! indistinguishable even to someone who knew to look.
//!
//! Driven through the router rather than by calling the predicates: the missing
//! thing was the call site, and a test of an extracted helper would keep passing
//! after the route stopped recording.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// Drives a SCIM request and returns the parsed body (or an empty object).
async fn scim_call(
    router: &axum::Router,
    token: &str,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> Value {
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
    assert!(
        response.status().is_success(),
        "{method} {uri} failed: {}",
        response.status()
    );
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read the response body")
        .to_bytes();
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).expect("the response is JSON")
}

/// The events recorded against a resource, oldest first, as `(action, detail)`.
async fn events_for(pool: &PgPool, resource_id: &str) -> Vec<(String, Value)> {
    sqlx::query_as(
        "SELECT action, detail FROM audit_logs WHERE resource_id = $1 ORDER BY created_at, action",
    )
    .bind(resource_id)
    .fetch_all(pool)
    .await
    .expect("read the audit rows")
}

/// Removes the events these tests wrote.
///
/// SCIM entries carry no `source` for the shared cleanup to match on, so the
/// ids have to be swept explicitly — an accumulating `audit_logs` table would
/// make the next run of this file read stale rows.
async fn forget(pool: &PgPool, resource_ids: &[String]) {
    for id in resource_ids {
        sqlx::query("DELETE FROM audit_logs WHERE resource_id = $1")
            .bind(id)
            .execute(pool)
            .await
            .expect("delete the test audit rows");
    }
}

/// Creates a user through SCIM and returns `(id, resource_id_string)`.
async fn create_user(router: &axum::Router, token: &str, name: &str) -> (Uuid, String) {
    let created = scim_call(
        router,
        token,
        "POST",
        "/scim/v2/Users",
        Some(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": name,
            "displayName": name,
            "emails": [{ "value": format!("{name}@example.com"), "primary": true }],
        })),
    )
    .await;
    let id = Uuid::parse_str(created["id"].as_str().expect("a created id")).expect("a UUID");
    (id, id.to_string())
}

#[tokio::test]
async fn every_scim_write_is_recorded() {
    let Some(state) = common::state().await else {
        return;
    };

    common::with_scim_token(state, move |state, token| async move {
        let router = common::scim_router(&state);
        let name = format!("audited-{}", Uuid::new_v4().simple());
        let (user, user_id) = create_user(&router, &token, &name).await;
        let group_name = format!("audited-g-{}", Uuid::new_v4().simple());
        let group = scim_call(
            &router,
            &token,
            "POST",
            "/scim/v2/Groups",
            Some(serde_json::json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": group_name,
            })),
        )
        .await;
        let group_id =
            Uuid::parse_str(group["id"].as_str().expect("a created id")).expect("a UUID");

        let events = events_for(&state.pool, &user_id).await;
        assert_eq!(
            events.iter().map(|(a, _)| a.as_str()).collect::<Vec<_>>(),
            vec!["scim.user.create"],
            "a creation is recorded"
        );
        assert_eq!(
            events[0].1["email"],
            format!("{name}@example.com"),
            "the creation event names the account it created"
        );

        // ── A PUT that changes a managed attribute ──────────────────────────
        scim_call(
            &router,
            &token,
            "PUT",
            &format!("/scim/v2/Users/{user}"),
            Some(serde_json::json!({
                "userName": name,
                "displayName": "Renamed By Idp",
                "emails": [{ "value": format!("{name}@example.com"), "primary": true }],
            })),
        )
        .await;

        let events = events_for(&state.pool, &user_id).await;
        let update = events
            .iter()
            .find(|(a, _)| a == "scim.user.update")
            .expect("a PUT must be recorded; it used to record nothing");
        assert_eq!(update.1["via"], "put");
        assert_eq!(
            update.1["changed"],
            serde_json::json!(["display_name"]),
            "the event must name what moved, not just that something did"
        );

        // ── `active: false`, the object spelling several clients send ───────
        scim_call(
            &router,
            &token,
            "PUT",
            &format!("/scim/v2/Users/{user}"),
            Some(serde_json::json!({
                "userName": name,
                "emails": [{ "value": format!("{name}@example.com"), "primary": true }],
                "active": false,
            })),
        )
        .await;

        let events = events_for(&state.pool, &user_id).await;
        let disabled = events
            .iter()
            .find(|(a, _)| a == "scim.user.disabled")
            .expect("a deactivation must be recorded");
        assert_eq!(disabled.1["via"], "put");
        assert_eq!(disabled.1["status"], "disabled");

        // ── `remove active`, the path-qualified spelling ────────────────────
        // The distinction matters when a client's behaviour changes: an operator
        // reading "this account was disabled" needs to know which request did it.
        scim_call(
            &router,
            &token,
            "PATCH",
            &format!("/scim/v2/Users/{user}"),
            Some(serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{ "op": "remove", "path": "active" }],
            })),
        )
        .await;

        // Re-enable, so the enable is recorded too.
        scim_call(
            &router,
            &token,
            "PATCH",
            &format!("/scim/v2/Users/{user}"),
            Some(serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{ "op": "replace", "path": "active", "value": true }],
            })),
        )
        .await;

        let events = events_for(&state.pool, &user_id).await;
        let actions: Vec<&str> = events.iter().map(|(a, _)| a.as_str()).collect();
        assert!(
            actions.contains(&"scim.user.enabled"),
            "an enable must be recorded: disabling was logged and enabling was \
             silent, so \"when did this account come back\" had no answer. Got {actions:?}"
        );

        // The deactivation was already recorded by the PUT above, so the
        // `remove active` PATCH is a *repeat* — and a repeat is not a new
        // decision. Only the PUT's entry plus the PATCH's enable should exist.
        let disables: Vec<&Value> = events
            .iter()
            .filter(|(a, _)| a == "scim.user.disabled")
            .map(|(_, d)| d)
            .collect();
        assert_eq!(
            disables.len(),
            1,
            "a redundant deactivation must not add a second entry: {actions:?}"
        );

        // ── A push that changes nothing adds nothing ────────────────────────
        // The counterpart of the transition guard: a conforming client re-sends
        // the whole resource on every poll, so "log every write" would bury the
        // real transitions under the IdP's polling interval.
        let before = actions.clone();
        scim_call(
            &router,
            &token,
            "PUT",
            &format!("/scim/v2/Users/{user}"),
            Some(serde_json::json!({
                "userName": name,
                "displayName": "Renamed By Idp",
                "emails": [{ "value": format!("{name}@example.com"), "primary": true }],
                "active": true,
            })),
        )
        .await;
        let after: Vec<String> = events_for(&state.pool, &user_id)
            .await
            .into_iter()
            .map(|(a, _)| a)
            .collect();
        assert_eq!(
            after, before,
            "an idempotent push is not an event; only the calendar changes"
        );

        // ── Groups ──────────────────────────────────────────────────────────
        scim_call(
            &router,
            &token,
            "PATCH",
            &format!("/scim/v2/Groups/{group_id}"),
            Some(serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{ "op": "add", "path": "members",
                                 "value": [{ "value": user.to_string() }] }],
            })),
        )
        .await;
        scim_call(
            &router,
            &token,
            "DELETE",
            &format!("/scim/v2/Groups/{group_id}"),
            None,
        )
        .await;

        let group_events = events_for(&state.pool, &group_id.to_string()).await;
        let group_actions: Vec<&str> = group_events.iter().map(|(a, _)| a.as_str()).collect();
        assert_eq!(
            group_actions,
            vec![
                "scim.group.create",
                "scim.group.update",
                "scim.group.delete"
            ],
            "group life cycle must be recorded end to end"
        );

        let members = group_events
            .iter()
            .find(|(a, _)| a == "scim.group.update")
            .map(|(_, d)| d.clone())
            .expect("the member add");
        assert_eq!(
            members["outcome"]["added"], 1,
            "one event per request, counting what it did: {members}"
        );
        assert_eq!(group_events[2].1["released_members"], 1);

        forget(&state.pool, &[user_id, group_id.to_string()]).await;
        common::delete_user(&state.pool, user).await;
        sqlx::query("DELETE FROM scim_groups WHERE id = $1")
            .bind(group_id)
            .execute(&state.pool)
            .await
            .expect("remove the group rows");
    })
    .await;
}
