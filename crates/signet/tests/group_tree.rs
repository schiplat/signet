//! The group/department tree and local membership.
//!
//! Pins the semantics the dashboard relies on: one tree with `kind`, direct
//! membership only in the OIDC claim, rename-by-id (membership follows), cycle
//! rejection, delete moving children up and releasing members, and `source`
//! ownership (SCIM/directory nodes are move-only; name/membership/deletion stay
//! with the source).
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use signet::directory::{engine, plan::SyncPlan};
use tower::ServiceExt;
use uuid::Uuid;

async fn call(
    state: &signet::state::AppState,
    method: &str,
    uri: &str,
    cookie: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("content-type", "application/json");
    if body.is_some() {
        builder = builder.header("accept", "application/json");
    }
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    let response = signet::groups::router()
        .with_state(state.clone())
        .oneshot(builder.body(body).expect("build request"))
        .await
        .expect("groups router answers");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn admin_call(
    state: &signet::state::AppState,
    uri: &str,
    cookie: &str,
) -> (StatusCode, Value) {
    let response = signet::admin::router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("cookie", cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("admin router answers");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn session_cookie(state: &signet::state::AppState, user: Uuid, role: &str) -> String {
    sqlx::query("UPDATE users SET role = $2 WHERE id = $1")
        .bind(user)
        .bind(role)
        .execute(&state.pool)
        .await
        .expect("set role");
    let token = signet::auth::session::create_session(&state.pool, user, 1, None, None)
        .await
        .expect("create session");
    format!("{}={token}", signet::auth::session::SESSION_COOKIE)
}

async fn cleanup(pool: &sqlx::PgPool, pattern: &str) {
    sqlx::query("DELETE FROM scim_groups WHERE display_name LIKE $1")
        .bind(pattern)
        .execute(pool)
        .await
        .expect("clean test groups");
}

/// The names a user currently carries, as the OIDC claim would see them.
async fn claim_names(pool: &sqlx::PgPool, user: Uuid) -> Vec<String> {
    let (local, directory): (Vec<String>, Vec<String>) = sqlx::query_as(
        "SELECT signet_group_names(groups), signet_group_names(directory_groups) \
         FROM users WHERE id = $1",
    )
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("read the user's groups");
    signet::models::effective_groups(&local, &directory)
}

#[tokio::test]
async fn the_tree_rename_membership_and_delete_semantics() {
    let Some(state) = common::state().await else {
        return;
    };
    let tag = Uuid::new_v4().simple().to_string();
    let gtest = format!("gtest-{tag}");
    cleanup(&state.pool, &format!("{gtest}%")).await;

    let admin = common::create_user(&state.pool, "").await;
    let manager = common::create_user(&state.pool, "").await;
    let member = common::create_user(&state.pool, "").await;

    common::with_users(
        state.clone(),
        vec![admin, manager, member],
        move |state, users| async move {
            let (admin, manager, member) = (users[0], users[1], users[2]);
            let admin_cookie = session_cookie(&state, admin, "admin").await;
            let manager_cookie = session_cookie(&state, manager, "manager").await;

            // 1. Department + group under it.
            let (status, dept) = call(
                &state,
                "POST",
                "/admin/groups",
                &admin_cookie,
                Some(json!({ "name": format!("{gtest}-dept"), "kind": "department" })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{dept}");
            let dept_id = dept["id"].as_str().expect("dept id").to_string();
            assert_eq!(dept["kind"], json!("department"));
            assert_eq!(dept["source"], json!("local"));

            let (status, group) = call(
                &state,
                "POST",
                "/admin/groups",
                &manager_cookie,
                Some(json!({
                    "name": format!("{gtest}-group"),
                    "parent_id": dept_id,
                })),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "a manager may create groups: {group}"
            );
            let group_id = group["id"].as_str().expect("group id").to_string();
            assert_eq!(group["kind"], json!("group"));

            // 2. Membership is local-only and direct: the parent department is not
            //    part of the claim just because the child group is.
            let (status, added) = call(
                &state,
                "POST",
                &format!("/admin/groups/{group_id}/members"),
                &manager_cookie,
                Some(json!({ "user_ids": [member] })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{added}");
            assert_eq!(added["updated"], json!(1), "{added}");
            assert_eq!(
                claim_names(&state.pool, member).await,
                vec![format!("{gtest}-group")],
                "direct membership only"
            );

            let (status, members) = call(
                &state,
                "GET",
                &format!("/admin/groups/{group_id}/members?limit=10&offset=0"),
                &manager_cookie,
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{members}");
            assert_eq!(members["total"], json!(1));
            assert_eq!(members["members"][0]["id"], json!(member.to_string()));

            // 3. Rename: membership follows the id, the claim shows the new name.
            let (status, renamed) = call(
                &state,
                "PUT",
                &format!("/admin/groups/{group_id}"),
                &manager_cookie,
                Some(json!({ "name": format!("{gtest}-renamed") })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{renamed}");
            assert_eq!(
                claim_names(&state.pool, member).await,
                vec![format!("{gtest}-renamed")]
            );

            // 4. Cycles are refused.
            let (status, _) = call(
                &state,
                "PUT",
                &format!("/admin/groups/{dept_id}"),
                &admin_cookie,
                Some(json!({ "parent_id": group_id })),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "a group cannot move under its child"
            );
            let (status, _) = call(
                &state,
                "PUT",
                &format!("/admin/groups/{dept_id}"),
                &admin_cookie,
                Some(json!({ "parent_id": dept_id })),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "self-parent is refused");

            // 5. Managers cannot delete; admins can, and children move up while
            //    membership is released.
            let (status, _) = call(
                &state,
                "DELETE",
                &format!("/admin/groups/{dept_id}"),
                &manager_cookie,
                None,
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "delete is admin-only");

            let (status, deleted) = call(
                &state,
                "DELETE",
                &format!("/admin/groups/{dept_id}"),
                &admin_cookie,
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{deleted}");
            assert_eq!(deleted["children_moved_up"], json!(1));

            // The child is now at the root and still holds its member.
            let (_, list) = call(&state, "GET", "/admin/groups", &admin_cookie, None).await;
            let child = list
                .as_array()
                .expect("group list")
                .iter()
                .find(|g| g["id"] == json!(group_id))
                .expect("the child group is still live");
            assert!(child["parent_id"].is_null(), "child moved to the root");
            assert_eq!(child["member_count"], json!(1));

            // Deleting the group releases the member and tombstones the row.
            let (status, deleted) = call(
                &state,
                "DELETE",
                &format!("/admin/groups/{group_id}"),
                &admin_cookie,
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{deleted}");
            assert_eq!(deleted["released_members"], json!(1));
            assert!(claim_names(&state.pool, member).await.is_empty());

            cleanup(&state.pool, &format!("{gtest}%")).await;
        },
    )
    .await;
}

#[tokio::test]
async fn source_owned_groups_are_move_only() {
    let Some(state) = common::state().await else {
        return;
    };
    let tag = Uuid::new_v4().simple().to_string();
    let gtest = format!("gtest-{tag}");
    cleanup(&state.pool, &format!("{gtest}%")).await;

    let admin = common::create_user(&state.pool, "").await;
    common::with_user(state.clone(), admin, move |state, admin| async move {
        let cookie = session_cookie(&state, admin, "admin").await;

        // A directory-owned node, as the sync would create it.
        let dir_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO scim_groups (id, display_name, source) \
             VALUES ($1, $2, 'directory')",
        )
        .bind(dir_id)
        .bind(format!("{gtest}-dir"))
        .execute(&state.pool)
        .await
        .expect("seed a directory group");

        let (status, _) = call(
            &state,
            "PUT",
            &format!("/admin/groups/{dir_id}"),
            &cookie,
            Some(json!({ "name": format!("{gtest}-dir-renamed") })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "the directory owns the name");

        let (status, _) = call(
            &state,
            "DELETE",
            &format!("/admin/groups/{dir_id}"),
            &cookie,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "the directory owns existence");

        let (status, _) = call(
            &state,
            "POST",
            &format!("/admin/groups/{dir_id}/members"),
            &cookie,
            Some(json!({ "user_ids": [admin] })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "the directory owns membership"
        );

        // Moving is a local organisational decision and stays allowed.
        let (status, parent) = call(
            &state,
            "POST",
            "/admin/groups",
            &cookie,
            Some(json!({ "name": format!("{gtest}-dept"), "kind": "department" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{parent}");
        let parent_id = parent["id"].as_str().expect("parent id").to_string();
        let (status, moved) = call(
            &state,
            "PUT",
            &format!("/admin/groups/{dir_id}"),
            &cookie,
            Some(json!({ "parent_id": parent_id })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "moving a directory group is allowed: {moved}"
        );
        assert_eq!(moved["parent_id"], json!(parent_id));

        cleanup(&state.pool, &format!("{gtest}%")).await;
    })
    .await;
}

#[tokio::test]
async fn a_full_group_run_prunes_only_empty_directory_groups() {
    let Some(state) = common::state().await else {
        return;
    };
    let tag = Uuid::new_v4().simple().to_string();
    let gtest = format!("gtest-{tag}");
    cleanup(&state.pool, &format!("{gtest}%")).await;

    let source = common::create_source(&state.pool).await;
    let user = common::create_user(&state.pool, "").await;

    common::run_scoped(
        state.clone(),
        vec![source],
        move |state, sources| async move {
            let source = &sources[0];
            let run_id = common::begin_run(&state.pool, source.id).await;

            let empty = Uuid::new_v4();
            let occupied = Uuid::new_v4();
            let parent = Uuid::new_v4();
            let child = Uuid::new_v4();
            for (id, name, kind, src, parent_id) in [
                (empty, format!("{gtest}-empty"), "group", "directory", None),
                (
                    occupied,
                    format!("{gtest}-occupied"),
                    "group",
                    "directory",
                    None,
                ),
                (
                    parent,
                    format!("{gtest}-parent"),
                    "department",
                    "directory",
                    None,
                ),
                (
                    child,
                    format!("{gtest}-child"),
                    "group",
                    "local",
                    Some(parent),
                ),
            ] {
                sqlx::query(
                "INSERT INTO scim_groups (id, display_name, kind, source, source_id, parent_id) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(id)
            .bind(name)
            .bind(kind)
            .bind(src)
            .bind(if src == "directory" { Some(source.id) } else { None })
            .bind(parent_id)
            .execute(&state.pool)
            .await
            .expect("seed a group");
            }
            sqlx::query("UPDATE users SET directory_groups = ARRAY[$2::uuid] WHERE id = $1")
                .bind(user)
                .bind(occupied)
                .execute(&state.pool)
                .await
                .expect("seed membership");

            let plan = SyncPlan {
                changes: Vec::new(),
                scanned: 0,
                reconciled: true,
                groups_owned: true,
            };
            engine::apply_plan(&state, source, run_id, &plan, None)
                .await
                .expect("apply an empty full plan");

            let live = |id: Uuid| {
                let pool = state.pool.clone();
                async move {
                    sqlx::query_scalar::<_, bool>(
                        "SELECT deleted_at IS NULL FROM scim_groups WHERE id = $1",
                    )
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .expect("read the group")
                }
            };
            assert!(!live(empty).await, "an empty directory group is tombstoned");
            assert!(live(occupied).await, "a member keeps its directory group");
            assert!(live(parent).await, "a node with children is kept");
            assert!(live(child).await, "local nodes are outside the sweep");

            sqlx::query("UPDATE users SET directory_groups = '{}' WHERE id = $1")
                .bind(user)
                .execute(&state.pool)
                .await
                .expect("release membership");
            cleanup(&state.pool, &format!("{gtest}%")).await;
        },
    )
    .await;
}

#[tokio::test]
async fn the_user_list_filters_by_group_and_subtree() {
    let Some(state) = common::state().await else {
        return;
    };
    let tag = Uuid::new_v4().simple().to_string();
    let gtest = format!("gtest-{tag}");
    cleanup(&state.pool, &format!("{gtest}%")).await;

    let admin = common::create_user(&state.pool, "").await;
    let in_child = common::create_user(&state.pool, "").await;
    let in_dept = common::create_user(&state.pool, "").await;
    let ungrouped = common::create_user(&state.pool, "").await;

    common::with_users(
        state.clone(),
        vec![admin, in_child, in_dept, ungrouped],
        move |state, users| async move {
            let (admin, in_child, in_dept, ungrouped) = (users[0], users[1], users[2], users[3]);
            let cookie = session_cookie(&state, admin, "admin").await;

            let (_, dept) = call(
                &state,
                "POST",
                "/admin/groups",
                &cookie,
                Some(json!({ "name": format!("{gtest}-dept"), "kind": "department" })),
            )
            .await;
            let dept_id = dept["id"].as_str().expect("dept id").to_string();
            let (_, child) = call(
                &state,
                "POST",
                "/admin/groups",
                &cookie,
                Some(json!({ "name": format!("{gtest}-child"), "parent_id": dept_id })),
            )
            .await;
            let child_id = child["id"].as_str().expect("child id").to_string();

            for (group, user) in [(&dept_id, in_dept), (&child_id, in_child)] {
                let (status, _) = call(
                    &state,
                    "POST",
                    &format!("/admin/groups/{group}/members"),
                    &cookie,
                    Some(json!({ "user_ids": [user] })),
                )
                .await;
                assert_eq!(status, StatusCode::OK);
            }

            let ids = |body: &Value| -> Vec<String> {
                body["users"]
                    .as_array()
                    .expect("users")
                    .iter()
                    .map(|u| u["id"].as_str().expect("id").to_string())
                    .collect()
            };

            // Direct membership only.
            let (status, body) = admin_call(
                &state,
                &format!("/admin/users?group_id={child_id}&limit=50"),
                &cookie,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(ids(&body), vec![in_child.to_string()]);

            // A department with descendants.
            let (status, body) = admin_call(
                &state,
                &format!("/admin/users?group_id={dept_id}&include_descendants=true&limit=50"),
                &cookie,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let subtree = ids(&body);
            assert_eq!(subtree.len(), 2, "direct dept member + child member");
            assert!(subtree.contains(&in_child.to_string()));
            assert!(subtree.contains(&in_dept.to_string()));

            // Ungrouped excludes both, and includes the fresh account. Other
            // tests' users may also be ungrouped, so only membership is pinned.
            let (status, body) =
                admin_call(&state, "/admin/users?group_id=ungrouped&limit=200", &cookie).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let ungrouped_ids = ids(&body);
            assert!(ungrouped_ids.contains(&ungrouped.to_string()));
            assert!(!ungrouped_ids.contains(&in_child.to_string()));
            assert!(!ungrouped_ids.contains(&in_dept.to_string()));

            cleanup(&state.pool, &format!("{gtest}%")).await;
        },
    )
    .await;
}
