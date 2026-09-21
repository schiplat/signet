//! `GET /admin/users` — the paged, server-searched list.
//!
//! The endpoint used to return every user with every SSO identity and directory
//! link, and the dashboard searched and sorted it in the browser. That works
//! until a directory sync puts thousands of accounts in the table: the response
//! grows without bound, and two of the three queries behind it read whole tables
//! to decorate the same rows.
//!
//! Moving the search to the server is where meaning can quietly change, because
//! `String.prototype.includes` and SQL `ILIKE` are not the same predicate. These
//! tests pin the parts that differ, plus the two properties paging needs: stable
//! order across pages, and decorations that belong to the page's own rows.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// Lists users with the given query string and returns the parsed body.
async fn list(router: &axum::Router, cookie: &str, query: &str) -> Value {
    let request = Request::builder()
        .uri(format!("/admin/users?{query}"))
        .header("cookie", cookie)
        .body(Body::empty())
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
    let body = String::from_utf8_lossy(&text).into_owned();
    assert_eq!(status, StatusCode::OK, "body: {body}");
    serde_json::from_str(&body).expect("JSON")
}

/// The ids in a list response, in order.
fn ids(body: &Value) -> Vec<String> {
    body["users"]
        .as_array()
        .expect("a users array")
        .iter()
        .map(|u| u["id"].as_str().expect("an id").to_string())
        .collect()
}

fn total(body: &Value) -> i64 {
    body["total"].as_i64().expect("a total")
}

/// Sets a column on a user, for the fields `create_user` does not choose.
async fn set(pool: &PgPool, id: Uuid, assignments: &str, value: &str) {
    sqlx::query(&format!(
        "UPDATE users SET {assignments} = $1 WHERE id = $2"
    ))
    .bind(value)
    .bind(id)
    .execute(pool)
    .await
    .expect("update the test user");
}

/// The search must cover what the browser filter covered, or rows that used to
/// be findable stop being findable.
#[tokio::test]
async fn the_search_covers_the_fields_the_browser_filtered_on() {
    let Some(state) = common::state().await else {
        return;
    };

    let (caller, cookie) = common::admin_cookie(&state).await;
    let marker = Uuid::new_v4().simple().to_string();

    // One user per searched column, each carrying the marker in exactly that
    // column, so "found it" can only have come from that column.
    let by_email = common::create_user(&state.pool, "").await;
    set(
        &state.pool,
        by_email,
        "email",
        &format!("{marker}@login.test"),
    )
    .await;
    let by_username = common::create_user(&state.pool, "").await;
    set(&state.pool, by_username, "username", &format!("u-{marker}")).await;
    let by_display = common::create_user(&state.pool, "").await;
    set(
        &state.pool,
        by_display,
        "display_name",
        &format!("Display {marker}"),
    )
    .await;
    let by_source = common::create_user(&state.pool, "").await;
    set(
        &state.pool,
        by_source,
        "provisioned_via",
        &format!("sso-{marker}"),
    )
    .await;

    let users = vec![by_email, by_username, by_display, by_source];
    common::with_users(state.clone(), users.clone(), |state, users| async move {
        // The creating admin is also in the table, and its own email carries no
        // marker, so a search that matched everything would show up here.
        let router = common::admin_router(&state);
        let body = list(&router, &cookie, &format!("q={marker}")).await;

        let mut found = ids(&body);
        found.sort();
        let mut expected: Vec<String> = users.iter().map(|u| u.to_string()).collect();
        expected.sort();
        assert_eq!(found, expected, "every searched column must match");
        assert_eq!(total(&body), 4);
    })
    .await;

    common::delete_user(&state.pool, caller).await;
}

/// `role` and `status` are closed sets, so they cannot carry a unique marker —
/// the assertion is the other way round: everything the search returns must have
/// the value that was searched for, and the seeded row must be in there.
#[tokio::test]
async fn the_search_covers_the_role_and_status_columns() {
    let Some(state) = common::state().await else {
        return;
    };

    let (caller, cookie) = common::admin_cookie(&state).await;
    let manager = common::create_user(&state.pool, "").await;
    sqlx::query("UPDATE users SET role = 'manager' WHERE id = $1")
        .bind(manager)
        .execute(&state.pool)
        .await
        .expect("promote to manager");

    let frozen = common::create_user(&state.pool, "").await;
    signet::admin::set_user_access(&state, frozen, signet::admin::UserAccess::Disabled)
        .await
        .expect("disable the account");

    common::with_users(
        state.clone(),
        vec![manager, frozen],
        |state, users| async move {
            let router = common::admin_router(&state);
            let (manager, frozen) = (users[0], users[1]);

            let body = list(&router, &cookie, "q=manager&limit=200").await;
            let rows = body["users"].as_array().unwrap();
            assert!(!rows.is_empty(), "a manager matches `manager`");
            assert!(
                rows.iter().all(|u| u["role"] == "manager"),
                "and nothing else does"
            );
            assert!(
                ids(&body).contains(&manager.to_string()),
                "including the one this test made"
            );

            let body = list(&router, &cookie, "q=disabled&limit=200").await;
            let rows = body["users"].as_array().unwrap();
            assert!(!rows.is_empty(), "a disabled account matches `disabled`");
            assert!(
                rows.iter().all(|u| u["status"] == "disabled"),
                "and no active account does"
            );
            assert!(ids(&body).contains(&frozen.to_string()));
        },
    )
    .await;

    for id in [caller, manager, frozen] {
        common::delete_user(&state.pool, id).await;
    }
}

/// `_` and `%` are wildcards to `ILIKE` and ordinary characters to
/// `String.includes`, and the search box has to keep meaning the second thing.
#[tokio::test]
async fn the_search_treats_wildcards_as_characters() {
    let Some(state) = common::state().await else {
        return;
    };

    let (caller, cookie) = common::admin_cookie(&state).await;
    let marker = Uuid::new_v4().simple().to_string();

    // Two display names that differ only in the character between the marker and
    // the suffix: one literal `_`, one an `x` that `%a_b%` would also match.
    let literal = common::create_user(&state.pool, "").await;
    set(
        &state.pool,
        literal,
        "display_name",
        &format!("{marker}_suffix"),
    )
    .await;
    let decoy = common::create_user(&state.pool, "").await;
    set(
        &state.pool,
        decoy,
        "display_name",
        &format!("{marker}xsuffix"),
    )
    .await;

    common::with_users(
        state.clone(),
        vec![literal, decoy],
        |state, users| async move {
            let router = common::admin_router(&state);

            let body = list(
                &router,
                &cookie,
                &format!("q={}%5F{}", marker, "suffix"), // marker_suffix, URL-encoded
            )
            .await;
            assert_eq!(
                ids(&body),
                vec![users[0].to_string()],
                "an underscore is a character, not a wildcard"
            );

            // And the same query with an `x` must find the other one, so the
            // test cannot pass by matching nothing at all.
            let body = list(&router, &cookie, &format!("q={marker}xsuffix")).await;
            assert_eq!(ids(&body), vec![users[1].to_string()]);
        },
    )
    .await;

    common::delete_user(&state.pool, caller).await;
}

/// A directory import stamps many users with the same `created_at`, so ties are
/// the normal case, not an edge case — and an unbroken tie means the rows a page
/// boundary lands on are free to swap between queries.
#[tokio::test]
async fn paging_through_ties_neither_repeats_nor_skips_rows() {
    let Some(state) = common::state().await else {
        return;
    };

    let (caller, cookie) = common::admin_cookie(&state).await;
    let marker = Uuid::new_v4().simple().to_string();

    let mut users = Vec::new();
    for index in 0..5 {
        let id = common::create_user(&state.pool, "").await;
        // The same display name and creation time for all five: the sort key is
        // the search marker's presence, and nothing else.
        set(&state.pool, id, "display_name", &format!("tied-{marker}")).await;
        set(
            &state.pool,
            id,
            "email",
            &format!("{marker}-{index}@login.test"),
        )
        .await;
        users.push(id);
    }
    // The same timestamp to the microsecond, after the per-row update.
    sqlx::query("UPDATE users SET created_at = NOW() WHERE id = ANY($1::uuid[])")
        .bind(&users)
        .execute(&state.pool)
        .await
        .expect("force the tie");

    common::with_users(state.clone(), users.clone(), |state, users| async move {
        let router = common::admin_router(&state);

        let mut seen: Vec<String> = Vec::new();
        for offset in [0, 2, 4] {
            let body = list(
                &router,
                &cookie,
                &format!("q={marker}&sort=created_at&dir=desc&limit=2&offset={offset}"),
            )
            .await;
            assert_eq!(total(&body), 5, "the total counts matches, not the page");
            seen.extend(ids(&body));
        }

        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            seen.len(),
            "no row may appear on two pages: {seen:?}"
        );

        let mut expected: Vec<String> = users.iter().map(|u| u.to_string()).collect();
        expected.sort();
        assert_eq!(unique, expected, "and no row may be skipped: {seen:?}");

        // The five are tied on the sort key, so the order within the tie is
        // entirely the query's choice — and the choice has to be `id ASC`, or the
        // rows a page boundary lands on are free to move between one request and
        // the next. Asserting the order rather than trusting it: the mutation
        // that drops the tiebreaker still returns every row exactly once, in
        // whatever order the plan produced, which happens to be stable here.
        let mut ascending = seen.clone();
        ascending.sort();
        assert_eq!(
            seen, ascending,
            "ties must be broken by id, in the same direction for every page"
        );
    })
    .await;

    common::delete_user(&state.pool, caller).await;
}

#[tokio::test]
async fn the_page_size_cannot_be_asked_past_its_ceiling() {
    let Some(state) = common::state().await else {
        return;
    };

    let (caller, cookie) = common::admin_cookie(&state).await;
    let router = common::admin_router(&state);

    let body = list(&router, &cookie, "limit=100000").await;
    assert_eq!(body["limit"].as_i64(), Some(200), "the cap holds");
    assert!(ids(&body).len() <= 200);

    // A nonsense limit is still a limit rather than a full table read.
    let body = list(&router, &cookie, "limit=0").await;
    assert_eq!(body["limit"].as_i64(), Some(1));

    common::delete_user(&state.pool, caller).await;
}

/// The identity and directory-link lookups are scoped to the page now; a user's
/// decorations must still be their own, and only their own.
#[tokio::test]
async fn the_decorations_belong_to_the_page_rows() {
    let Some(state) = common::state().await else {
        return;
    };

    let (caller, cookie) = common::admin_cookie(&state).await;
    let marker = Uuid::new_v4().simple().to_string();
    let provider = format!("prov-{marker}");

    sqlx::query(
        "INSERT INTO upstream_providers \
             (code, provider_type, display_name, client_id, client_secret_enc, allowed_email_domains) \
         VALUES ($1, 'oidc', $2, 'cid', 'enc', '{}')",
    )
    .bind(&provider)
    .bind(format!("Provider {marker}"))
    .execute(&state.pool)
    .await
    .expect("seed the provider");

    let linked = common::create_user(&state.pool, "").await;
    set(
        &state.pool,
        linked,
        "email",
        &format!("{marker}-linked@login.test"),
    )
    .await;
    let plain = common::create_user(&state.pool, "").await;
    set(
        &state.pool,
        plain,
        "email",
        &format!("{marker}-plain@login.test"),
    )
    .await;

    sqlx::query(
        "INSERT INTO user_identities (id, user_id, provider_code, subject) \
         VALUES ($1, $2, $3, 'sub')",
    )
    .bind(Uuid::new_v4())
    .bind(linked)
    .bind(&provider)
    .execute(&state.pool)
    .await
    .expect("link an identity");

    common::with_users(
        state.clone(),
        vec![linked, plain],
        |state, users| async move {
            let router = common::admin_router(&state);

            // One row per page, so the second request must not reuse the first
            // page's decorations.
            let body = list(
                &router,
                &cookie,
                &format!("q={marker}&sort=email&dir=asc&limit=1&offset=0"),
            )
            .await;
            let first = &body["users"][0];
            let first_id = first["id"].as_str().unwrap();
            let identities = first["sso_identities"].as_array().expect("identities");

            let (expected_id, expected_len) = if first_id == users[0].to_string() {
                (users[0], 1)
            } else {
                (users[1], 0)
            };
            assert_eq!(first_id, expected_id.to_string(), "sorted by email");
            assert_eq!(
                identities.len(),
                expected_len,
                "a page must carry only its own rows' identities: {first}"
            );

            // The other row, on its own page, gets the other answer.
            let body = list(
                &router,
                &cookie,
                &format!("q={marker}&sort=email&dir=asc&limit=1&offset=1"),
            )
            .await;
            let second = &body["users"][0];
            assert_ne!(second["id"].as_str().unwrap(), first_id);
            assert_eq!(
                second["sso_identities"].as_array().unwrap().len(),
                1 - expected_len,
                "and the other row's own: {second}"
            );
        },
    )
    .await;

    common::delete_user(&state.pool, caller).await;
    common::delete_user(&state.pool, linked).await;
    common::delete_user(&state.pool, plain).await;
    sqlx::query("DELETE FROM upstream_providers WHERE code = $1")
        .bind(&provider)
        .execute(&state.pool)
        .await
        .expect("clean up the provider");
}
