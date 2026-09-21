//! The overview counters, after they were collapsed from nineteen round trips
//! into a handful of statements.
//!
//! The counters are read in one scan now, with `FILTER` clauses deciding which
//! rows of that scan each number counts. That is a behaviour-preserving rewrite
//! only if the `FILTER` clauses agree with the `WHERE` clauses they replaced —
//! a window missing from a filter, or a bound applied to the wrong one, would
//! still return a plausible-looking number. So the assertions here are exact
//! numbers rather than "greater than zero".
//!
//! Isolation comes from the `client_id` filter: every metric on the page is
//! scoped to one app, and the rows this test writes carry a random client id
//! nothing else uses. The rows are planted directly instead of driven through a
//! login, because what is under test is the arithmetic over `created_at`
//! windows, and a real login can only ever land in the 24-hour bucket.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

async fn get_stats(router: &axum::Router, cookie: &str, query: &str) -> Value {
    let request = Request::builder()
        .method("GET")
        .uri(format!("/admin/stats?{query}"))
        .header("cookie", cookie)
        .body(Body::empty())
        .expect("build request");
    let response = router.clone().oneshot(request).await.expect("send request");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "stats failed: {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).expect("stats is json")
}

/// Plants one `auth.login` row at `age` before now, attributed to `client_id`.
async fn plant_login(state: &signet::state::AppState, actor: Uuid, client_id: &str, age: Duration) {
    sqlx::query(
        r#"
        INSERT INTO audit_logs
            (id, actor_user_id, actor_email, action, resource_type, client_id, created_at)
        VALUES ($1, $2, 'stats@example.invalid', 'auth.login', 'user', $3, $4)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(actor)
    .bind(client_id)
    .bind(Utc::now() - age)
    .execute(&state.pool)
    .await
    .expect("plant a login row");
}

/// The three day-based windows and the three distinct-actor windows have to
/// count the same rows they counted when they were six separate queries.
///
/// Four rows are planted, one in each bucket: inside 24h, inside 7d only,
/// inside 30d only, and outside all three. Each has its own actor, so the
/// distinct counts can be told apart from the row counts (1/2/3 versus
/// 1/2/3, with four rows present in the table).
#[tokio::test]
async fn the_login_counters_still_respect_their_windows() {
    let Some(state) = common::state().await else {
        return;
    };
    let (admin, cookie) = common::admin_cookie(&state).await;
    let client = format!("stats-test-{}", Uuid::new_v4());

    let actors: Vec<Uuid> = {
        let mut ids = Vec::new();
        for _ in 0..3 {
            ids.push(common::create_user(&state.pool, "").await);
        }
        ids
    };

    plant_login(&state, actors[0], &client, Duration::hours(1)).await;
    plant_login(&state, actors[1], &client, Duration::days(3)).await;
    plant_login(&state, actors[2], &client, Duration::days(10)).await;
    // Outside every window. Counted by none of the six numbers; if a `FILTER`
    // is missing, this row is what makes the difference show up.
    plant_login(&state, actors[0], &client, Duration::days(40)).await;

    let body = get_stats(
        &common::admin_router(&state),
        &cookie,
        &format!("client_id={client}"),
    )
    .await;

    assert_eq!(body["logins_24h"], 1, "one row is inside 24 hours: {body}");
    assert_eq!(body["logins_7d"], 2, "two rows are inside 7 days: {body}");
    assert_eq!(
        body["logins_30d"], 3,
        "three rows are inside 30 days: {body}"
    );
    assert_eq!(
        body["unique_users_24h"], 1,
        "one distinct actor inside 24 hours: {body}"
    );
    assert_eq!(
        body["unique_users_7d"], 2,
        "two distinct actors inside 7 days: {body}"
    );
    assert_eq!(
        body["unique_users_30d"], 3,
        "three distinct actors inside 30 days: {body}"
    );

    // The trend and distribution reads share the scan's scope, so they must not
    // see rows the counters exclude.
    let browsers_total: i64 = body["browsers"]
        .as_array()
        .expect("browsers is an array")
        .iter()
        .map(|row| row["count"].as_i64().unwrap_or(0))
        .sum();
    assert_eq!(
        browsers_total, 3,
        "browser distribution is over the same 30 days: {body}"
    );

    // The counters block is unrelated to the client scope and must still be
    // populated — a cross join that matched no row would return zero here.
    assert!(
        body["users_total"].as_i64().unwrap_or(0) >= 4,
        "the admin, the three actors and possibly more: {body}"
    );
    assert!(body["clients_total"].as_i64().is_some(), "{body}");

    let _ = sqlx::query("DELETE FROM audit_logs WHERE client_id = $1")
        .bind(&client)
        .execute(&state.pool)
        .await;
    common::delete_user(&state.pool, admin).await;
    for id in actors {
        common::delete_user(&state.pool, id).await;
    }
}
