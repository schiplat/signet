//! Bulk import/export: per-row isolation, admission gating, and the CSV shape.
//!
//! The import contract is "a 300-row import must not die on row 297": every
//! row is validated on its own and failures are reported with the row index.
//! Export must be formula-neutralized (user-chosen fields land in spreadsheet
//! cells) and staff-only.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

async fn call_admin(
    state: &signet::state::AppState,
    cookie: &str,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            12345,
        ))));
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    let response = signet::admin::router()
        .with_state(state.clone())
        .oneshot(builder.body(body).expect("build request"))
        .await
        .expect("router answers");
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

fn tag(prefix: &str) -> String {
    format!("{}-{}", prefix, Uuid::new_v4().simple())
}

#[tokio::test]
async fn import_creates_skips_and_reports_row_errors_without_dying() {
    let Some(state) = common::state().await else {
        return;
    };
    let (_, cookie) = common::admin_cookie(&state).await;

    let existing = format!("{}@import.test", tag("exist"));
    let new1_email = format!("{}@import.test", tag("new1"));
    common::create_user(&state.pool, "").await; // control user, not part of batch
    sqlx::query(
        "INSERT INTO users (id, sub, email, display_name, password_hash, status, role) \
                 VALUES ($1, $2, $3, 'Pre', '', 'active', 'member')",
    )
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4().to_string())
    .bind(&existing)
    .execute(&state.pool)
    .await
    .expect("insert the pre-existing user");

    let batch = json!({
        "users": [
            { "email": new1_email, "display_name": "New One" },
            { "email": existing, "display_name": "Would Overwrite" },
            { "email": format!("{}@import.test", tag("badrole")), "role": "superuser",
              "display_name": "Bad Role" },
            { "email": format!("{}@import.test", tag("badpw")), "password": "short" },
        ],
        "update": false
    });
    // Note: `dup` is absent from the batch — the skip path is exercised by the
    // pre-existing row above.

    let (status, body) =
        call_admin(&state, &cookie, "POST", "/admin/users/import", Some(batch)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["created"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["skipped"].as_array().unwrap().len(), 1);
    assert_eq!(body["skipped"][0], json!(existing));
    // Row errors: admin-role escalation refused, weak password refused.
    assert_eq!(body["errors"].as_array().unwrap().len(), 2);
    let escalations: Vec<&Value> = body["errors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["error"].as_str().unwrap().contains("role"))
        .collect();
    assert!(
        !escalations.is_empty(),
        "role escalation must be a row error"
    );

    // The skipped user's display name is untouched.
    let display: String = sqlx::query_scalar("SELECT display_name FROM users WHERE email = $1")
        .bind(&existing)
        .fetch_one(&state.pool)
        .await
        .expect("read pre-existing user");
    assert_eq!(display, "Pre");

    // Passwordless rows start SSO-only (empty hash), like JIT members.
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE email = $1")
        .bind(&new1_email)
        .fetch_one(&state.pool)
        .await
        .expect("read imported user");
    assert_eq!(hash, "");
}

#[tokio::test]
async fn import_update_mode_overwrites_profile_but_never_passwords() {
    let Some(state) = common::state().await else {
        return;
    };
    let (_, cookie) = common::admin_cookie(&state).await;

    let email = format!("{}@import.test", tag("upd"));
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, sub, email, display_name, password_hash, status, role) \
                 VALUES ($1, $2, $3, 'Before', 'known-hash', 'active', 'member')",
    )
    .bind(id)
    .bind(Uuid::new_v4().to_string())
    .bind(&email)
    .execute(&state.pool)
    .await
    .expect("insert target user");

    let batch = json!({
        "users": [{ "email": email, "display_name": "After", "password": "NewPassw0rdX" }],
        "update": true
    });
    let (status, body) =
        call_admin(&state, &cookie, "POST", "/admin/users/import", Some(batch)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["updated"].as_array().unwrap().len(), 1);

    let (display, hash): (String, String) =
        sqlx::query_as("SELECT display_name, password_hash FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(&state.pool)
            .await
            .expect("read updated user");
    assert_eq!(display, "After");
    assert_eq!(hash, "known-hash", "import must never touch passwords");

    common::delete_user(&state.pool, id).await;
}

#[tokio::test]
async fn export_is_staff_only_and_formula_neutralized() {
    let Some(state) = common::state().await else {
        return;
    };
    // A member must be refused.
    let member = common::create_user(&state.pool, "").await;
    let token = signet::auth::session::create_session(&state.pool, member, 1, None, None)
        .await
        .expect("member session");
    let member_cookie = format!("{}={token}", signet::auth::session::SESSION_COOKIE);
    let response = signet::admin::router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/admin/users/export")
                .header("cookie", &member_cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router answers");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    common::delete_user(&state.pool, member).await;

    // Staff sees CSV with formula-neutralized cells.
    let (_, cookie) = common::admin_cookie(&state).await;
    let attacker = format!("=cmd|' /c calc'!@{}", tag("f").to_lowercase());
    sqlx::query(
        "INSERT INTO users (id, sub, email, display_name, password_hash, status, role) \
                 VALUES ($1, $2, $3, 'Safe', '', 'active', 'member')",
    )
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4().to_string())
    .bind(&attacker)
    .execute(&state.pool)
    .await
    .expect("insert formula user");

    let response = signet::admin::router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/admin/users/export")
                .header("cookie", &cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router answers");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .starts_with("text/csv"),
        "content-type must be CSV"
    );
    let csv = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let csv = String::from_utf8_lossy(&csv);
    assert!(csv.contains("email,username,display_name,role,status,groups,phone"));
    assert!(
        csv.contains(&format!("'{attacker}")),
        "formula prefix must be neutralized: {csv}"
    );
}
