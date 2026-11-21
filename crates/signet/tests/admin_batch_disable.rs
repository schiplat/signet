//! `POST /admin/users/batch-disable` — the batch semantics.
//!
//! The handler used to walk the ids and call `set_user_access` per user, which
//! made a selection of N accounts 3+N round trips and recorded nothing in the
//! audit log at all. It now reads the roles in one query, updates in one
//! statement, revokes the sessions in one delete, and writes one audit event per
//! account.
//!
//! The rewrite has two properties that a per-user loop gave for free and a
//! batched statement does not: the permission check still applies to *each*
//! target (a manager must not be able to include an admin in the selection), and
//! the count still reflects only the accounts that actually changed.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{Form, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// Drives a request and returns the status and body.
async fn call(
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

/// A user with `role`, and a live session to check the revocation against.
async fn user_with_role(pool: &PgPool, role: &str) -> Uuid {
    let id = common::create_user(pool, "").await;
    sqlx::query("UPDATE users SET role = $2 WHERE id = $1")
        .bind(id)
        .bind(role)
        .execute(pool)
        .await
        .expect("set the role");
    signet::auth::session::create_session(pool, id, 1, None, None)
        .await
        .expect("create a session");
    id
}

async fn sessions_of(pool: &PgPool, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count the sessions")
}

async fn access_of(pool: &PgPool, user: Uuid) -> (String, bool) {
    sqlx::query_as("SELECT status, local_disabled FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("read the access state")
}

/// A manager is staff, so the route accepts them — but their selection must be
/// filtered, not merely allowed through because they named nobody they cannot
/// touch.
#[tokio::test]
async fn a_manager_cannot_disable_an_admin_through_a_batch() {
    let Some(state) = common::state().await else {
        return;
    };

    let manager = user_with_role(&state.pool, "manager").await;
    let member = user_with_role(&state.pool, "member").await;
    let admin = user_with_role(&state.pool, "admin").await;

    common::with_users(
        state.clone(),
        vec![manager, member, admin],
        |state, users| async move {
            let (manager, member, admin) = (users[0], users[1], users[2]);

            // A session for the manager, since `admin_cookie` creates its own
            // actor; this one is the *target* selector we are testing.
            let cookie = format!(
                "{}={}",
                signet::auth::session::SESSION_COOKIE,
                signet::auth::session::create_session(&state.pool, manager, 1, None, None)
                    .await
                    .expect("create the manager's session")
            );

            let (status, body) = call(
                &common::admin_router(&state),
                &cookie,
                "POST",
                "/admin/users/batch-disable",
                Some(serde_json::json!({ "ids": [member, admin] })),
            )
            .await;

            assert_eq!(status, StatusCode::OK, "body: {body}");
            assert_eq!(
                body, r#"{"disabled":1}"#,
                "only the member is within a manager's reach"
            );

            assert_eq!(
                access_of(&state.pool, member).await,
                ("disabled".to_string(), true),
                "the member must be disabled, with the local intent recorded"
            );
            assert_eq!(
                access_of(&state.pool, admin).await,
                ("active".to_string(), false),
                "the admin must be untouched"
            );
            assert_eq!(
                sessions_of(&state.pool, member).await,
                0,
                "a disabled account must not keep live sessions"
            );
            assert_eq!(
                sessions_of(&state.pool, admin).await,
                1,
                "and an untouched account keeps its own"
            );
        },
    )
    .await;

    common::delete_user(&state.pool, manager).await;
}

#[tokio::test]
async fn the_count_covers_only_the_accounts_that_changed() {
    let Some(state) = common::state().await else {
        return;
    };

    let (caller, cookie) = common::admin_cookie(&state).await;
    let first = common::create_user(&state.pool, "").await;
    let second = common::create_user(&state.pool, "").await;
    let absent = Uuid::new_v4();

    common::with_users(
        state.clone(),
        vec![first, second],
        move |state, users| async move {
            let router = common::admin_router(&state);

            let (status, body) = call(
                &router,
                &cookie,
                "POST",
                "/admin/users/batch-disable",
                Some(serde_json::json!({ "ids": [users[0], absent, users[1]] })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                body, r#"{"disabled":2}"#,
                "an id that does not exist is not a disable"
            );

            // Idempotent: disabling an already-disabled account still reports it,
            // because the row was written and the session sweep ran.
            let (status, body) = call(
                &router,
                &cookie,
                "POST",
                "/admin/users/batch-disable",
                Some(serde_json::json!({ "ids": users })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, r#"{"disabled":2}"#);
        },
    )
    .await;

    common::delete_user(&state.pool, caller).await;
}

/// The bulk path recorded no audit events at all, so a selection of accounts
/// disabled by a manager left nothing behind naming who they were.
#[tokio::test]
async fn every_account_in_the_batch_is_audited() {
    let Some(state) = common::state().await else {
        return;
    };

    let (caller, cookie) = common::admin_cookie(&state).await;
    let first = common::create_user(&state.pool, "").await;
    let second = common::create_user(&state.pool, "").await;

    common::with_users(
        state.clone(),
        vec![first, second],
        move |state, users| async move {
            let (status, body) = call(
                &common::admin_router(&state),
                &cookie,
                "POST",
                "/admin/users/batch-disable",
                Some(serde_json::json!({ "ids": users })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "body: {body}");

            let audited: Vec<(String, String)> = sqlx::query_as(
                "SELECT resource_id, detail->>'email' FROM audit_logs \
                 WHERE action = 'user.disable' AND actor_user_id = $1",
            )
            .bind(caller)
            .fetch_all(&state.pool)
            .await
            .expect("read the audit trail");

            let mut ids: Vec<String> = audited.iter().map(|(id, _)| id.clone()).collect();
            ids.sort();
            let mut expected: Vec<String> = users.iter().map(|u| u.to_string()).collect();
            expected.sort();
            assert_eq!(ids, expected, "one event per disabled account");

            assert!(
                audited.iter().all(|(_, email)| !email.is_empty()),
                "each event names the account: {audited:?}"
            );
        },
    )
    .await;

    common::delete_user(&state.pool, caller).await;
}

/// The relying party stub: records every `logout_token` it is sent, so the
/// assertion can be about the notification, not just the delete.
type LogoutTokens = Arc<Mutex<Vec<String>>>;

#[tokio::test]
async fn a_batch_disable_notifies_the_relying_party_of_what_it_revoked() {
    let Some(state) = common::state_with(|cfg| cfg.outbound_allow_private = true).await else {
        return;
    };

    // The stub RP, reachable because this state allows loopback outbound.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the RP stub");
    let stub_addr = listener.local_addr().expect("stub address");
    let received: LogoutTokens = Arc::new(Mutex::new(Vec::new()));
    let stub_calls = Arc::clone(&received);
    let stub = Router::new().route(
        "/backchannel",
        axum::routing::post(move |Form(form): Form<HashMap<String, String>>| {
            let calls = Arc::clone(&stub_calls);
            async move {
                if let Some(token) = form.get("logout_token") {
                    calls.lock().expect("the stub lock").push(token.clone());
                }
                StatusCode::OK
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, stub).await.expect("stub serves");
    });

    let client_id = format!("bc-{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO client_apps \
             (id, client_id, client_secret_hash, redirect_uris, \
              backchannel_logout_uri, ip_allowlist_enabled) \
         VALUES ($1, $2, 'test', ARRAY['http://localhost/cb'], $3, FALSE)",
    )
    .bind(Uuid::new_v4())
    .bind(&client_id)
    .bind(format!("http://{stub_addr}/backchannel"))
    .execute(&state.pool)
    .await
    .expect("insert the RP client");

    let (caller, cookie) = common::admin_cookie(&state).await;
    let granted = common::create_user(&state.pool, "").await;
    let ungranted = common::create_user(&state.pool, "").await;
    let client_for_cleanup = client_id.clone();

    common::with_users(
        state.clone(),
        vec![granted, ungranted],
        move |state, users| async move {
            // The consent is what puts the client in the notification's reach; the
            // second subject deliberately never granted it. Both lose sessions.
            sqlx::query(
                "INSERT INTO oauth_consents (id, user_id, client_id, scopes) \
             VALUES ($1, $2, $3, 'openid')",
            )
            .bind(Uuid::new_v4())
            .bind(users[0])
            .bind(&client_id)
            .execute(&state.pool)
            .await
            .expect("grant the client");
            for user in &users {
                signet::auth::session::create_session(&state.pool, *user, 1, None, None)
                    .await
                    .expect("create a session");
            }
            // The token's `sub` is the account's OIDC subject, not its row id.
            let (subject,): (String,) = sqlx::query_as("SELECT sub FROM users WHERE id = $1")
                .bind(users[0])
                .fetch_one(&state.pool)
                .await
                .expect("read the granted account's subject");

            let (status, body) = call(
                &common::admin_router(&state),
                &cookie,
                "POST",
                "/admin/users/batch-disable",
                Some(serde_json::json!({ "ids": users })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "body: {body}");
            assert_eq!(body, r#"{"disabled":2}"#);

            let tokens = received.lock().expect("the stub lock").clone();
            assert_eq!(
                tokens.len(),
                1,
                "only the subject that granted the client is notified"
            );

            // The notification is a Signet-signed JWT; its payload names the
            // revoked subject, the notified client and the logout event.
            let parts: Vec<&str> = tokens[0].split('.').collect();
            let payload = URL_SAFE_NO_PAD
                .decode(parts[1])
                .expect("decode the logout token payload");
            let claims: serde_json::Value =
                serde_json::from_slice(&payload).expect("parse the logout token claims");
            assert_eq!(
                claims["sub"], subject,
                "the notified subject is the one that lost a session"
            );
            assert_eq!(claims["aud"], client_id, "the token names the RP");
            assert!(
                claims["events"]
                    .get("http://schemas.openid.net/event/backchannel-logout")
                    .is_some(),
                "the back-channel-logout event member is present: {:?}",
                claims["events"]
            );
        },
    )
    .await;

    common::delete_user(&state.pool, caller).await;
    sqlx::query("DELETE FROM client_apps WHERE client_id = $1")
        .bind(client_for_cleanup)
        .execute(&state.pool)
        .await
        .expect("remove the RP client");
}
