//! Self-service client registration — the GitHub-style "my apps" surface.
//!
//! What these tests pin down is the ownership boundary, because that is the
//! whole security story: every /me/clients read and write is scoped to
//! `owner_id = current user`, a miss is a plain 404 (no existence leak), and
//! the plaintext secret travels to the dashboard exactly once. The SQL
//! defaults (grants, PKCE, allowlist off) are asserted once so the form cannot
//! silently drift from the RFC 7591 registration defaults.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::Row;
use tower::ServiceExt;
use uuid::Uuid;

/// Drives one request against the developer router and returns status + body.
async fn call(
    state: &signet::state::AppState,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            12345,
        ))));
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    let response = signet::developer::router()
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

fn cookie_for(token: String) -> String {
    format!("{}={token}", signet::auth::session::SESSION_COOKIE)
}

/// Removes the clients a test created, before user cleanup turns them into
/// unowned rows in the shared database.
async fn delete_clients_owned_by(state: &signet::state::AppState, users: &[Uuid]) {
    sqlx::query("DELETE FROM client_apps WHERE owner_id = ANY($1)")
        .bind(users)
        .execute(&state.pool)
        .await
        .expect("delete test clients");
}

#[tokio::test]
async fn registration_applies_rfc7591_defaults_and_shows_the_secret_once() {
    let Some(state) = common::state().await else {
        return;
    };
    let user = common::create_user(&state.pool, "").await;
    common::with_user(state.clone(), user, move |state, user| async move {
        let token = signet::auth::session::create_session(&state.pool, user, 1, None, None)
            .await
            .expect("create session");
        let cookie = cookie_for(token);

        let (status, body) = call(
            &state,
            "POST",
            "/me/clients",
            Some(&cookie),
            Some(json!({
                "client_name": "My Integration",
                "redirect_uris": ["https://app.example/callback"]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create answered {body}");
        assert!(
            body["client"]["client_id"]
                .as_str()
                .expect("client_id")
                .starts_with("sgn_cl_"),
            "self-registered ids use the generated sgn_cl_ prefix: {body}"
        );
        let secret = body["client_secret"].as_str().expect("plaintext secret");
        assert!(!secret.is_empty());

        // The stored row: ownership recorded, defaults identical to RFC 7591
        // registration, and only the hash persisted.
        let client_id = body["client"]["client_id"].as_str().expect("client_id");
        let row = sqlx::query(
            "SELECT owner_id, client_name, grant_types, pkce_required, \
                    ip_allowlist_enabled, scopes, client_secret_hash \
             FROM client_apps WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_one(&state.pool)
        .await
        .expect("load created client");
        assert_eq!(
            row.try_get::<Option<uuid::Uuid>, _>("owner_id")
                .expect("owner_id"),
            Some(user)
        );
        assert_eq!(
            row.try_get::<String, _>("client_name")
                .expect("client_name"),
            "My Integration"
        );
        assert_eq!(
            row.try_get::<Vec<String>, _>("grant_types")
                .expect("grant_types"),
            vec!["authorization_code", "refresh_token"]
        );
        assert!(row.try_get::<bool, _>("pkce_required").expect("pkce"));
        assert!(!row
            .try_get::<bool, _>("ip_allowlist_enabled")
            .expect("allowlist off"));
        assert_eq!(
            row.try_get::<Vec<String>, _>("scopes").expect("scopes"),
            vec!["email", "openid", "profile"]
        );
        assert_ne!(
            row.try_get::<String, _>("client_secret_hash")
                .expect("hash"),
            secret,
            "only the keyed digest is stored, never the plaintext"
        );

        delete_clients_owned_by(&state, &[user]).await;
    })
    .await;
}

#[tokio::test]
async fn an_unauthenticated_request_is_rejected() {
    let Some(state) = common::state().await else {
        return;
    };
    let (status, _) = call(&state, "GET", "/me/clients", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(
        &state,
        "POST",
        "/me/clients",
        None,
        Some(json!({"client_name": "X", "redirect_uris": ["https://a.example/c"]})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn owners_see_only_their_own_clients() {
    let Some(state) = common::state().await else {
        return;
    };
    let u1 = common::create_user(&state.pool, "").await;
    let u2 = common::create_user(&state.pool, "").await;
    common::with_users(state, vec![u1, u2], move |state, users| async move {
        let (u1, u2) = (users[0], users[1]);
        let cookie1 = cookie_for(
            signet::auth::session::create_session(&state.pool, u1, 1, None, None)
                .await
                .expect("session 1"),
        );
        let cookie2 = cookie_for(
            signet::auth::session::create_session(&state.pool, u2, 1, None, None)
                .await
                .expect("session 2"),
        );

        for name in ["App One", "App Two"] {
            let (status, _) = call(
                &state,
                "POST",
                "/me/clients",
                Some(&cookie1),
                Some(json!({
                    "client_name": name,
                    "redirect_uris": ["https://one.example/cb"]
                })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
        let (status, _) = call(
            &state,
            "POST",
            "/me/clients",
            Some(&cookie2),
            Some(json!({
                "client_name": "App Three",
                "redirect_uris": ["https://two.example/cb"]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, list1) = call(&state, "GET", "/me/clients", Some(&cookie1), None).await;
        assert_eq!(status, StatusCode::OK);
        let ids1: Vec<&str> = list1
            .as_array()
            .expect("list")
            .iter()
            .map(|c| c["client_id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids1.len(), 2, "owner 1 sees exactly their two: {list1}");

        let (status, list2) = call(&state, "GET", "/me/clients", Some(&cookie2), None).await;
        assert_eq!(status, StatusCode::OK);
        let ids2: Vec<&str> = list2
            .as_array()
            .expect("list")
            .iter()
            .map(|c| c["client_id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids2.len(), 1);
        assert!(
            ids1.iter().all(|id| !ids2.contains(id)),
            "ownership sets are disjoint: {ids1:?} vs {ids2:?}"
        );

        delete_clients_owned_by(&state, &users).await;
    })
    .await;
}

#[tokio::test]
async fn another_owners_client_is_a_plain_404() {
    let Some(state) = common::state().await else {
        return;
    };
    let u1 = common::create_user(&state.pool, "").await;
    let u2 = common::create_user(&state.pool, "").await;
    common::with_users(state, vec![u1, u2], move |state, users| async move {
        let (u1, u2) = (users[0], users[1]);
        let cookie1 = cookie_for(
            signet::auth::session::create_session(&state.pool, u1, 1, None, None)
                .await
                .expect("session 1"),
        );
        let cookie2 = cookie_for(
            signet::auth::session::create_session(&state.pool, u2, 1, None, None)
                .await
                .expect("session 2"),
        );

        let (status, created) = call(
            &state,
            "POST",
            "/me/clients",
            Some(&cookie1),
            Some(json!({
                "client_name": "App One",
                "redirect_uris": ["https://one.example/cb"]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let client_pk = created["client"]["id"].as_str().expect("uuid");

        let uri = format!("/me/clients/{client_pk}");
        let (status, _) = call(
            &state,
            "PUT",
            &uri,
            Some(&cookie2),
            Some(json!({"client_name": "Hijacked"})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "rename across owners");

        let (status, _) = call(
            &state,
            "POST",
            &format!("{uri}/rotate-secret"),
            Some(&cookie2),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "rotate across owners");

        let (status, _) = call(&state, "DELETE", &uri, Some(&cookie2), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "delete across owners");

        // The stored name is untouched: the 404s were refusals, not effects.
        let stored: String =
            sqlx::query_scalar("SELECT client_name FROM client_apps WHERE id = $1")
                .bind(client_pk.parse::<uuid::Uuid>().expect("uuid"))
                .fetch_one(&state.pool)
                .await
                .expect("load client");
        assert_eq!(stored, "App One");

        delete_clients_owned_by(&state, &users).await;
    })
    .await;
}

#[tokio::test]
async fn rotate_replaces_the_stored_secret() {
    let Some(state) = common::state().await else {
        return;
    };
    let user = common::create_user(&state.pool, "").await;
    common::with_user(state.clone(), user, move |state, user| async move {
        let cookie = cookie_for(
            signet::auth::session::create_session(&state.pool, user, 1, None, None)
                .await
                .expect("session"),
        );
        let (_, created) = call(
            &state,
            "POST",
            "/me/clients",
            Some(&cookie),
            Some(json!({
                "client_name": "App",
                "redirect_uris": ["https://app.example/cb"]
            })),
        )
        .await;
        let old_secret = created["client_secret"]
            .as_str()
            .expect("secret")
            .to_string();
        let client_pk: Uuid = created["client"]["id"]
            .as_str()
            .expect("uuid")
            .parse()
            .expect("uuid");

        let (status, rotated) = call(
            &state,
            "POST",
            &format!("/me/clients/{client_pk}/rotate-secret"),
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let new_secret = rotated["client_secret"].as_str().expect("new secret");
        assert_ne!(new_secret, old_secret);

        let stored: String =
            sqlx::query_scalar("SELECT client_secret_hash FROM client_apps WHERE id = $1")
                .bind(client_pk)
                .fetch_one(&state.pool)
                .await
                .expect("load client");
        let new_hash = signet::auth::client_secret::digest(&state.client_secret_key, new_secret);
        assert_eq!(stored, new_hash, "the new secret is the live one");

        delete_clients_owned_by(&state, &[user]).await;
    })
    .await;
}

#[tokio::test]
async fn the_admin_list_names_the_owner_and_unowned_rows_stay_blank() {
    // The admin surface is where "who owns this" has to be answerable: staff
    // manage every client and must see whose self-registered app they are
    // about to rotate or delete. Admin-created clients (owner NULL) stay "—".
    let Some(state) = common::state().await else {
        return;
    };
    let owner = common::create_user(&state.pool, "").await;
    let (admin_id, admin_cookie) = common::admin_cookie(&state).await;
    let owner_email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(owner)
        .fetch_one(&state.pool)
        .await
        .expect("owner email");

    common::with_users(
        state.clone(),
        vec![owner, admin_id],
        move |state, users| async move {
            let owner = users[0];
            let cookie = cookie_for(
                signet::auth::session::create_session(&state.pool, owner, 1, None, None)
                    .await
                    .expect("owner session"),
            );
            let (status, created) = call(
                &state,
                "POST",
                "/me/clients",
                Some(&cookie),
                Some(json!({
                    "client_name": "Owned App",
                    "redirect_uris": ["https://owned.example/cb"]
                })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);

            // An admin-created client in the same list: no owner.
            let legacy_id = format!("admin-{}", Uuid::new_v4().simple());
            sqlx::query(
                "INSERT INTO client_apps (id, client_id, client_secret_hash, redirect_uris) \
             VALUES ($1, $2, 'x', ARRAY['https://legacy.example/cb'])",
            )
            .bind(Uuid::new_v4())
            .bind(&legacy_id)
            .execute(&state.pool)
            .await
            .expect("insert admin client");

            let response = signet::admin::router()
                .with_state(state.clone())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/admin/clients")
                        .header("cookie", &admin_cookie)
                        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            12345,
                        ))))
                        .body(Body::empty())
                        .expect("build request"),
                )
                .await
                .expect("admin router answers");
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = response
                .into_body()
                .collect()
                .await
                .expect("read body")
                .to_bytes();
            let list: Value = serde_json::from_slice(&bytes).expect("json list");

            let owned = list
                .as_array()
                .expect("list")
                .iter()
                .find(|c| c["client_id"] == created["client"]["client_id"])
                .expect("owned app is listed");
            assert_eq!(owned["owner_email"], json!(owner_email), "owner is named");
            assert_eq!(
                owned["owner_id"],
                json!(owner.to_string()),
                "owner_id is the owning user"
            );
            let admin_made = list
                .as_array()
                .expect("list")
                .iter()
                .find(|c| c["client_id"] == json!(legacy_id))
                .expect("admin-created app is listed");
            assert!(
                admin_made["owner_email"].is_null() && admin_made["owner_id"].is_null(),
                "admin-created clients have no owner: {admin_made}"
            );

            sqlx::query("DELETE FROM client_apps WHERE client_id = $1")
                .bind(&legacy_id)
                .execute(&state.pool)
                .await
                .expect("remove admin client");
            delete_clients_owned_by(&state, &users).await;
        },
    )
    .await;
}

#[tokio::test]
async fn delete_removes_the_client_and_cascades() {
    let Some(state) = common::state().await else {
        return;
    };
    let user = common::create_user(&state.pool, "").await;
    common::with_user(state.clone(), user, move |state, user| async move {
        let cookie = cookie_for(
            signet::auth::session::create_session(&state.pool, user, 1, None, None)
                .await
                .expect("session"),
        );
        let (_, created) = call(
            &state,
            "POST",
            "/me/clients",
            Some(&cookie),
            Some(json!({
                "client_name": "App",
                "redirect_uris": ["https://app.example/cb"]
            })),
        )
        .await;
        let client_pk: Uuid = created["client"]["id"]
            .as_str()
            .expect("uuid")
            .parse()
            .expect("uuid");
        let client_id = created["client"]["client_id"].as_str().expect("client_id");

        // A consent row must go with the client, matching the admin delete
        // contract (oauth_consents.client_id is ON DELETE CASCADE).
        sqlx::query(
            "INSERT INTO oauth_consents (id, user_id, client_id, scopes) \
             VALUES ($1, $2, $3, 'openid')",
        )
        .bind(Uuid::new_v4())
        .bind(user)
        .bind(client_id)
        .execute(&state.pool)
        .await
        .expect("seed consent");

        let (status, body) = call(
            &state,
            "DELETE",
            &format!("/me/clients/{client_pk}"),
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "delete answered {body}");
        assert_eq!(body["ok"], json!(true));

        assert!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM client_apps WHERE id = $1")
                .bind(client_pk)
                .fetch_one(&state.pool)
                .await
                .expect("count clients")
                == 0,
            "client row is gone"
        );
        assert!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM oauth_consents WHERE client_id = $1"
            )
            .bind(client_id)
            .fetch_one(&state.pool)
            .await
            .expect("count consents")
                == 0,
            "consent cascaded"
        );

        // Repeating the delete is the same 404 any stranger would get.
        let (status, _) = call(
            &state,
            "DELETE",
            &format!("/me/clients/{client_pk}"),
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn the_form_rejects_an_unusable_application() {
    let Some(state) = common::state().await else {
        return;
    };
    let user = common::create_user(&state.pool, "").await;
    common::with_user(state.clone(), user, move |state, user| async move {
        let cookie = cookie_for(
            signet::auth::session::create_session(&state.pool, user, 1, None, None)
                .await
                .expect("session"),
        );

        for (label, payload) in [
            (
                "empty name",
                json!({"client_name": "   ", "redirect_uris": ["https://a.example/c"]}),
            ),
            (
                "no redirect uris",
                json!({"client_name": "App", "redirect_uris": []}),
            ),
            (
                "non-http redirect uri",
                json!({"client_name": "App", "redirect_uris": ["ftp://a.example/c"]}),
            ),
            (
                "scopes without openid",
                json!({"client_name": "App", "redirect_uris": ["https://a.example/c"], "scopes": ["profile"]}),
            ),
        ] {
            let (status, body) = call(&state, "POST", "/me/clients", Some(&cookie), Some(payload))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {body}");
        }

        // The update endpoint keeps absent fields — rename without re-sending
        // the redirect URIs does not wipe them.
        let (_, created) = call(
            &state,
            "POST",
            "/me/clients",
            Some(&cookie),
            Some(json!({
                "client_name": "App",
                "redirect_uris": ["https://app.example/cb"]
            })),
        )
        .await;
        let client_pk = created["client"]["id"].as_str().expect("uuid");
        let (status, updated) = call(
            &state,
            "PUT",
            &format!("/me/clients/{client_pk}"),
            Some(&cookie),
            Some(json!({"client_name": "Renamed"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(updated["client_name"], json!("Renamed"));
        assert_eq!(
            updated["redirect_uris"],
            json!(["https://app.example/cb"]),
            "absent redirect_uris keep the stored value"
        );

        delete_clients_owned_by(&state, &[user]).await;
    })
    .await;
}

#[tokio::test]
async fn unowned_clients_stay_admin_managed() {
    // A client that predates ownership (owner NULL) is invisible to the
    // self-service surface and untouched by the migration — deleting it stays
    // an admin operation.
    let Some(state) = common::state().await else {
        return;
    };
    let user = common::create_user(&state.pool, "").await;
    common::with_user(state.clone(), user, move |state, user| async move {
        let cookie = cookie_for(
            signet::auth::session::create_session(&state.pool, user, 1, None, None)
                .await
                .expect("session"),
        );
        let legacy_id = format!("legacy-{}", Uuid::new_v4().simple());
        let legacy_pk = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO client_apps (id, client_id, client_secret_hash, redirect_uris) \
             VALUES ($1, $2, 'x', ARRAY['https://legacy.example/cb'])",
        )
        .bind(legacy_pk)
        .bind(&legacy_id)
        .execute(&state.pool)
        .await
        .expect("insert legacy client");

        let (status, list) = call(&state, "GET", "/me/clients", Some(&cookie), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !list
                .as_array()
                .expect("list")
                .iter()
                .any(|c| c["client_id"] == json!(legacy_id)),
            "an unowned client never appears in a user's list: {list}"
        );

        sqlx::query("DELETE FROM client_apps WHERE id = $1")
            .bind(legacy_pk)
            .execute(&state.pool)
            .await
            .expect("remove legacy client");
    })
    .await;
}
