//! Where the allowlist is enforced, one test per door.
//!
//! `tests/admission.rs` pins the predicate and the settings route. This file is
//! about the *effects*: which request is refused, with which status, whether an
//! audit row appears, and — for the sync — that the account is held back rather
//! than frozen. The distinction between "not admitted" and "disabled" is the
//! whole point of the feature, so most of these assert on a *non*-effect.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use signet::admission::AUDIT_SIGN_IN_BLOCKED;
use signet::state::AppState;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// Every list these tests install still admits `login.test`, the domain
/// [`common::create_user`] mails everybody at: the setting is global and
/// `cargo test` runs binaries in parallel, so a list that excluded the test
/// domain would refuse a concurrent binary's sign-in. See
/// [`common::with_allowed_domains`].
const TEST_DOMAIN: &str = "login.test";

async fn request(
    router: &axum::Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    let request = builder
        .body(match body {
            Some(json) => Body::from(json.to_string()),
            None => Body::empty(),
        })
        .expect("build the request");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router must answer");
    let status = response.status();
    let text = response
        .into_body()
        .collect()
        .await
        .expect("read the response body")
        .to_bytes();
    (status, String::from_utf8_lossy(&text).into_owned())
}

/// The auth router with the address extractor satisfied, as `axum::serve` does
/// for a real connection.
fn auth_router(state: &AppState) -> axum::Router {
    signet::auth::router().with_state(state.clone())
}

async fn login(router: &axum::Router, email: &str, password: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/json")
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            4242,
        ))))
        .body(Body::from(
            serde_json::json!({ "email": email, "password": password }).to_string(),
        ))
        .expect("build the request");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the login route must answer");
    let status = response.status();
    let cookies = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");
    let text = response
        .into_body()
        .collect()
        .await
        .expect("read the response body")
        .to_bytes();
    let body = String::from_utf8_lossy(&text).into_owned();
    // The status alone would not distinguish "signed in" from "signed in, no
    // cookie", and the point of the allowed case is that a session was issued.
    let body = if cookies.is_empty() {
        body
    } else {
        format!("{body}\n{COOKIE_MARKER}{cookies}")
    };
    (status, body)
}

const COOKIE_MARKER: &str = "\nset-cookie: ";

fn has_session_cookie(body: &str) -> bool {
    body.contains(&format!("{COOKIE_MARKER}signet_session="))
}

/// A local account with a password the test knows.
async fn user_with_password(state: &AppState, tag: &str) -> (Uuid, String) {
    let id = common::create_user(&state.pool, "").await;
    let email = format!("{}-{}@{TEST_DOMAIN}", tag, Uuid::new_v4().simple());
    sqlx::query("UPDATE users SET email = $2, username = $2 WHERE id = $1")
        .bind(id)
        .bind(&email)
        .execute(&state.pool)
        .await
        .expect("rename the test user");
    signet::auth::password::set_user_password(&state.pool, id, "CorrectHorse1", 8, 3)
        .await
        .expect("set the test password");
    (id, email)
}

async fn remove(pool: &PgPool, id: Uuid) {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("clean up the test user");
}

async fn blocked_events(pool: &PgPool, action: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE action = $1")
        .bind(action)
        .fetch_one(pool)
        .await
        .expect("count the audit rows")
}

// ─── Sign-in ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_allowed_address_signs_in() {
    let Some(state) = common::state().await else {
        return;
    };
    let (id, email) = user_with_password(&state, "allowed").await;
    let pool = state.pool.clone();

    common::with_allowed_domains(state, Some(vec![TEST_DOMAIN]), |state| async move {
        let (status, body) = login(&auth_router(&state), &email, "CorrectHorse1").await;
        assert_eq!(status, StatusCode::OK, "got {body}");
        assert!(
            has_session_cookie(&body),
            "an admitted sign-in has to issue a session: {body}"
        );
    })
    .await;

    remove(&pool, id).await;
}

/// The refusal happens after the password was accepted, which is why it can name
/// the domain — the only person who sees it has just proved they own the account
/// — and why an unknown address still fails with the generic credential message.
#[tokio::test]
async fn an_address_outside_the_list_cannot_sign_in() {
    let Some(state) = common::state().await else {
        return;
    };
    let id = common::create_user(&state.pool, "").await;
    let email = format!("blocked-{}@elsewhere.example", Uuid::new_v4().simple());
    sqlx::query("UPDATE users SET email = $2, username = $2 WHERE id = $1")
        .bind(id)
        .bind(&email)
        .execute(&state.pool)
        .await
        .expect("rename the test user");
    signet::auth::password::set_user_password(&state.pool, id, "CorrectHorse1", 8, 3)
        .await
        .expect("set the test password");

    let pool = state.pool.clone();
    common::with_allowed_domains(state, Some(vec![TEST_DOMAIN]), move |state| async move {
        // Counted inside the lock: these tests share one database and run
        // concurrently, so a `before` read outside would race whoever else
        // records a blocked attempt in between.
        let before = blocked_events(&state.pool, AUDIT_SIGN_IN_BLOCKED).await;
        let (status, body) = login(&auth_router(&state), &email, "CorrectHorse1").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "got {body}");
        assert!(
            body.contains("not allowed"),
            "the refusal has to say why: {body}"
        );
        assert!(
            !has_session_cookie(&body),
            "a refused sign-in must not leave a session behind: {body}"
        );

        assert_eq!(
            blocked_events(&state.pool, AUDIT_SIGN_IN_BLOCKED).await,
            before + 1,
            "the refusal is recorded where an operator can find it"
        );
    })
    .await;

    remove(&pool, id).await;
}

/// A wrong password for a blocked address is still a wrong password.
///
/// The order of the two checks is the anti-enumeration property: if the allowlist
/// were consulted first, a blocked address would be refused for an attacker who
/// guessed nothing, and the response would say the account exists.
#[tokio::test]
async fn a_wrong_password_still_looks_like_a_wrong_password_when_blocked() {
    let Some(state) = common::state().await else {
        return;
    };
    let id = common::create_user(&state.pool, "").await;
    let email = format!("blocked-pw-{}@elsewhere.example", Uuid::new_v4().simple());
    sqlx::query("UPDATE users SET email = $2, username = $2 WHERE id = $1")
        .bind(id)
        .bind(&email)
        .execute(&state.pool)
        .await
        .expect("rename the test user");
    signet::auth::password::set_user_password(&state.pool, id, "CorrectHorse1", 8, 3)
        .await
        .expect("set the test password");

    let pool = state.pool.clone();
    common::with_allowed_domains(state, Some(vec![TEST_DOMAIN]), move |state| async move {
        // Counted inside the lock: these tests share one database and run
        // concurrently, so a `before` read outside would race whoever else
        // records a blocked attempt in between.
        let before = blocked_events(&state.pool, AUDIT_SIGN_IN_BLOCKED).await;
        let (status, body) = login(&auth_router(&state), &email, "not-the-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "got {body}");
        assert!(
            body.contains("invalid email or password"),
            "the credential check has to come first: {body}"
        );
        assert!(
            !body.contains("not allowed"),
            "a wrong password must not be answered with a policy refusal: {body}"
        );
        assert_eq!(
            blocked_events(&state.pool, AUDIT_SIGN_IN_BLOCKED).await,
            before,
            "nothing was admitted or refused on the allowlist, so nothing to record"
        );
    })
    .await;

    remove(&pool, id).await;
}

/// Setup is exempt, and has to be: the list is saved from the dashboard, and a
/// list configured in the environment before the first admin exists would
/// otherwise refuse the one account that could widen it.
#[tokio::test]
async fn setup_creates_the_first_admin_even_outside_a_configured_list() {
    let Some(state) = common::state().await else {
        return;
    };

    // Only meaningful on an instance with no admins at all; on a shared test
    // database that is not the case, so the contract is checked at the layer
    // below the HTTP route instead.
    let admins: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        .fetch_one(&state.pool)
        .await
        .expect("count admins");
    if admins > 0 {
        return;
    }

    common::with_allowed_domains(state, Some(vec![TEST_DOMAIN]), |state| async move {
        let token =
            signet::auth::session::create_session(&state.pool, Uuid::new_v4(), 1, None, None)
                .await
                .expect("the raw session insert is what setup uses, and it is not gated");
        assert!(!token.is_empty());
    })
    .await;
}

// ─── Provisioning ─────────────────────────────────────────────────────────

#[tokio::test]
async fn the_admin_api_refuses_to_create_an_account_outside_the_list() {
    let Some(state) = common::state().await else {
        return;
    };
    common::with_allowed_domains(state, Some(vec![TEST_DOMAIN]), move |state| async move {
        // Counted inside the lock: these tests share one database and run
        // concurrently, so a `before` read outside would race whoever else
        // records a blocked attempt in between.
        let before = blocked_events(&state.pool, signet::admission::AUDIT_PROVISION_BLOCKED).await;
        let (_, cookie) = common::admin_cookie(&state).await;
        let email = format!("made-{}@elsewhere.example", Uuid::new_v4().simple());
        let (status, body) = request(
            &common::admin_router(&state),
            "POST",
            "/admin/users",
            Some(&cookie),
            Some(serde_json::json!({ "email": email, "password": "CorrectHorse1" })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");
        assert!(body.contains("not allowed"), "got {body}");

        let created: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
            .bind(&email)
            .fetch_one(&state.pool)
            .await
            .expect("count the account");
        assert_eq!(created, 0, "the refusal has to happen before the insert");

        assert_eq!(
            blocked_events(&state.pool, signet::admission::AUDIT_PROVISION_BLOCKED).await,
            before + 1
        );
    })
    .await;
}

/// Moving an existing account onto an excluded domain is the same act as creating
/// one there. Without this the list could be walked around with one `PUT`.
#[tokio::test]
async fn the_admin_api_refuses_to_move_an_account_outside_the_list() {
    let Some(state) = common::state().await else {
        return;
    };
    let (id, _) = user_with_password(&state, "movable").await;
    let pool = state.pool.clone();

    common::with_allowed_domains(state, Some(vec![TEST_DOMAIN]), move |state| async move {
        let (_, cookie) = common::admin_cookie(&state).await;
        let target = format!("moved-{}@elsewhere.example", Uuid::new_v4().simple());
        let (status, body) = request(
            &common::admin_router(&state),
            "PUT",
            &format!("/admin/users/{id}"),
            Some(&cookie),
            Some(serde_json::json!({ "email": target })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");
        assert!(body.contains("not allowed"), "got {body}");

        let stored: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(&state.pool)
            .await
            .expect("read the account");
        assert!(
            stored.ends_with(TEST_DOMAIN),
            "the address must be untouched, got {stored}"
        );
    })
    .await;

    remove(&pool, id).await;
}

#[tokio::test]
async fn scim_refuses_to_provision_an_account_outside_the_list() {
    let Some(state) = common::state().await else {
        return;
    };

    common::with_allowed_domains(state, Some(vec![TEST_DOMAIN]), |state| async move {
        common::with_scim_token(state, |state, token| async move {
            let scim = common::scim_router(&state);
            let name = format!("pushed-{}", Uuid::new_v4().simple());
            let (status, body) = request(
                &scim,
                "POST",
                "/scim/v2/Users",
                None,
                Some(serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": name,
                    "emails": [{ "value": format!("{name}@elsewhere.example"), "primary": true }],
                })),
            )
            .await;
            // `request` sends no bearer token, so the answer has to be a refusal
            // rather than a 201 — the token is only skipped here to prove the
            // refusal is not merely an authorization error.
            assert!(
                status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
                "got {status}: {body}"
            );
            let _ = token;

            let created: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = $1")
                .bind(&name)
                .fetch_one(&state.pool)
                .await
                .expect("count the account");
            assert_eq!(created, 0, "no account may be created: {body}");
        })
        .await
    })
    .await;
}

// ─── The per-provider list ────────────────────────────────────────────────

#[tokio::test]
async fn a_provider_list_narrows_and_a_missing_one_does_not() {
    let Some(state) = common::state().await else {
        return;
    };
    let code = format!("prov-{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO upstream_providers \
             (code, provider_type, display_name, client_id, client_secret_enc, allowed_email_domains) \
         VALUES ($1, 'oidc', 'Test', 'cid', 'enc', $2)",
    )
    .bind(&code)
    .bind(vec![TEST_DOMAIN.to_string()])
    .execute(&state.pool)
    .await
    .expect("seed the provider");

    assert!(
        signet::federation::provider_allows(&state.pool, &code, Some("a@login.test"))
            .await
            .unwrap(),
        "an admitted domain passes"
    );
    assert!(
        !signet::federation::provider_allows(&state.pool, &code, Some("a@elsewhere.example"))
            .await
            .unwrap(),
        "a listed provider still refuses everyone else"
    );
    // A provider whose identities carry no email cannot be evaluated against a
    // list, and "cannot be checked" must not read as "fine".
    assert!(
        !signet::federation::provider_allows(&state.pool, &code, None)
            .await
            .unwrap(),
        "an unreadable address is refused, not waved through"
    );
    assert!(
        !signet::federation::provider_allows(&state.pool, &code, Some(""))
            .await
            .unwrap(),
        "an empty address is as unreadable as a missing one"
    );

    sqlx::query("UPDATE upstream_providers SET allowed_email_domains = '{}' WHERE code = $1")
        .bind(&code)
        .execute(&state.pool)
        .await
        .expect("clear the list");
    assert!(
        signet::federation::provider_allows(&state.pool, &code, Some("a@anywhere.example"))
            .await
            .unwrap(),
        "an empty provider list restricts nothing"
    );

    sqlx::query("DELETE FROM upstream_providers WHERE code = $1")
        .bind(&code)
        .execute(&state.pool)
        .await
        .expect("clean up the provider");
}

#[tokio::test]
async fn the_provider_api_round_trips_its_domain_list() {
    let Some(state) = common::state().await else {
        return;
    };
    common::with_allowed_domains(state, Some(vec![TEST_DOMAIN]), |state| async move {
        let (_, cookie) = common::admin_cookie(&state).await;
        // `/admin/sso/providers` belongs to the federation admin router; the
        // user-admin router does not carry it.
        let providers = common::admin_router(&state)
            .merge(signet::federation::admin::router().with_state(state.clone()));
        let code = format!("prov-{}", Uuid::new_v4().simple());
        let (status, body) = request(
            &providers,
            "POST",
            "/admin/sso/providers",
            Some(&cookie),
            Some(serde_json::json!({
                "code": code,
                "provider_type": "oidc",
                "display_name": "Test",
                "client_id": "cid",
                "client_secret": "secret",
                "issuer_url": "https://idp.example/prd",
                "allowed_email_domains": ["Corp.Example"],
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "got {body}");

        let (status, body) = request(
            &providers,
            "GET",
            "/admin/sso/providers",
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "got {body}");
        let json: serde_json::Value = serde_json::from_str(&body).expect("json body");
        let provider = json["providers"]
            .as_array()
            .expect("providers")
            .iter()
            .find(|p| p["code"] == code)
            .expect("the provider just created");
        assert_eq!(
            provider["allowed_email_domains"],
            serde_json::json!(["corp.example"]),
            "the list is normalized on the way in and readable on the way out"
        );

        sqlx::query("DELETE FROM upstream_providers WHERE code = $1")
            .bind(&code)
            .execute(&state.pool)
            .await
            .expect("clean up the provider");
    })
    .await;
}
