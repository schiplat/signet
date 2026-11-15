//! Public self-registration: off by default, pending until the address is
//! verified, and refused unless SMTP and CAPTCHA are configured.
//!
//! One test function drives the whole flow: the CAPTCHA verify URL is
//! process-global, and the signup switch/allowlist are DB-global, so cases that
//! swapped them under each other would be testing the race rather than the
//! feature.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::extract::Form;
use axum::http::{Request, StatusCode};
use axum::{Json, Router};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// Every address this test creates, so cleanup can find leaked rows from an
/// earlier failed run too.
const PREFIX: &str = "it-signup-";
const PASSWORD: &str = "Sup3rSecret!";

/// Drives one request against the signup router. `ip` becomes the `AuditIp`
/// extension the access-log middleware installs in the live app.
async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    ip: &str,
    cookie: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .extension(signet::http::extract::AuditIp(Some(ip.to_string())));
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    let response = app
        .clone()
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

/// The siteverify stub: token "good" verifies, anything else is refused with
/// the same shape the real providers use.
async fn stub_verify(Form(form): Form<StubForm>) -> Json<Value> {
    if form.response == "good" {
        Json(json!({ "success": true }))
    } else {
        Json(json!({ "success": false, "error-codes": ["invalid-input-response"] }))
    }
}

#[derive(serde::Deserialize)]
struct StubForm {
    #[allow(dead_code)]
    secret: String,
    response: String,
}

fn signup_body(email: &str, password: &str, captcha: &str) -> Value {
    json!({
        "email": email,
        "password": password,
        "captcha_token": captcha,
    })
}

/// The token the outbox holds; tests decrypt it with the same key the mailer
/// would use, so no dev logging switch is needed.
async fn mailed_token(state: &signet::state::AppState, to: &str) -> String {
    let sealed: Option<String> = sqlx::query_scalar(
        "SELECT email_body_enc FROM outbox \
         WHERE kind = 'email' AND email_to = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(to)
    .fetch_optional(&state.pool)
    .await
    .expect("read the queued verification mail");
    let body = state
        .encryptor
        .decrypt(&sealed.expect("a verification email must be queued"))
        .expect("the queued body decrypts");
    assert!(
        body.contains("/signup/confirm#token="),
        "the token belongs in the URL fragment, not the query string: {body}"
    );
    let marker = "token=";
    let start = body
        .find(marker)
        .map(|i| i + marker.len())
        .expect("the verification link carries a token");
    body[start..]
        .chars()
        .take_while(|c| !c.is_whitespace())
        .collect()
}

/// Seeds a pending request with a token the test already knows, for the
/// confirm-side cases whose real token would be buried in an encrypted email.
async fn seed_pending(pool: &PgPool, email: &str, token: &str, expired: bool) {
    sqlx::query("DELETE FROM signup_requests WHERE email = $1")
        .bind(email)
        .execute(pool)
        .await
        .expect("clear a prior pending request");
    sqlx::query(
        r#"
        INSERT INTO signup_requests
            (id, email, display_name, password_hash, token_hash, expires_at)
        VALUES ($1, $2, 'Seed User', 'not-a-real-hash', $3,
                NOW() + CASE WHEN $4 THEN INTERVAL '-1 minute' ELSE INTERVAL '30 minutes' END)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(email)
    .bind(signet::crypto::util::sha256_hex(token))
    .bind(expired)
    .execute(pool)
    .await
    .expect("seed the pending request");
}

/// Removes every row this test (or a previous failed run) created under
/// [`PREFIX`], plus the switch itself.
async fn cleanup(pool: &PgPool) {
    let like = format!("{PREFIX}%");
    for sql in [
        "DELETE FROM outbox WHERE email_to LIKE $1",
        "DELETE FROM signup_requests WHERE email LIKE $1",
        "DELETE FROM signup_attempts WHERE email LIKE $1",
        "DELETE FROM audit_logs WHERE detail ->> 'email' LIKE $1",
        "DELETE FROM users WHERE email LIKE $1 OR username LIKE $1",
    ] {
        sqlx::query(sql)
            .bind(&like)
            .execute(pool)
            .await
            .expect("clean up signup test rows");
    }
    sqlx::query("DELETE FROM app_settings WHERE key = 'auth.public_signup'")
        .execute(pool)
        .await
        .expect("clear the signup switch");
}

#[tokio::test]
async fn public_signup_is_off_by_default_and_pending_until_verified() {
    // The CAPTCHA provider is per-process environment configuration; the stub
    // is what `SIGNET_CAPTCHA_VERIFY_URL` exists for.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the CAPTCHA stub");
    let stub_addr = listener.local_addr().expect("stub address");
    let stub = Router::new().route("/siteverify", axum::routing::post(stub_verify));
    tokio::spawn(async move {
        axum::serve(listener, stub).await.expect("stub serves");
    });
    std::env::set_var(
        "SIGNET_CAPTCHA_VERIFY_URL",
        format!("http://{stub_addr}/siteverify"),
    );
    std::env::set_var("SIGNET_CAPTCHA_PROVIDER", "turnstile");
    std::env::set_var("SIGNET_CAPTCHA_SITE_KEY", "signup-test-site-key");
    std::env::set_var("SIGNET_CAPTCHA_SECRET_KEY", "signup-test-secret");
    // Enabling requires an email relay; resolution only needs a host, and the
    // outbox worker is not started by `build_state`, so nothing leaves the box.
    std::env::set_var("SIGNET_SMTP_HOST", "smtp.invalid");

    let Some(state) = common::state().await else {
        return;
    };
    // A failed earlier run can leave the namespace behind; start from the
    // documented default. DB rows would also shadow the env provider above.
    sqlx::query("DELETE FROM app_settings WHERE key LIKE 'captcha.%'")
        .execute(&state.pool)
        .await
        .expect("clear stale CAPTCHA settings");
    signet::admission::set_allowed_domains(&state.pool, None)
        .await
        .expect("start with no domain restriction");
    cleanup(&state.pool).await;

    let (admin, cookie) = common::admin_cookie(&state).await;
    let task_state = state.clone();
    let outcome = tokio::spawn(async move {
        let state = task_state;
        let app = signet::signup::router().with_state(state.clone());

        // ── Off by default ──────────────────────────────────────────────
        let (status, body) = call(&app, "GET", "/signup/status", None, "198.51.100.1", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["enabled"], json!(false));
        let (status, body) = call(
            &app,
            "POST",
            "/signup",
            Some(signup_body(
                &format!("{PREFIX}disabled@example.test"),
                PASSWORD,
                "good",
            )),
            "198.51.100.1",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        // ── Enabling without CAPTCHA is refused ─────────────────────────
        std::env::remove_var("SIGNET_CAPTCHA_PROVIDER");
        std::env::remove_var("SIGNET_CAPTCHA_SITE_KEY");
        std::env::remove_var("SIGNET_CAPTCHA_SECRET_KEY");
        let (status, body) = call(
            &app,
            "PATCH",
            "/admin/settings/signup",
            Some(json!({ "enabled": true })),
            "198.51.100.2",
            Some(&cookie),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "CAPTCHA is a hard prerequisite: {body}"
        );
        assert!(
            body["error"].as_str().unwrap_or("").contains("CAPTCHA"),
            "the refusal names the missing prerequisite: {body}"
        );
        // The admin view carries the same blocking list the UI renders.
        let (status, body) = call(
            &app,
            "GET",
            "/admin/settings/signup",
            None,
            "198.51.100.2",
            Some(&cookie),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ready"], json!(false));
        assert_eq!(body["smtp_configured"], json!(true));
        assert_eq!(body["captcha_configured"], json!(false));
        assert!(
            body["problems"]
                .as_array()
                .is_some_and(|p| p.iter().any(|v| v.as_str().unwrap_or("").contains("CAPTCHA"))),
            "{body}"
        );
        std::env::set_var("SIGNET_CAPTCHA_PROVIDER", "turnstile");
        std::env::set_var("SIGNET_CAPTCHA_SITE_KEY", "signup-test-site-key");
        std::env::set_var("SIGNET_CAPTCHA_SECRET_KEY", "signup-test-secret");

        // ── A configured relay must also be usable ──────────────────────
        // Presence of a host is not enough: an invalid From would fail on the
        // first verification mail, so the preflight must refuse it now.
        let previous_from: Option<Value> =
            sqlx::query_scalar("SELECT value FROM app_settings WHERE key = 'smtp.from'")
                .fetch_optional(&state.pool)
                .await
                .expect("read the current From setting");
        sqlx::query(
            "INSERT INTO app_settings (key, value, updated_at) VALUES ('smtp.from', $1, NOW()) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
        )
        .bind(json!("not a mailbox"))
        .execute(&state.pool)
        .await
        .expect("install an invalid From");
        let (status, body) = call(
            &app,
            "GET",
            "/admin/settings/signup",
            None,
            "198.51.100.2",
            Some(&cookie),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ready"], json!(false));
        assert_eq!(body["smtp_configured"], json!(false));
        assert!(
            body["problems"]
                .as_array()
                .is_some_and(|p| p.iter().any(|v| v.as_str().unwrap_or("").contains("From"))),
            "{body}"
        );
        let (status, body) = call(
            &app,
            "PATCH",
            "/admin/settings/signup",
            Some(json!({ "enabled": true })),
            "198.51.100.2",
            Some(&cookie),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body["error"].as_str().unwrap_or("").contains("From"),
            "the refusal names the unusable From: {body}"
        );
        match previous_from {
            Some(value) => {
                sqlx::query(
                    "INSERT INTO app_settings (key, value, updated_at) VALUES ('smtp.from', $1, NOW()) \
                     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
                )
                .bind(value)
                .execute(&state.pool)
                .await
                .expect("restore the From setting");
            }
            None => {
                sqlx::query("DELETE FROM app_settings WHERE key = 'smtp.from'")
                    .execute(&state.pool)
                    .await
                    .expect("remove the test From setting");
            }
        }

        // ── Turn it on ──────────────────────────────────────────────────
        let (status, body) = call(
            &app,
            "PATCH",
            "/admin/settings/signup",
            Some(json!({ "enabled": true })),
            "198.51.100.2",
            Some(&cookie),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["enabled"], json!(true));
        assert_eq!(body["smtp_configured"], json!(true));
        assert_eq!(body["captcha_configured"], json!(true));
        assert_eq!(body["ready"], json!(true));
        assert_eq!(body["problems"], json!([]));

        let (status, body) = call(&app, "GET", "/signup/status", None, "198.51.100.3", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["enabled"], json!(true));
        assert_eq!(body["captcha_enabled"], json!(true));
        assert!(body["min_password_length"].as_u64().unwrap_or(0) >= 8);

        // ── A prerequisite disappearing fails closed ────────────────────
        // The switch stays on, but the public page must stop advertising the
        // form and the endpoint must refuse rather than verify without a
        // challenge.
        std::env::remove_var("SIGNET_CAPTCHA_PROVIDER");
        std::env::remove_var("SIGNET_CAPTCHA_SITE_KEY");
        std::env::remove_var("SIGNET_CAPTCHA_SECRET_KEY");
        let (status, body) = call(&app, "GET", "/signup/status", None, "198.51.100.3", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["enabled"], json!(false));
        let (status, body) = call(
            &app,
            "GET",
            "/admin/settings/signup",
            None,
            "198.51.100.3",
            Some(&cookie),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ready"], json!(false));
        assert!(
            body["problems"]
                .as_array()
                .is_some_and(|p| p.iter().any(|v| v.as_str().unwrap_or("").contains("CAPTCHA"))),
            "the admin checklist explains the outage: {body}"
        );
        let (status, body) = call(
            &app,
            "POST",
            "/signup",
            Some(signup_body(
                &format!("{PREFIX}unavailable@example.test"),
                PASSWORD,
                "good",
            )),
            "198.51.100.3",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        std::env::set_var("SIGNET_CAPTCHA_PROVIDER", "turnstile");
        std::env::set_var("SIGNET_CAPTCHA_SITE_KEY", "signup-test-site-key");
        std::env::set_var("SIGNET_CAPTCHA_SECRET_KEY", "signup-test-secret");

        // ── CAPTCHA gates the form ──────────────────────────────────────
        let (status, body) = call(
            &app,
            "POST",
            "/signup",
            Some(json!({
                "email": format!("{PREFIX}nocaptcha@example.test"),
                "password": PASSWORD,
            })),
            "198.51.100.4",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let (status, body) = call(
            &app,
            "POST",
            "/signup",
            Some(signup_body(
                &format!("{PREFIX}badcaptcha@example.test"),
                PASSWORD,
                "bogus",
            )),
            "198.51.100.5",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // ── Weak password is refused ────────────────────────────────────
        let (status, body) = call(
            &app,
            "POST",
            "/signup",
            Some(signup_body(
                &format!("{PREFIX}weak@example.test"),
                "weakpassword",
                "good",
            )),
            "198.51.100.6",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM signup_requests WHERE email LIKE $1")
                .bind(format!("{PREFIX}weak%"))
                .fetch_one(&state.pool)
                .await
                .expect("count pending");
        assert_eq!(pending, 0, "a weak password creates no pending request");

        // ── The full flow: request → mail → confirm ─────────────────────
        let new_email = format!("{PREFIX}new@example.test");
        let (status, body) = call(
            &app,
            "POST",
            "/signup",
            Some(signup_body(&new_email, PASSWORD, "good")),
            "198.51.100.7",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, json!({ "status": "ok" }));

        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM signup_requests WHERE email = $1")
                .bind(&new_email)
                .fetch_one(&state.pool)
                .await
                .expect("count the pending request");
        assert_eq!(pending, 1, "the request is pending, not an account");
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
            .bind(&new_email)
            .fetch_one(&state.pool)
            .await
            .expect("count users");
        assert_eq!(users, 0, "confirmation, not the request, creates the user");

        let token = mailed_token(&state, &new_email).await;
        let (status, body) = call(
            &app,
            "POST",
            "/signup/confirm",
            Some(json!({ "token": token.clone() })),
            "198.51.100.7",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, json!({ "status": "ok" }));

        let (role, via, verified, display_name, password_hash): (
            String,
            Option<String>,
            bool,
            String,
            String,
        ) = sqlx::query_as(
            "SELECT role, provisioned_via, email_verified, display_name, password_hash \
             FROM users WHERE email = $1",
        )
        .bind(&new_email)
        .fetch_one(&state.pool)
        .await
        .expect("read the created user");
        assert_eq!(role, "member");
        assert_eq!(via.as_deref(), Some("signup"));
        assert!(verified, "the address was proven by the link");
        assert_eq!(display_name, "it-signup-new");
        assert!(
            signet::auth::password::verify_password_offloaded(PASSWORD, &password_hash)
                .await
                .expect("verify the stored hash"),
            "the chosen password must be the one stored"
        );

        let sessions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sessions WHERE user_id = \
                                               (SELECT id FROM users WHERE email = $1)",
        )
        .bind(&new_email)
        .fetch_one(&state.pool)
        .await
        .expect("count sessions");
        assert_eq!(sessions, 0, "confirmation must not sign anyone in");

        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM signup_requests WHERE email = $1")
                .bind(&new_email)
                .fetch_one(&state.pool)
                .await
                .expect("count the consumed request");
        assert_eq!(pending, 0, "the link is single-use");

        // Replaying the consumed link is the single-use assertion, and an
        // unknown token answers the same way (no oracle for link existence).
        for replay in [token, "definitely-not-a-live-token".to_string()] {
            let (status, body) = call(
                &app,
                "POST",
                "/signup/confirm",
                Some(json!({ "token": replay })),
                "198.51.100.7",
                None,
            )
            .await;
            assert_eq!(status, StatusCode::GONE, "{body}");
        }

        // ── An existing account gets a notice, not a verification link ──
        let existing = format!("{PREFIX}existing@example.test");
        sqlx::query(
            "INSERT INTO users (id, sub, email, display_name, password_hash, status, role) \
             VALUES ($1, $2, $3, 'Existing User', '', 'active', 'member')",
        )
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4().to_string())
        .bind(&existing)
        .execute(&state.pool)
        .await
        .expect("seed an existing account");
        let (status, body) = call(
            &app,
            "POST",
            "/signup",
            Some(signup_body(&existing, PASSWORD, "good")),
            "198.51.100.8",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, json!({ "status": "ok" }));
        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM signup_requests WHERE email = $1")
                .bind(&existing)
                .fetch_one(&state.pool)
                .await
                .expect("count pending for an existing account");
        assert_eq!(pending, 0);
        let subject: Option<String> = sqlx::query_scalar(
            "SELECT email_subject FROM outbox WHERE email_to = $1 \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&existing)
        .fetch_optional(&state.pool)
        .await
        .expect("read the notice email");
        assert_eq!(subject.as_deref(), Some("Signet account already exists"));

        // ── Per-email budget ────────────────────────────────────────────
        let rate_email = format!("{PREFIX}rate@example.test");
        for attempt in 0..4 {
            let (status, body) = call(
                &app,
                "POST",
                "/signup",
                Some(signup_body(&rate_email, PASSWORD, "good")),
                "198.51.100.9",
                None,
            )
            .await;
            if attempt < 3 {
                assert_eq!(status, StatusCode::OK, "attempt {attempt}: {body}");
            } else {
                assert_eq!(
                    status,
                    StatusCode::TOO_MANY_REQUESTS,
                    "the fourth request in the window is refused: {body}"
                );
            }
        }

        // ── Per-IP budget (weak passwords keep this cheap) ──────────────
        for attempt in 0..6 {
            let email = format!("{PREFIX}ip{attempt}@example.test");
            let (status, body) = call(
                &app,
                "POST",
                "/signup",
                Some(signup_body(&email, "weakpassword", "good")),
                "198.51.100.10",
                None,
            )
            .await;
            if attempt < 5 {
                assert_eq!(status, StatusCode::BAD_REQUEST, "attempt {attempt}: {body}");
            } else {
                assert_eq!(
                    status,
                    StatusCode::TOO_MANY_REQUESTS,
                    "the sixth request from one IP is refused: {body}"
                );
            }
        }

        // ── Confirmation refuses an address that was taken meanwhile ────
        let taken = format!("{PREFIX}taken@example.test");
        seed_pending(&state.pool, &taken, "taken-token", false).await;
        sqlx::query(
            "INSERT INTO users (id, sub, email, display_name, password_hash, status, role) \
             VALUES ($1, $2, $3, 'Taken User', '', 'active', 'member')",
        )
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4().to_string())
        .bind(&taken)
        .execute(&state.pool)
        .await
        .expect("seed the racing account");
        let (status, body) = call(
            &app,
            "POST",
            "/signup/confirm",
            Some(json!({ "token": "taken-token" })),
            "198.51.100.11",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM signup_requests WHERE email = $1")
                .bind(&taken)
                .fetch_one(&state.pool)
                .await
                .expect("count the consumed raced request");
        assert_eq!(pending, 0, "the refused link is still consumed");

        // ── Expired link ────────────────────────────────────────────────
        let expired = format!("{PREFIX}expired@example.test");
        seed_pending(&state.pool, &expired, "expired-token", true).await;
        let (status, body) = call(
            &app,
            "POST",
            "/signup/confirm",
            Some(json!({ "token": "expired-token" })),
            "198.51.100.12",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::GONE, "{body}");

        // ── The admission allowlist applies to signup too ───────────────
        common::with_allowed_domains(
            state.clone(),
            Some(vec!["login.test"]),
            |state| async move {
                let app = signet::signup::router().with_state(state.clone());
                let (status, body) = call(
                    &app,
                    "POST",
                    "/signup",
                    Some(signup_body(
                        &format!("{PREFIX}denied@example.test"),
                        PASSWORD,
                        "good",
                    )),
                    "198.51.100.13",
                    None,
                )
                .await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
                let pending: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM signup_requests WHERE email = $1")
                        .bind(format!("{PREFIX}denied@example.test"))
                        .fetch_one(&state.pool)
                        .await
                        .expect("count the denied request");
                assert_eq!(pending, 0);
            },
        )
        .await;

        // ── Disabling closes the door immediately ───────────────────────
        let (status, body) = call(
            &app,
            "PATCH",
            "/admin/settings/signup",
            Some(json!({ "enabled": false })),
            "198.51.100.2",
            Some(&cookie),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = call(&app, "GET", "/signup/status", None, "198.51.100.14", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["enabled"], json!(false));
        let (status, body) = call(
            &app,
            "POST",
            "/signup",
            Some(signup_body(
                &format!("{PREFIX}afterdisable@example.test"),
                PASSWORD,
                "good",
            )),
            "198.51.100.14",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    })
    .await;

    cleanup(&state.pool).await;
    common::delete_user(&state.pool, admin).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic.into_panic());
    }
}
