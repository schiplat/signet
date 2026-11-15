//! Branding: the product name the UI shows about itself. Public read
//! (sign-in/reset/setup are unauthenticated), admin write with validation,
//! DB > env precedence, and an audit trail without surprises.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

/// `branding.*` rows are singletons in a shared database, so the tests in this
/// binary must not interleave (one resets rows the other is asserting on).
static BRANDING_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn admin_call(
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
    let response = signet::settings::router()
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

/// The unauthenticated read lives on the public api_v1 router, not the admin
/// settings router — this is what the sign-in page mounts.
async fn public_branding(state: &signet::state::AppState) -> Value {
    let response = axum::Router::new()
        .route(
            "/branding",
            axum::routing::get(signet::settings::public_branding),
        )
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/branding")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router answers");
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

#[tokio::test]
async fn branding_names_validate_persist_and_reset() {
    let _guard = BRANDING_LOCK.lock().await;
    let Some(state) = common::state().await else {
        return;
    };
    sqlx::query("DELETE FROM app_settings WHERE key = 'branding.name'")
        .execute(&state.pool)
        .await
        .expect("clear branding");
    let (_, cookie) = common::admin_cookie(&state).await;

    // Public read before anything is set: the built-in default.
    let body = public_branding(&state).await;
    assert_eq!(body["name"], json!("Signet"));

    // Save a name; the public endpoint serves it without authentication.
    let (status, body) = admin_call(
        &state,
        &cookie,
        "PATCH",
        "/admin/settings/branding",
        Some(json!({ "name": "  Acme Identity  " })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], json!("Acme Identity"), "trimmed on save");
    let body = public_branding(&state).await;
    assert_eq!(body["name"], json!("Acme Identity"));

    // Refusals: empty, too long, control characters.
    for bad in ["   ", "", &"x".repeat(65), "bad\u{0007}name"] {
        let (status, _) = admin_call(
            &state,
            &cookie,
            "PATCH",
            "/admin/settings/branding",
            Some(json!({ "name": bad })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?}");
    }

    // Reset falls back to the built-in default (no env override in tests).
    let (status, body) =
        admin_call(&state, &cookie, "DELETE", "/admin/settings/branding", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["overridden"], json!(false));
    let body = public_branding(&state).await;
    assert_eq!(body["name"], json!("Signet"));

    // The audit trail carries the lifecycle.
    let events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action IN ('settings.branding_update', 'settings.branding_reset')",
    )
    .fetch_one(&state.pool)
    .await
    .expect("count audit");
    assert!(events >= 2, "{events} branding audit events");
}

/// Drives the public image endpoint (mounted on the public api router in
/// production; a two-line router here keeps the test independent of lib.rs).
async fn public_logo(state: &signet::state::AppState) -> (StatusCode, Option<String>, Vec<u8>) {
    let response = axum::Router::new()
        .route(
            "/branding/logo",
            axum::routing::get(signet::settings::public_branding_logo),
        )
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .uri("/branding/logo")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router answers");
    let status = response.status();
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes()
        .to_vec();
    (status, content_type, bytes)
}

/// 1×1 transparent PNG.
const PNG_1PX: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

#[tokio::test]
async fn a_logo_uploads_serves_and_removes() {
    let _guard = BRANDING_LOCK.lock().await;
    let Some(state) = common::state().await else {
        return;
    };
    sqlx::query("DELETE FROM app_settings WHERE key LIKE 'branding.%'")
        .execute(&state.pool)
        .await
        .expect("clear branding rows");

    let (admin, cookie) = common::admin_cookie(&state).await;
    common::with_user(state.clone(), admin, move |state, _| async move {
        // 1. Upload a real PNG data URL.
        let data_url = format!("data:image/png;base64,{PNG_1PX}");
        let (status, body) = admin_call(
            &state,
            &cookie,
            "POST",
            "/admin/settings/branding/logo",
            Some(json!({ "data_url": data_url })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["logo_set"], json!(true));
        let url = body["logo_url"].as_str().expect("logo url");
        assert!(
            url.starts_with("/api/v1/branding/logo?v="),
            "versioned URL busts the immutable cache: {url}"
        );

        // 2. The unauthenticated reads expose it.
        let brand = public_branding(&state).await;
        assert_eq!(brand["logo_url"], json!(url));
        let (status, content_type, bytes) = public_logo(&state).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some("image/png"));
        assert_eq!(
            &bytes[..8],
            &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
            "the stored bytes come back untouched"
        );

        // 3. Refusals: SVG (script-capable), mislabeled bytes, oversize.
        let mut oversize = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        oversize.resize(256 * 1024 + 1, 0);
        for bad in [
            json!({ "data_url": "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=" }),
            json!({ "data_url": format!("data:image/png;base64,{}", STANDARD.encode(b"not a png")) }),
            json!({ "data_url": "not-a-data-url" }),
            json!({ "data_url": format!("data:image/png;base64,{}", STANDARD.encode(oversize)) }),
        ] {
            let (status, body) = admin_call(
                &state,
                &cookie,
                "POST",
                "/admin/settings/branding/logo",
                Some(bad),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        }

        // 4. Removal: the endpoint 404s again and the public JSON reports null.
        let (status, body) = admin_call(
            &state,
            &cookie,
            "DELETE",
            "/admin/settings/branding/logo",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["logo_set"], json!(false));
        let (status, _, _) = public_logo(&state).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(public_branding(&state).await["logo_url"], Value::Null);

        // 5. Reset branding clears a logo too (the whole section resets).
        let (_, body) = admin_call(
            &state,
            &cookie,
            "POST",
            "/admin/settings/branding/logo",
            Some(json!({ "data_url": format!("data:image/png;base64,{PNG_1PX}") })),
        )
        .await;
        assert!(body["logo_set"].as_bool().expect("logo_set"));
        let (_, body) =
            admin_call(&state, &cookie, "DELETE", "/admin/settings/branding", None).await;
        assert_eq!(body["logo_set"], json!(false));
        let (status, _, _) = public_logo(&state).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // 6. Audit trail.
        let events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs \
             WHERE action IN ('settings.branding_logo_update', 'settings.branding_logo_remove')",
        )
        .fetch_one(&state.pool)
        .await
        .expect("count logo audit");
        assert!(events >= 3, "{events} logo audit events");

        sqlx::query("DELETE FROM app_settings WHERE key LIKE 'branding.%'")
            .execute(&state.pool)
            .await
            .expect("clear branding rows");
    })
    .await;
}
