//! RFC 7591 dynamic client registration.
//!
//! Pins the interoperability details that standard clients depend on: the
//! space-separated `scope` string (not just our native `scopes` array), the
//! `sgn_cl_` / `sgn_cs_` credential prefixes, the single-use initial access
//! token, and the registration defaults (PKCE, auth-code + refresh, no IP
//! allowlist). `client_name` must survive into the dashboard's Name column —
//! dropping it made registered clients anonymous.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

fn addr() -> ConnectInfo<std::net::SocketAddr> {
    ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 12345)))
}

async fn read_json(response: axum::response::Response) -> (StatusCode, Value) {
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

async fn issue_token(state: &signet::state::AppState, cookie: &str) -> String {
    let response = signet::admin::router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/clients/registration-tokens")
                .header("cookie", cookie)
                .extension(addr())
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("admin router answers");
    let (status, body) = read_json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["token"]
        .as_str()
        .expect("registration token")
        .to_string()
}

async fn register(
    state: &signet::state::AppState,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = signet::oidc::router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .extension(addr())
                .body(Body::from(body.to_string()))
                .expect("build request"),
        )
        .await
        .expect("oidc router answers");
    read_json(response).await
}

#[tokio::test]
async fn a_standard_client_registers_with_the_scope_string_and_defaults() {
    let Some(state) = common::state().await else {
        return;
    };
    let (admin, cookie) = common::admin_cookie(&state).await;
    common::with_user(state.clone(), admin, move |state, _| async move {
        let token = issue_token(&state, &cookie).await;

        // RFC 7591 §2: `scope` is a space-separated string, not an array.
        let (status, body) = register(
            &state,
            &token,
            json!({
                "redirect_uris": ["https://app.example/callback"],
                "client_name": "DCR App",
                "scope": "openid profile"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let client_id = body["client_id"].as_str().expect("client_id");
        let secret = body["client_secret"].as_str().expect("client_secret");
        assert!(
            client_id.starts_with("sgn_cl_"),
            "generated ids carry the Signet prefix: {client_id}"
        );
        assert!(
            secret.starts_with("sgn_cs_"),
            "generated secrets carry the Signet prefix"
        );

        let row = sqlx::query_as::<_, (Vec<String>, String, bool, Vec<String>)>(
            "SELECT scopes, client_name, ip_allowlist_enabled, grant_types \
             FROM client_apps WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_one(&state.pool)
        .await
        .expect("load registered client");
        assert_eq!(row.0, vec!["openid", "profile"], "scope string parsed");
        assert_eq!(
            row.1, "DCR App",
            "client_name persisted for the Name column"
        );
        assert!(!row.2, "no IP allowlist by default");
        assert_eq!(
            row.3,
            vec!["authorization_code", "refresh_token"],
            "fixed grant pair"
        );

        // Single use: a second registration on the same token is refused.
        let (status, _) = register(
            &state,
            &token,
            json!({"redirect_uris": ["https://other.example/cb"]}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        sqlx::query("DELETE FROM client_apps WHERE client_id = $1")
            .bind(client_id)
            .execute(&state.pool)
            .await
            .expect("remove registered client");
    })
    .await;
}
