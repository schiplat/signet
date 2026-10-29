use crate::auth::current_user;
use crate::error::{AppError, AppResult};
use crate::models::ClientApp;
use crate::state::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct ConsentBody {
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    /// Additional scopes (from the client's allow-list) the user opted into via
    /// checkboxes. Requested scopes are always granted in full on `allow`.
    optional_scopes: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: String,
    code_challenge_method: Option<String>,
    allow: bool,
}

pub async fn consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ConsentBody>,
) -> AppResult<Response> {
    let user = current_user(&state, &headers).await?;

    let client = sqlx::query_as::<_, ClientApp>(
        r#"
        SELECT id, client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
               grant_types, pkce_required, scopes, enabled,
               ip_allowlist_enabled, allowed_cidrs
        FROM client_apps
        WHERE client_id = $1
        "#,
    )
    .bind(&body.client_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::bad_request("unknown client_id"))?;

    if !client.enabled {
        return Err(AppError::bad_request("client disabled"));
    }
    // Same carve-out as authorize: the issuer's own test-callback URI is a
    // permitted redirect for every client, or a first-time test drive would
    // die here after authorize accepted it.
    let test_redirect =
        crate::oidc::test_callback::test_callback_url(state.config.public_base(), &body.client_id);
    if !client.redirect_uris.iter().any(|u| u == &body.redirect_uri)
        && body.redirect_uri != test_redirect
    {
        return Err(AppError::bad_request("redirect_uri not allowed"));
    }

    let scope = crate::oidc::normalize_scope(body.scope.as_deref().unwrap_or("openid"));
    crate::oidc::validate_client_scope(&scope, &client.scopes)?;

    if !body.allow {
        let mut url = url::Url::parse(&body.redirect_uri)
            .map_err(|_| AppError::bad_request("bad redirect_uri"))?;
        url.query_pairs_mut().append_pair("error", "access_denied");
        if let Some(s) = &body.state {
            url.query_pairs_mut().append_pair("state", s);
        }
        // Returned as JSON like the allow branch: the consent page uses fetch,
        // which cannot read a 303's Location header. `body.redirect_uri` was
        // already validated against the client allow-list above.
        return Ok(Json(serde_json::json!({ "redirect": url.as_str() })).into_response());
    }

    // Requested scopes are mandatory: on `allow` they are granted in full.
    // `optional_scopes` are extra scopes the user opted into from the client's
    // allow-list. The stored grant is the union of the two.
    let mut granted: Vec<&str> = scope.split_whitespace().collect();
    if let Some(opt) = body.optional_scopes.as_deref() {
        for s in opt.split_whitespace() {
            if !client.scopes.iter().any(|a| a == s) {
                return Err(AppError::bad_request(format!(
                    "optional scope not allowed for this client: {s}"
                )));
            }
            granted.push(s);
        }
    }
    granted.sort_unstable();
    granted.dedup();
    let granted = granted.join(" ");

    sqlx::query(
        r#"
        INSERT INTO oauth_consents (id, user_id, client_id, scopes)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_id, client_id)
        DO UPDATE SET scopes = EXCLUDED.scopes, granted_at = NOW()
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(user.id)
    .bind(&body.client_id)
    .bind(&granted)
    .execute(&state.pool)
    .await?;

    // Return to authorize with the REQUESTED scope only — optional grants are
    // persisted for future requests but do not widen this token exchange.
    // The redirect target is returned as JSON (not a 303): the dashboard consent
    // page uses fetch, which cannot read a redirect's Location header.
    let return_to = format!("/oauth/authorize?{}", consent_return_query(&body, &scope));
    Ok(Json(serde_json::json!({ "redirect": return_to })).into_response())
}

fn consent_return_query(b: &ConsentBody, scope: &str) -> String {
    let mut parts = vec![
        "response_type=code".to_string(),
        format!("client_id={}", urlencoding::encode(&b.client_id)),
        format!("redirect_uri={}", urlencoding::encode(&b.redirect_uri)),
        format!("code_challenge={}", urlencoding::encode(&b.code_challenge)),
        format!("scope={}", urlencoding::encode(scope)),
    ];
    if let Some(v) = &b.state {
        parts.push(format!("state={}", urlencoding::encode(v)));
    }
    if let Some(v) = &b.nonce {
        parts.push(format!("nonce={}", urlencoding::encode(v)));
    }
    if let Some(v) = &b.code_challenge_method {
        parts.push(format!("code_challenge_method={}", urlencoding::encode(v)));
    }
    parts.join("&")
}
