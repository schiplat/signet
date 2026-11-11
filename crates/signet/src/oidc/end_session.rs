use crate::auth::session::{
    clear_session_cookie, cookie_value, destroy_session, user_from_session_token, SESSION_COOKIE,
};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::{Form, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use jsonwebtoken::{Algorithm, Validation};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Default, Deserialize)]
pub struct EndSessionParams {
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
}

/// `GET /oauth/end_session` — accepted only with a valid `id_token_hint`.
///
/// A top-level GET navigation carries the `SameSite=Lax` session cookie, so an
/// attacker's link could otherwise sign the victim out at will. A signed
/// id_token is something only a real client holds, and its `sub` lets this
/// endpoint refuse when it names a different account than the live session —
/// which is exactly the CSRF check a GET needs. Clients that cannot supply one
/// use POST (below), which the cookie policy already protects.
pub async fn end_session_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Query(q): Query<EndSessionParams>,
) -> AppResult<Response> {
    if q.id_token_hint.is_none() {
        return Err(AppError::bad_request(
            "id_token_hint is required on GET /oauth/end_session; POST does not require it",
        ));
    }
    finish(state, headers, jar, q).await
}

/// `POST /oauth/end_session` — the cross-site-safe form.
///
/// A cross-site form POST does not carry the Lax cookie, so an attacker's page
/// cannot log the victim out. A hint, when present, is still verified: it is
/// what authorizes the `post_logout_redirect_uri` branch.
pub async fn end_session_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(q): Form<EndSessionParams>,
) -> AppResult<Response> {
    finish(state, headers, jar, q).await
}

async fn finish(
    state: AppState,
    headers: HeaderMap,
    jar: CookieJar,
    q: EndSessionParams,
) -> AppResult<Response> {
    // The session the request is about to end, if any. Resolved before the
    // hint check: a hint naming another account must not end this one.
    let session_user = match cookie_value(&headers, SESSION_COOKIE) {
        Some(token) => user_from_session_token(&state.pool, &token).await?,
        None => None,
    };

    let hinted_client = match q.id_token_hint.as_deref() {
        None => None,
        Some(hint) => {
            let claims = verify_hint(&state, hint)?;
            if let Some(session_user) = &session_user {
                if claims.sub != session_user.sub {
                    return Err(AppError::forbidden(
                        "id_token_hint belongs to a different account",
                    ));
                }
            }
            claims.aud
        }
    };

    // `client_id` is optional in the spec; when omitted, the hint's audience is
    // the client. When both are present they must agree, or the allow-list
    // lookup below would consult a client the token was not issued to.
    if let (Some(explicit), Some(from_hint)) = (q.client_id.as_deref(), hinted_client.as_deref()) {
        if explicit != from_hint {
            return Err(AppError::bad_request(
                "client_id does not match the id_token_hint audience",
            ));
        }
    }
    let client_id = q.client_id.as_deref().or(hinted_client.as_deref());

    let jar = if let Some(token) = cookie_value(&headers, SESSION_COOKIE) {
        destroy_session(&state.pool, &token).await?;
        jar.add(clear_session_cookie(state.config.cookie_secure))
    } else {
        jar
    };

    // Redirect back to the client only if the URI is allow-listed for that
    // client, and only for a client we can name.
    if let (Some(client_id), Some(uri)) = (client_id, &q.post_logout_redirect_uri) {
        let allowed: Option<Vec<String>> = sqlx::query_scalar(
            "SELECT post_logout_redirect_uris FROM client_apps WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&state.pool)
        .await?;
        if let Some(list) = allowed {
            if list.iter().any(|u| u == uri) {
                let mut url =
                    url::Url::parse(uri).map_err(|_| AppError::bad_request("bad redirect uri"))?;
                if let Some(s) = &q.state {
                    url.query_pairs_mut().append_pair("state", s);
                }
                return Ok((jar, Redirect::temporary(url.as_str())).into_response());
            }
        }
    }

    Ok((jar, Redirect::temporary("/")).into_response())
}

struct HintClaims {
    sub: String,
    aud: Option<String>,
}

/// Verifies a logout hint as a token this issuer signed, not yet expired.
///
/// `aud` is read by hand rather than through `Validation::set_audience`: the
/// caller may not know the client yet (that is what the hint tells it), and a
/// single-audience string is what this issuer emits.
fn verify_hint(state: &AppState, hint: &str) -> AppResult<HintClaims> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(std::slice::from_ref(&state.config.issuer));
    validation.validate_aud = false;
    let data = jsonwebtoken::decode::<Value>(hint, state.keys.decoding(), &validation)
        .map_err(|_| AppError::bad_request("invalid id_token_hint"))?;
    let sub = data
        .claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::bad_request("id_token_hint has no sub"))?
        .to_string();
    let aud = match data.claims.get("aud") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Array(items)) => items.first().and_then(Value::as_str).map(str::to_string),
        _ => None,
    };
    Ok(HintClaims { sub, aud })
}
