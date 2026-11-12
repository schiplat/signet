use crate::audit::{record, AuditEvent};
use crate::crypto::util::{random_token, sha256_b64url, sha256_hex};
use crate::error::{AppError, AppResult};
use crate::http::extract::client_ip;
use crate::http::source_ip::check_client_source_ip;
use crate::models::{active_user_by_id, ClientApp, User};
use crate::state::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Form;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    /// client_credentials: requested scope, clamped to the client's list.
    pub scope: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    /// Binds this id_token to the access token issued beside it (OIDC Core
    /// 3.1.3.6); a client that checks it detects a response whose halves were
    /// mixed by an attacker.
    at_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    /// OIDC Core §5.4: separate standard claim, not nested in `email`.
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    /// When the user authenticated (the session's creation), carried from the
    /// auth code for RPs implementing max_age/step-up on their side.
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone_number: Option<String>,
}

#[derive(Debug, Serialize)]
struct AccessTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    scope: String,
    token_use: String,
    /// When the mint carried a user (authorization_code/refresh); absent on
    /// client-credentials tokens, whose `sub` is the client itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    #[serde(flatten)]
    extra: Option<serde_json::Map<String, serde_json::Value>>,
}

pub async fn token(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> AppResult<impl IntoResponse> {
    let (client_id, client_secret) = resolve_client_credentials(&headers, &form)?;
    let client = load_client(&state, &client_id).await?;
    if !crate::auth::client_secret::verify(
        &state,
        &client.client_id,
        &client_secret,
        &client.client_secret_hash,
    )
    .await?
    {
        return Err(AppError::oauth_unauthorized(
            "invalid_client",
            "invalid client credentials",
        ));
    }
    let source = client_ip(&headers, Some(addr));
    check_client_source_ip(
        client.ip_allowlist_enabled,
        &client.allowed_cidrs,
        source.as_deref(),
    )?;

    // The registered grant list is the client's own declaration of what it may
    // do; honouring it is what stops an admin's "disable refresh for this
    // client" from being a no-op. Checked before dispatch so both grants get
    // the same answer.
    if !client.grant_types.iter().any(|g| g == &form.grant_type) {
        return Err(AppError::oauth(
            "unsupported_grant_type",
            format!("client is not registered for the {} grant", form.grant_type),
        ));
    }

    let body = match form.grant_type.as_str() {
        "authorization_code" => issue_from_code(&state, &client, &form).await?,
        "refresh_token" => {
            issue_from_refresh(
                &state,
                &client,
                &form,
                source,
                crate::http::extract::user_agent(&headers),
            )
            .await?
        }
        "client_credentials" => issue_client_credentials(&state, &client, &form).await?,
        _ => {
            return Err(AppError::oauth(
                "unsupported_grant_type",
                "unsupported grant_type",
            ))
        }
    };
    Ok((StatusCode::OK, axum::Json(body)))
}

fn resolve_client_credentials(
    headers: &HeaderMap,
    form: &TokenForm,
) -> AppResult<(String, String)> {
    resolve_client_credentials_parts(
        headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    )
}

pub(crate) fn resolve_client_credentials_parts(
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> AppResult<(String, String)> {
    if let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) {
        let raw = auth.to_str().unwrap_or_default();
        if let Some(b64) = raw.strip_prefix("Basic ") {
            use base64::Engine;
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) {
                if let Ok(s) = String::from_utf8(decoded) {
                    if let Some((id, secret)) = s.split_once(':') {
                        return Ok((id.to_string(), secret.to_string()));
                    }
                }
            }
        }
    }

    let id = form_client_id
        .ok_or_else(|| AppError::oauth_unauthorized("invalid_client", "missing client_id"))?;
    let secret = form_client_secret
        .ok_or_else(|| AppError::oauth_unauthorized("invalid_client", "missing client_secret"))?;
    Ok((id.to_string(), secret.to_string()))
}

pub(crate) async fn load_client(state: &AppState, client_id: &str) -> AppResult<ClientApp> {
    sqlx::query_as::<_, ClientApp>(
        r#"
        SELECT id, client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
               grant_types, extra_claims, backchannel_logout_uri, pkce_required, scopes, enabled,
               ip_allowlist_enabled, allowed_cidrs
        FROM client_apps
        WHERE client_id = $1 AND enabled = TRUE
        "#,
    )
    .bind(client_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::oauth_unauthorized("invalid_client", "unknown client"))
}

async fn issue_from_code(
    state: &AppState,
    client: &ClientApp,
    form: &TokenForm,
) -> AppResult<serde_json::Value> {
    let code = form
        .code
        .as_deref()
        .ok_or_else(|| AppError::oauth("invalid_request", "missing code"))?;
    let redirect_uri = form
        .redirect_uri
        .as_deref()
        .ok_or_else(|| AppError::oauth("invalid_request", "missing redirect_uri"))?;
    let code_verifier = form
        .code_verifier
        .as_deref()
        .ok_or_else(|| AppError::oauth("invalid_request", "missing code_verifier"))?;
    // RFC 7636 §4.1: the verifier has the same 43–128 unreserved-character
    // bound as the challenge. The exchange still hashes what arrived, so this
    // is a protocol check, not a security boundary.
    crate::oidc::validate_pkce_param("code_verifier", code_verifier)
        .map_err(|e| AppError::oauth("invalid_request", e.to_string()))?;

    let code_hash = sha256_hex(code);
    let row = sqlx::query_as::<_, AuthCodeRow>(
        r#"
        SELECT id, client_id, user_id, redirect_uri, scope, code_challenge, nonce, expires_at, consumed_at, auth_time
        FROM auth_codes
        WHERE code_hash = $1
        "#,
    )
    .bind(code_hash)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::oauth("invalid_grant", "invalid code"))?;

    if row.consumed_at.is_some() {
        return Err(AppError::oauth("invalid_grant", "code already used"));
    }
    if row.expires_at < Utc::now() {
        return Err(AppError::oauth("invalid_grant", "code expired"));
    }
    if row.client_id != client.client_id {
        return Err(AppError::oauth("invalid_grant", "client mismatch"));
    }
    if row.redirect_uri != redirect_uri {
        return Err(AppError::oauth("invalid_grant", "redirect_uri mismatch"));
    }

    let expected = sha256_b64url(code_verifier);
    if expected != row.code_challenge {
        return Err(AppError::oauth("invalid_grant", "invalid code_verifier"));
    }

    // Consume atomically. The SELECT above cannot tell two concurrent
    // exchanges apart, so this conditional UPDATE is the one-time-use claim:
    // whoever's UPDATE finds the row already consumed loses, and RFC 6749
    // §4.1.2 makes single use the mitigation for code interception — a lost
    // race must not mint a second token set.
    let consumed = sqlx::query(
        "UPDATE auth_codes SET consumed_at = NOW() WHERE id = $1 AND consumed_at IS NULL",
    )
    .bind(row.id)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if consumed == 0 {
        return Err(AppError::oauth("invalid_grant", "code already used"));
    }

    let user = active_user_for_grant(state, row.user_id).await?;
    // A code exchange starts a fresh family; rotation keeps the parent's.
    build_token_response(
        state,
        client,
        &user,
        &row.scope,
        row.nonce,
        None,
        row.auth_time.map(|t| t.timestamp()),
    )
    .await
}

/// The client-credentials grant (RFC 6749 §4.4): machine-to-machine tokens
/// where the client *is* the principal.
///
/// `sub` is the `client_id` — there is no user behind the token, so user
/// claims (`email`, `groups`, ...) are absent by construction and per-client
/// `$field` extras resolve to nothing (only literals survive). No refresh
/// token: a service re-authenticates with its secret, which is what the grant
/// is for. Scope is the client's own registered list, requested via the form
/// and clamped to it.
async fn issue_client_credentials(
    state: &AppState,
    client: &ClientApp,
    form: &TokenForm,
) -> AppResult<serde_json::Value> {
    let scope = crate::oidc::normalize_scope(form.scope.as_deref().unwrap_or(""));
    if let Some(requested) = form.scope.as_deref() {
        for s in requested.split_whitespace() {
            if !client.scopes.iter().any(|a| a == s) {
                return Err(AppError::oauth(
                    "invalid_scope",
                    format!("scope not allowed for this client: {s}"),
                ));
            }
        }
    }
    let scope = if scope.is_empty() {
        client.scopes.join(" ")
    } else {
        scope
    };

    let now = Utc::now();
    let access_exp = now + Duration::seconds(state.rt().access_token_ttl_secs);
    let mut claims = serde_json::json!({
        "iss": state.config.issuer,
        "sub": client.client_id,
        "aud": client.client_id,
        "exp": access_exp.timestamp(),
        "iat": now.timestamp(),
        "scope": scope,
        "token_use": "access",
    });
    let obj = claims.as_object_mut().expect("claims are an object");
    // No user: only literal extras can resolve here.
    crate::models::merge_extra_claims(obj, client.extra_claims.as_ref(), None)?;
    let access_token = state.keys.load().encode(&claims)?;

    crate::metrics::inc_tokens_issued();

    Ok(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": state.rt().access_token_ttl_secs,
        "scope": scope,
    }))
}

/// `active_user_by_id` for the token endpoint's error vocabulary.
///
/// A missing or disabled account is a failed grant (`invalid_grant`), not an
/// authentication problem: the client authenticated fine, and RFC 6749 §5.2
/// has a code for "the grant is no longer usable". Other errors (database)
/// keep their normal mapping.
async fn active_user_for_grant(state: &AppState, user_id: Uuid) -> AppResult<User> {
    match active_user_by_id(&state.pool, user_id).await {
        Ok(user) => Ok(user),
        Err(AppError::Unauthorized(_)) | Err(AppError::NotFound(_)) => Err(AppError::oauth(
            "invalid_grant",
            "the account for this grant is not active",
        )),
        Err(e) => Err(e),
    }
}

/// Revokes every still-live refresh token in `family`. Returns how many died.
pub async fn revoke_refresh_family(pool: &sqlx::PgPool, family: Uuid) -> AppResult<u64> {
    let res = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = NOW() \
         WHERE COALESCE(family_id, id) = $1 AND revoked_at IS NULL",
    )
    .bind(family)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Revokes every still-live refresh token issued to `user_id`, across clients.
///
/// The credential-event sibling of [`revoke_refresh_family`]: a password
/// change or reset must retire the delegated credentials too, or a client —
/// or whoever extracted its refresh token — keeps minting access tokens
/// straight through the account's recovery. Callers are the password events
/// (self change, admin reset, emailed reset, forced change); plain session
/// events do not belong here.
pub async fn revoke_refresh_tokens_for_user(pool: &sqlx::PgPool, user_id: Uuid) -> AppResult<u64> {
    let res = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = NOW() \
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

async fn issue_from_refresh(
    state: &AppState,
    client: &ClientApp,
    form: &TokenForm,
    ip: Option<String>,
    user_agent: Option<String>,
) -> AppResult<serde_json::Value> {
    let refresh = form
        .refresh_token
        .as_deref()
        .ok_or_else(|| AppError::oauth("invalid_request", "missing refresh_token"))?;
    let token_hash = sha256_hex(refresh);

    let row = sqlx::query_as::<_, RefreshRow>(
        r#"
        SELECT id, client_id, user_id, scope, expires_at, revoked_at, family_id
        FROM refresh_tokens
        WHERE token_hash = $1
        "#,
    )
    .bind(token_hash)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::oauth("invalid_grant", "invalid refresh_token"))?;

    if row.revoked_at.is_some() {
        // A refresh token is single-use: it was revoked by its own rotation.
        // Presenting it again therefore means either the client or the holder
        // of a stolen copy just replayed it — the standard response (OAuth 2.0
        // BCP) is to kill the whole family, so the thief's newer token dies
        // with the legitimate client's. A client that merely lost its refresh
        // response re-authenticates; a leak would have forced that anyway.
        return Err(revoke_family_on_reuse(state, client, &row, ip, user_agent, "replayed").await);
    }
    if row.expires_at < Utc::now() {
        return Err(AppError::oauth(
            "invalid_grant",
            "refresh_token expired or revoked",
        ));
    }
    if row.client_id != client.client_id {
        return Err(AppError::oauth("invalid_grant", "client mismatch"));
    }

    // rotate — atomically. The SELECT above cannot tell two concurrent
    // refreshes apart, so the conditional revocation is the rotation claim:
    // a request whose UPDATE finds the row already revoked lost the race and
    // goes through the same family-kill as a replay, which is exactly the
    // BCP's answer to two holders of one token.
    let rotated = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(row.id)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if rotated == 0 {
        return Err(
            revoke_family_on_reuse(state, client, &row, ip, user_agent, "concurrent").await,
        );
    }

    let user = active_user_for_grant(state, row.user_id).await?;
    build_token_response(state, client, &user, &row.scope, None, row.family_id, None).await
}

/// The shared response to presenting — or losing the atomic rotation race on —
/// an already-revoked refresh token: kill the whole family, so whichever
/// request is not the legitimate client's walks away with nothing live, and
/// leave the audit trail an operator needs to tell the two apart.
async fn revoke_family_on_reuse(
    state: &AppState,
    client: &ClientApp,
    row: &RefreshRow,
    ip: Option<String>,
    user_agent: Option<String>,
    reason: &'static str,
) -> AppError {
    let family = row.family_id.unwrap_or(row.id);
    let revoked = match revoke_refresh_family(&state.pool, family).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(error = %e, %family, "failed to revoke refresh token family");
            0
        }
    };
    tracing::warn!(client_id = %client.client_id, revoked, reason, "refresh token reuse detected; family revoked");
    record(
        state,
        AuditEvent {
            actor: None,
            action: "oauth.refresh_reuse",
            resource_type: "user",
            resource_id: Some(row.user_id.to_string()),
            detail: json!({
                "client_id": client.client_id,
                "revoked": revoked,
                "reason": reason,
            }),
            ip,
            user_agent,
            client_id: Some(client.client_id.clone()),
        },
    )
    .await;
    AppError::oauth("invalid_grant", "refresh_token expired or revoked")
}

#[allow(clippy::too_many_arguments)]
async fn build_token_response(
    state: &AppState,
    client: &ClientApp,
    user: &User,
    scope: &str,
    nonce: Option<String>,
    family: Option<Uuid>,
    auth_time: Option<i64>,
) -> AppResult<serde_json::Value> {
    let now = Utc::now();
    let access_exp = now + Duration::seconds(state.rt().access_token_ttl_secs);
    let id_exp = now + Duration::seconds(state.rt().id_token_ttl_secs);

    let mut access_claims = serde_json::to_value(AccessTokenClaims {
        iss: state.config.issuer.clone(),
        sub: user.sub.clone(),
        aud: client.client_id.clone(),
        exp: access_exp.timestamp(),
        iat: now.timestamp(),
        scope: scope.to_string(),
        token_use: "access".into(),
        email_verified: Some(user.email_verified),
        extra: None,
    })
    .expect("access claims serialize")
    .as_object_mut()
    .expect("access claims are an object")
    .clone();
    // Per-client claims go on both halves of the response: the id_token is
    // what an RP's session sees, the access token is what its API calls see.
    crate::models::merge_extra_claims(
        &mut access_claims,
        client.extra_claims.as_ref(),
        Some(user),
    )?;
    let access_token = state.keys.load().encode(&access_claims)?;

    let mut id_claims = serde_json::to_value(IdTokenClaims {
        iss: state.config.issuer.clone(),
        sub: user.sub.clone(),
        aud: client.client_id.clone(),
        exp: id_exp.timestamp(),
        iat: now.timestamp(),
        at_hash: crate::crypto::util::at_hash(&access_token),
        nonce,
        email: crate::oidc::scope_contains(scope, "email").then(|| user.email.clone()),
        email_verified: crate::oidc::scope_contains(scope, "email").then_some(user.email_verified),
        auth_time: None,
        name: crate::oidc::scope_contains(scope, "profile").then(|| user.display_name.clone()),
        preferred_username: crate::oidc::scope_contains(scope, "profile")
            .then(|| user.username.clone().unwrap_or_else(|| user.email.clone())),
        groups: crate::oidc::scope_contains(scope, "groups")
            .then(|| crate::models::effective_groups(&user.groups, &user.directory_groups)),
        phone_number: crate::oidc::scope_contains(scope, "phone")
            .then(|| user.phone.clone())
            .flatten(),
    })
    .expect("id claims serialize")
    .as_object_mut()
    .expect("id claims are an object")
    .clone();
    if crate::oidc::scope_contains(scope, "email") {
        id_claims.insert("email_verified".into(), json!(user.email_verified));
    }
    crate::models::merge_extra_claims(&mut id_claims, client.extra_claims.as_ref(), Some(user))?;
    if let Some(at) = auth_time {
        id_claims.insert("auth_time".into(), json!(at));
    }
    let id_token = state.keys.load().encode(&id_claims)?;

    let refresh = random_token(32);
    let refresh_hash = sha256_hex(&refresh);
    let refresh_exp = now + Duration::days(state.rt().refresh_token_ttl_days);
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (id, token_hash, client_id, user_id, scope, family_id, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(refresh_hash)
    .bind(&client.client_id)
    .bind(user.id)
    .bind(scope)
    .bind(family.unwrap_or_else(Uuid::new_v4))
    .bind(refresh_exp)
    .execute(&state.pool)
    .await?;

    crate::metrics::inc_tokens_issued();

    Ok(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": state.rt().access_token_ttl_secs,
        "refresh_token": refresh,
        "id_token": id_token,
        "scope": scope,
    }))
}

#[derive(Debug, sqlx::FromRow)]
struct AuthCodeRow {
    id: Uuid,
    client_id: String,
    user_id: Uuid,
    redirect_uri: String,
    scope: String,
    code_challenge: String,
    nonce: Option<String>,
    expires_at: chrono::DateTime<Utc>,
    consumed_at: Option<chrono::DateTime<Utc>>,
    auth_time: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, sqlx::FromRow)]
struct RefreshRow {
    id: Uuid,
    client_id: String,
    user_id: Uuid,
    scope: String,
    expires_at: chrono::DateTime<Utc>,
    revoked_at: Option<chrono::DateTime<Utc>>,
    family_id: Option<Uuid>,
}
