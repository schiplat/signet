use crate::error::{AppError, AppResult};
use crate::models::User;
use crate::state::AppState;
use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::Json;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;

#[derive(Debug, Deserialize)]
struct AccessClaims {
    sub: String,
    token_use: Option<String>,
    scope: Option<String>,
}

pub async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::unauthorized("missing Authorization"))?;
    let token = auth
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::unauthorized("invalid Authorization"))?;

    let pem = fs::read_to_string(&state.config.jwt_private_key_path)
        .map_err(|e| AppError::Anyhow(e.into()))?;
    let decoding =
        DecodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| AppError::Anyhow(e.into()))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(std::slice::from_ref(&state.config.issuer));
    validation.validate_aud = false;

    let data = jsonwebtoken::decode::<AccessClaims>(token, &decoding, &validation)
        .map_err(|_| AppError::unauthorized("invalid access_token"))?;
    if data.claims.token_use.as_deref() != Some("access") {
        return Err(AppError::unauthorized("not an access token"));
    }

    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, sub, email, username, display_name, password_hash, status, role,
               mfa_required, must_change_password, totp_enabled, totp_secret, groups, phone,
               provisioned_via, created_at, updated_at
        FROM users WHERE sub = $1 AND status = 'active'
        "#,
    )
    .bind(&data.claims.sub)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("user not found"))?;

    let scope = data.claims.scope.as_deref().unwrap_or("openid");
    let mut out = serde_json::Map::new();
    out.insert("sub".into(), json!(user.sub));
    if crate::oidc::scope_contains(scope, "email") {
        out.insert("email".into(), json!(user.email));
    }
    if crate::oidc::scope_contains(scope, "profile") {
        out.insert("name".into(), json!(user.display_name));
        out.insert(
            "preferred_username".into(),
            json!(user.username.as_deref().unwrap_or(&user.email)),
        );
    }
    if crate::oidc::scope_contains(scope, "groups") {
        out.insert("groups".into(), json!(user.groups));
    }
    if crate::oidc::scope_contains(scope, "phone") {
        if let Some(p) = &user.phone {
            out.insert("phone_number".into(), json!(p));
            out.insert("phone_number_verified".into(), json!(false));
        }
    }

    Ok(Json(Value::Object(out)))
}
