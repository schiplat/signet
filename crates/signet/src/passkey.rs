use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::auth::session::{create_session, current_user, session_cookie};
use crate::crypto_util::{b64url_encode, random_token};
use crate::error::{AppError, AppResult};
use crate::models::{PublicUser, User, USER_COLS};
use crate::state::AppState;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use uuid::Uuid;
use webauthn_rs::prelude::*;

const CHALLENGE_TTL_SECS: u64 = 5 * 60;

/// Transient in-memory challenge state. Single-instance deployment; a restart
/// invalidates any in-flight ceremonies, which is safe (they are single-use).
pub(crate) enum ChallengeState {
    Register {
        state: PasskeyRegistration,
        user_id: Uuid,
    },
    Authenticate {
        state: PasskeyAuthentication,
        user_id: Uuid,
    },
}

pub(crate) struct ChallengeEntry {
    state: ChallengeState,
    expires: Instant,
}

pub(crate) type ChallengeStore = Arc<Mutex<HashMap<String, ChallengeEntry>>>;

pub(crate) fn new_store() -> ChallengeStore {
    Arc::new(Mutex::new(HashMap::new()))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/me/passkeys", get(list_passkeys))
        .route("/me/passkeys/start", post(register_start))
        .route("/me/passkeys/finish", post(register_finish))
        .route("/me/passkeys/{id}", delete(remove_passkey))
        .route("/passkeys/start", post(login_start))
        .route("/passkeys/finish", post(login_finish))
}

fn wa_err(e: webauthn_rs::prelude::WebauthnError) -> AppError {
    AppError::bad_request(format!("webauthn: {e}"))
}

fn take_challenge(store: &ChallengeStore, token: &str, kind: &str) -> AppResult<ChallengeState> {
    let mut map = store.lock().unwrap_or_else(|e| e.into_inner());
    // Opportunistic expiry sweep.
    let now = Instant::now();
    map.retain(|_, v| v.expires > now);

    let entry = map
        .remove(token)
        .ok_or_else(|| AppError::bad_request("webauthn challenge expired or invalid"))?;
    if entry.expires <= now {
        return Err(AppError::bad_request(
            "webauthn challenge expired or invalid",
        ));
    }
    let matches = match &entry.state {
        ChallengeState::Register { .. } => kind == "register",
        ChallengeState::Authenticate { .. } => kind == "authenticate",
    };
    if !matches {
        return Err(AppError::bad_request("webauthn challenge type mismatch"));
    }
    Ok(entry.state)
}

fn store_challenge(store: &ChallengeStore, token: String, state: ChallengeState) {
    let mut map = store.lock().unwrap_or_else(|e| e.into_inner());
    map.insert(
        token,
        ChallengeEntry {
            state,
            expires: Instant::now() + std::time::Duration::from_secs(CHALLENGE_TTL_SECS),
        },
    );
}

// --- passkey persistence ---

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct PasskeyRow {
    id: Uuid,
    name: String,
    credential_id: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

async fn load_passkeys(state: &AppState, user_id: Uuid) -> AppResult<Vec<Passkey>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT passkey_json FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    rows.into_iter()
        .map(|(json,)| {
            serde_json::from_str::<Passkey>(&json).map_err(|e| AppError::Anyhow(e.into()))
        })
        .collect()
}

async fn load_user(state: &AppState, id: Uuid) -> AppResult<User> {
    sqlx::query_as::<_, User>(&format!(
        "SELECT {USER_COLS} FROM users WHERE id = $1 AND status = 'active'"
    ))
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("user inactive"))
}

// --- list ---

async fn list_passkeys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<PasskeyRow>>> {
    let user = current_user(&state, &headers).await?;
    let rows = sqlx::query_as::<_, PasskeyRow>(
        r#"
        SELECT id, name, credential_id, created_at, last_used_at
        FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at DESC
        "#,
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

// --- register ---

async fn register_start(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    let existing = load_passkeys(&state, user.id).await?;
    let exclude: Vec<CredentialID> = existing.iter().map(|p| p.cred_id().clone()).collect();

    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(user.id, &user.email, &user.display_name, Some(exclude))
        .map_err(wa_err)?;

    let token = random_token(32);
    store_challenge(
        &state.passkey_challenges,
        token.clone(),
        ChallengeState::Register {
            state: reg_state,
            user_id: user.id,
        },
    );

    Ok(Json(json!({ "token": token, "challenge": ccr })))
}

#[derive(Debug, Deserialize)]
struct RegisterFinishBody {
    token: String,
    name: String,
    credential: Value,
}

async fn register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterFinishBody>,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;

    let ChallengeState::Register {
        state: reg_state,
        user_id,
    } = take_challenge(&state.passkey_challenges, &body.token, "register")?
    else {
        return Err(AppError::bad_request("webauthn challenge type mismatch"));
    };
    if user_id != user.id {
        return Err(AppError::bad_request("webauthn challenge mismatch"));
    }

    let cred: RegisterPublicKeyCredential = serde_json::from_value(body.credential)
        .map_err(|e| AppError::bad_request(format!("invalid credential: {e}")))?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&cred, &reg_state)
        .map_err(wa_err)?;

    let credential_id = b64url_encode(passkey.cred_id().as_ref());
    let name = body.name.trim().to_string();
    let passkey_json = serde_json::to_string(&passkey).map_err(|e| AppError::Anyhow(e.into()))?;
    let id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO webauthn_credentials (id, user_id, name, credential_id, passkey_json)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(id)
    .bind(user.id)
    .bind(if name.is_empty() {
        "Passkey".to_string()
    } else {
        name
    })
    .bind(&credential_id)
    .bind(passkey_json)
    .execute(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db)
            if db.constraint() == Some("webauthn_credentials_credential_id_key") =>
        {
            AppError::bad_request("this passkey is already registered")
        }
        other => AppError::from(other),
    })?;

    crate::audit::record(
        &state.pool,
        crate::audit::AuditEvent {
            actor: Some(user),
            action: "mfa.passkey_enroll",
            resource_type: "user",
            resource_id: Some(id.to_string()),
            detail: json!({ "credential_id": credential_id }),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "ok": true, "id": id })))
}

async fn remove_passkey(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    sqlx::query("DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user.id)
        .execute(&state.pool)
        .await?;

    crate::audit::record(
        &state.pool,
        crate::audit::AuditEvent {
            actor: Some(user),
            action: "mfa.passkey_remove",
            resource_type: "user",
            resource_id: Some(id.to_string()),
            detail: json!({}),
            ip: None,
            user_agent: crate::http_util::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "ok": true })))
}

// --- login ---

#[derive(Debug, Deserialize)]
struct LoginStartBody {
    email: String,
}

async fn login_start(
    State(state): State<AppState>,
    Json(body): Json<LoginStartBody>,
) -> AppResult<Json<Value>> {
    let email = body.email.trim().to_lowercase();
    let user: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM users WHERE (email = $1 OR username = $1) AND status = 'active'",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?;
    let Some((user_id,)) = user else {
        return Err(AppError::bad_request("no passkeys for this account"));
    };

    let passkeys = load_passkeys(&state, user_id).await?;
    if passkeys.is_empty() {
        return Err(AppError::bad_request("no passkeys for this account"));
    }

    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(wa_err)?;

    let token = random_token(32);
    store_challenge(
        &state.passkey_challenges,
        token.clone(),
        ChallengeState::Authenticate {
            state: auth_state,
            user_id,
        },
    );

    Ok(Json(json!({ "token": token, "challenge": rcr })))
}

#[derive(Debug, Deserialize)]
struct LoginFinishBody {
    token: String,
    credential: Value,
    /// Optional `/oauth/authorize?...` return URL carried through from the
    /// login page, used to attribute the login to the initiating OAuth app.
    #[serde(default)]
    return_to: Option<String>,
}

async fn login_finish(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<LoginFinishBody>,
) -> AppResult<impl IntoResponse> {
    let ip = crate::http_util::client_ip(&headers, Some(addr));
    let client_id =
        crate::audit::resolve_audit_client_id(&state.pool, body.return_to.as_deref()).await;

    let ChallengeState::Authenticate {
        state: auth_state,
        user_id,
    } = take_challenge(&state.passkey_challenges, &body.token, "authenticate")?
    else {
        return Err(AppError::bad_request("webauthn challenge type mismatch"));
    };

    let cred: PublicKeyCredential = serde_json::from_value(body.credential)
        .map_err(|e| AppError::bad_request(format!("invalid credential: {e}")))?;

    let auth_result = state
        .webauthn
        .finish_passkey_authentication(&cred, &auth_state)
        .map_err(wa_err)?;

    let cred_id_b64 = b64url_encode(auth_result.cred_id().as_ref());

    let mut matched = false;
    for mut pk in load_passkeys(&state, user_id).await? {
        if pk.update_credential(&auth_result).is_some() {
            let updated_json =
                serde_json::to_string(&pk).map_err(|e| AppError::Anyhow(e.into()))?;
            sqlx::query(
                "UPDATE webauthn_credentials SET passkey_json = $3, last_used_at = NOW() WHERE user_id = $1 AND credential_id = $2",
            )
            .bind(user_id)
            .bind(&cred_id_b64)
            .bind(updated_json)
            .execute(&state.pool)
            .await?;
            matched = true;
            break;
        }
    }

    if !matched {
        return Err(AppError::unauthorized("passkey not recognized"));
    }

    let user = load_user(&state, user_id).await?;
    if user.must_change_password {
        return crate::mfa::challenge_password_change(&state, jar, user).await;
    }
    let token = create_session(
        &state.pool,
        user.id,
        state.config.session_ttl_hours,
        ip.as_deref(),
        crate::http_util::user_agent(&headers).as_deref(),
    )
    .await?;
    let jar = jar.add(session_cookie(
        &token,
        state.config.cookie_secure,
        state.config.session_ttl_hours,
    ));
    let jar = crate::federation::consume_pending_link(&state, jar, &user).await;

    crate::login_alert::track_login(
        &state.pool,
        &user,
        ip.as_deref(),
        crate::http_util::user_agent(&headers).as_deref(),
    )
    .await;

    crate::audit::record(
        &state.pool,
        crate::audit::AuditEvent {
            actor: Some(user.clone()),
            action: "auth.login",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "mfa": "passkey" }),
            ip,
            user_agent: crate::http_util::user_agent(&headers),
            client_id,
        },
    )
    .await;
    crate::metrics::inc_logins();

    Ok((
        jar,
        Json(json!({
            "status": "ok",
            "user": PublicUser::from(user),
        })),
    ))
}
