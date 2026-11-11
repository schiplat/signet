use crate::audit::{record, AuditEvent};
use crate::auth::password::{set_user_password, verify_password_offloaded};
use crate::auth::session::{
    clear_session_cookie, cookie_value, current_user, current_user_unrestricted, destroy_session,
    list_sessions, revoke_all_sessions, revoke_other_sessions, revoke_session_by_id,
    session_id_for_token, SESSION_COOKIE,
};
use crate::directory;
use crate::error::{AppError, AppResult};
use crate::http::extract::{client_ip, AuditIp};
use crate::mfa::{begin_login_mfa_flow, force_password_change};
use crate::models::{PublicUser, User, USER_COLS};
use crate::state::AppState;
use axum::extract::{ConnectInfo, Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{FromRow, Row};
use std::net::SocketAddr;
use uuid::Uuid;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/login/password-change", post(force_password_change))
        .route("/logout", post(logout))
        .route("/me", get(me).patch(update_me))
        .route("/me/password", post(change_password))
        .route(
            "/me/sessions",
            get(list_my_sessions).post(revoke_my_other_sessions),
        )
        .route("/me/sessions/{id}", delete(revoke_my_session))
        .route("/me/consents", get(list_my_consents))
        .route("/me/consents/{client_id}", delete(revoke_my_consent))
        .route("/me/activity", get(my_activity))
}

#[derive(Debug, Deserialize)]
struct LoginBody {
    email: String,
    password: String,
    /// Optional `/oauth/authorize?...` return URL; used to attribute the
    /// login (and its audit trail) to the initiating OAuth app.
    #[serde(default)]
    return_to: Option<String>,
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<LoginBody>,
) -> AppResult<impl IntoResponse> {
    let email = body.email.trim().to_lowercase();
    let client_id =
        crate::audit::resolve_audit_client_id(&state.pool, body.return_to.as_deref()).await;
    // The lockout stamp rides along on the same row. It used to be a second
    // query for the same row, which is one extra round trip on every login — the
    // busiest write path there is. The failure counter itself is only meaningful
    // as an atomic increment (below), so it is not read here at all.
    let row = sqlx::query(&format!(
        "SELECT {USER_COLS}, locked_until \
         FROM users WHERE email = $1 OR username = $1"
    ))
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("invalid email/username or password"))?;
    let user = User::from_row(&row)?;
    let locked_until: Option<DateTime<Utc>> = row.try_get("locked_until")?;

    if user.status != "active" {
        return Err(AppError::unauthorized("account disabled"));
    }

    let ip = client_ip(&headers, Some(addr));

    if let Some(locked_until) = locked_until {
        if locked_until > Utc::now() {
            let secs = (locked_until - Utc::now()).num_seconds().max(1);
            let mins = (secs as f64 / 60.0).ceil() as i64;
            return Err(AppError::unauthorized(format!(
                "account locked, try again in ~{mins} minute(s)"
            )));
        }
    }

    // ── Credential check: local (argon2) or bind-through (LDAP) ─────────
    //
    // Federated (SSO JIT) and directory-provisioned users carry an empty
    // `password_hash` and so have no local password — they must sign in through
    // their upstream provider. Handing "" to the hash parser would surface a 500
    // instead of a 401, so the local branch checks for it explicitly.
    let credential = match directory::auth::resolve(&state, user.id).await? {
        directory::auth::LoginPath::Local => {
            let ok = !user.password_hash.is_empty()
                && verify_password_offloaded(&body.password, &user.password_hash).await?;
            if ok {
                directory::auth::Credential::Valid
            } else {
                directory::auth::Credential::Invalid {
                    counts_toward_lockout: true,
                }
            }
        }
        directory::auth::LoginPath::Ldap(target) => {
            directory::auth::verify(&target, &body.password).await
        }
    };

    let counts_toward_lockout = match credential {
        directory::auth::Credential::Valid => None,
        directory::auth::Credential::Invalid {
            counts_toward_lockout,
        } => Some(counts_toward_lockout),
        directory::auth::Credential::Unavailable {
            source_code,
            detail,
        } => {
            // D6: fail closed. The password is neither accepted nor rejected —
            // nobody could check it — so this must not look like a credential
            // failure, and there is no local fallback to slide into.
            crate::metrics::inc_directory_unavailable();
            audit_directory_login_failure(
                &state,
                &user,
                ip.clone(),
                crate::http::extract::user_agent(&headers),
                client_id.clone(),
                &source_code,
                &detail,
            )
            .await;
            return Err(AppError::unavailable("directory unavailable"));
        }
    };

    if let Some(counts_toward_lockout) = counts_toward_lockout {
        if counts_toward_lockout {
            crate::metrics::inc_login_failures();
        } else {
            // A directory rejection is counted on its own series, so "our
            // verifier rejected this" and "the directory rejected this" can be
            // told apart on a dashboard (§8.4).
            crate::metrics::inc_directory_login_failures();
        }
        record_login_failure(
            &state,
            &user,
            ip.clone(),
            crate::http::extract::user_agent(&headers),
            client_id.clone(),
        )
        .await?;

        if !counts_toward_lockout {
            // §8.4: the rejection is recorded (above) but not charged against the
            // local counter, because the directory's own lockout policy owns it.
            return Err(AppError::unauthorized("invalid email or password"));
        }

        // One atomic increment decides both the counter and the lockout. The
        // read-modify-write it replaced computed `read + 1` per request, so N
        // concurrent guesses all wrote the same small number and the counter
        // never reached the threshold however many guesses landed.
        let attempts: i32 = sqlx::query_scalar(
            "UPDATE users SET failed_login_attempts = failed_login_attempts + 1, \
             updated_at = NOW() WHERE id = $1 RETURNING failed_login_attempts",
        )
        .bind(user.id)
        .fetch_one(&state.pool)
        .await?;
        if attempts as i64 >= state.rt().max_login_attempts {
            let until = Utc::now() + Duration::minutes(state.rt().lockout_minutes);
            sqlx::query(
                "UPDATE users SET failed_login_attempts = 0, locked_until = $2, updated_at = NOW() WHERE id = $1",
            )
            .bind(user.id)
            .bind(until)
            .execute(&state.pool)
            .await?;
            return Err(AppError::unauthorized(
                "too many failed attempts, account locked",
            ));
        }
        return Err(AppError::unauthorized("invalid email or password"));
    }

    sqlx::query("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1")
        .bind(user.id)
        .execute(&state.pool)
        .await?;

    begin_login_mfa_flow(
        &state,
        jar,
        user,
        ip,
        crate::http::extract::user_agent(&headers),
        client_id,
        crate::admission::via::PASSWORD,
    )
    .await
}

async fn record_login_failure(
    state: &AppState,
    user: &User,
    ip: Option<String>,
    user_agent: Option<String>,
    client_id: Option<String>,
) -> AppResult<()> {
    record(
        state,
        AuditEvent {
            actor: Some(user.clone()),
            action: "auth.login_failed",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({}),
            ip,
            user_agent,
            client_id,
        },
    )
    .await;
    Ok(())
}

/// Records that a login could not be attempted because the owning directory was
/// unreachable (§8.3).
///
/// Separate from `auth.login_failed` on purpose: a rejected password and an
/// outage have completely different responses, and an operator debugging "nobody
/// can log in" must be able to tell them apart with one query. The credential is
/// never included — the event exists to show the outage, not the attempt.
#[allow(clippy::too_many_arguments)]
async fn audit_directory_login_failure(
    state: &AppState,
    user: &User,
    ip: Option<String>,
    user_agent: Option<String>,
    client_id: Option<String>,
    source_code: &str,
    detail: &str,
) {
    record(
        state,
        AuditEvent {
            actor: Some(user.clone()),
            action: "auth.directory_unavailable",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "source": source_code, "error": detail }),
            ip,
            user_agent,
            client_id,
        },
    )
    .await;
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> AppResult<impl IntoResponse> {
    if let Some(token) = cookie_value(&headers, SESSION_COOKIE) {
        destroy_session(&state.pool, &token).await?;
    }
    let jar = jar.add(clear_session_cookie(state.config.cookie_secure));
    Ok((jar, Json(json!({ "ok": true }))))
}

async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    // Unrestricted on purpose: this is the identity read the UI needs to
    // render the forced-password-change state and route the user to the one
    // endpoint (the change below) that can clear it.
    let user = current_user_unrestricted(&state, &headers).await?;
    Ok(Json(json!({ "user": PublicUser::from(user) })))
}

async fn list_my_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    let sessions = list_sessions(&state.pool, user.id).await?;
    let current_id = match cookie_value(&headers, SESSION_COOKIE) {
        Some(t) => session_id_for_token(&state.pool, &t).await?,
        None => None,
    };
    Ok(Json(json!({
        "sessions": sessions,
        "current_session_id": current_id,
    })))
}

async fn revoke_my_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    let current_id = match cookie_value(&headers, SESSION_COOKIE) {
        Some(t) => session_id_for_token(&state.pool, &t).await?,
        None => None,
    };
    if Some(id) == current_id {
        return Err(AppError::bad_request(
            "cannot revoke your current session; use log out instead",
        ));
    }
    if !revoke_session_by_id(&state.pool, user.id, id).await? {
        return Err(AppError::NotFound("session not found".into()));
    }
    Ok(Json(json!({ "ok": true })))
}

async fn revoke_my_other_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    match cookie_value(&headers, SESSION_COOKIE) {
        Some(t) => {
            if let Some(current_id) = session_id_for_token(&state.pool, &t).await? {
                revoke_other_sessions(&state.pool, user.id, current_id).await?;
            }
        }
        None => {
            revoke_all_sessions(&state.pool, user.id).await?;
        }
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, sqlx::FromRow)]
struct MyConsent {
    client_id: String,
    scopes: String,
    granted_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct MyActivityRow {
    id: Uuid,
    action: String,
    resource_type: String,
    resource_id: Option<String>,
    detail: Value,
    ip: Option<String>,
    browser: Option<String>,
    os: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, serde::Deserialize)]
struct ActivityQuery {
    page: Option<i64>,
    page_size: Option<i64>,
}

/// Current user's own audit trail — login history plus account/security actions.
/// Available to every authenticated role (self-service, not staff-scoped).
async fn my_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ActivityQuery>,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;

    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * page_size;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE actor_user_id = $1")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await?;

    let items = sqlx::query_as::<_, MyActivityRow>(
        r#"
        SELECT id, action, resource_type, resource_id, detail, ip, browser, os, created_at
        FROM audit_logs
        WHERE actor_user_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(user.id)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    // Security summary backing the header cards (self-service, distinct from the
    // global Overview snapshot).
    let last_login = sqlx::query_as::<
        _,
        (
            Option<String>,
            Option<String>,
            Option<String>,
            DateTime<Utc>,
        ),
    >(
        "SELECT ip, browser, os, created_at FROM audit_logs \
         WHERE actor_user_id = $1 AND action = 'auth.login' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user.id)
    .fetch_optional(&state.pool)
    .await?;

    let active_sessions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND expires_at > NOW()",
    )
    .bind(user.id)
    .fetch_one(&state.pool)
    .await?;

    let passkey_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = $1")
            .bind(user.id)
            .fetch_one(&state.pool)
            .await?;

    let consent_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_consents WHERE user_id = $1")
            .bind(user.id)
            .fetch_one(&state.pool)
            .await?;

    Ok(Json(json!({
        "summary": {
            "last_login": last_login.map(|(ip, browser, os, at)| json!({
                "ip": ip,
                "browser": browser,
                "os": os,
                "at": at,
            })),
            "active_sessions": active_sessions,
            "totp_enabled": user.totp_enabled,
            "passkey_count": passkey_count,
            "consent_count": consent_count,
        },
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    })))
}

async fn list_my_consents(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    let rows = sqlx::query_as::<_, MyConsent>(
        r#"
        SELECT client_id, scopes, granted_at
        FROM oauth_consents
        WHERE user_id = $1
        ORDER BY granted_at DESC
        "#,
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;

    let consents: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "client_id": r.client_id,
                "scopes": r.scopes.split_whitespace().collect::<Vec<_>>(),
                "granted_at": r.granted_at,
            })
        })
        .collect();

    Ok(Json(json!({ "consents": consents })))
}

async fn revoke_my_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Path(client_id): Path<String>,
) -> AppResult<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);
    let res = sqlx::query("DELETE FROM oauth_consents WHERE user_id = $1 AND client_id = $2")
        .bind(user.id)
        .bind(&client_id)
        .execute(&state.pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("consent not found".into()));
    }

    // Also revoke any outstanding refresh tokens so the client can no longer
    // refresh on the user's behalf once consent is withdrawn.
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = NOW() \
         WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL",
    )
    .bind(user.id)
    .bind(&client_id)
    .execute(&state.pool)
    .await?;

    record(
        &state,
        AuditEvent {
            actor: Some(user),
            action: "oauth.consent_revoke",
            resource_type: "client",
            resource_id: Some(client_id),
            detail: json!({}),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
struct UpdateMeBody {
    display_name: Option<String>,
    phone: Option<String>,
}

async fn update_me(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Json(body): Json<UpdateMeBody>,
) -> AppResult<Json<serde_json::Value>> {
    let user = current_user(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);
    let display_name = body
        .display_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::bad_request("display_name required"))?;

    // Same ownership rule as the admin path: a directory- or SCIM-managed
    // display name is not the account holder's to edit locally. Without this
    // the profile form was a way around the restriction, and the edit survived
    // only until the next sync overwrote it.
    if display_name != user.display_name {
        if let Some(authority) = crate::authority::managing_authority(&state.pool, user.id).await? {
            if let Some(msg) = authority.write_error("display_name") {
                return Err(AppError::forbidden(msg));
            }
        }
    }

    let phone = if body.phone.is_some() {
        crate::admin::normalize_phone(body.phone)?
    } else {
        user.phone.clone()
    };
    if let Some(p) = &phone {
        if user.phone.as_deref() != Some(p.as_str())
            && crate::admin::phone_exists(&state.pool, p, Some(user.id)).await?
        {
            return Err(AppError::bad_request("phone already exists"));
        }
    }

    let updated = sqlx::query_as::<_, crate::models::User>(&format!(
        r#"
        UPDATE users SET display_name = $2, phone = $3, updated_at = NOW()
        WHERE id = $1
        RETURNING {USER_COLS}
        "#
    ))
    .bind(user.id)
    .bind(&display_name)
    .bind(&phone)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.constraint() == Some("users_phone_key") => {
            AppError::bad_request("phone already exists")
        }
        other => AppError::from(other),
    })?;

    record(
        &state,
        AuditEvent {
            actor: Some(user),
            action: "me.profile_update",
            resource_type: "user",
            resource_id: Some(updated.id.to_string()),
            detail: json!({ "display_name": display_name }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "user": PublicUser::from(updated) })))
}

#[derive(Debug, Deserialize)]
struct ChangePasswordBody {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Json(body): Json<ChangePasswordBody>,
) -> AppResult<Json<serde_json::Value>> {
    // Unrestricted on purpose: this endpoint is what clears a pending
    // `must_change_password`, so it cannot sit behind the gate it exists to
    // lift (the current-password check is its own authentication).
    let user = current_user_unrestricted(&state, &headers).await?;
    let ip = crate::http::extract::audit_ip(audit_ip);
    // SSO-JIT and directory-provisioned accounts have no local password, so
    // there is nothing to verify: parsing the empty hash surfaced as a 500.
    // Their credential lives upstream (or arrives by email reset).
    if user.password_hash.is_empty() {
        return Err(AppError::bad_request(
            "this account has no local password; set one through the password reset flow \
             or your SSO provider",
        ));
    }
    if !verify_password_offloaded(&body.current_password, &user.password_hash).await? {
        return Err(AppError::unauthorized("current password is incorrect"));
    }
    set_user_password(
        &state.pool,
        user.id,
        &body.new_password,
        state.rt().password_min_length,
        state.rt().password_history_size,
    )
    .await?;

    // A new password retires the credentials the old one authorized. The
    // scenario this endpoint exists for is "the old one may be compromised",
    // so every other session dies — the current one stays, because the user is
    // using it right now — and the refresh tokens delegated to OAuth clients
    // die with them: they outlive passwords unless revoked explicitly.
    let session_id = match cookie_value(&headers, SESSION_COOKIE) {
        Some(token) => session_id_for_token(&state.pool, &token).await?,
        None => None,
    };
    let revoked_sessions = match session_id {
        Some(id) => revoke_other_sessions(&state.pool, user.id, id).await?,
        None => revoke_all_sessions(&state.pool, user.id).await?,
    };
    let revoked_tokens = crate::oidc::revoke_refresh_tokens_for_user(&state.pool, user.id).await?;

    record(
        &state,
        AuditEvent {
            actor: Some(user.clone()),
            action: "auth.password_change",
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({
                "revoked_sessions": revoked_sessions,
                "revoked_refresh_tokens": revoked_tokens,
            }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({ "ok": true })))
}
