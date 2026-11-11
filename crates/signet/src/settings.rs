//! Runtime settings: operational policy that an administrator can change from
//! the dashboard instead of editing `.env` and redeploying.
//!
//! Precedence is **DB > env > built-in default**, per field. A key is written
//! to `app_settings` only when an administrator changes it, so an operator's
//! existing environment keeps working untouched: the DB layer starts empty and
//! every value reports where it came from.
//!
//! What deliberately stays in the environment: the database URL, listen address,
//! key file paths, the issuer, the trusted-proxy list and the outbound-private
//! switch. Those are needed *before* the database can be read, are network/trust
//! boundaries rather than policy, or (the issuer) break every client if changed
//! wrongly and cannot be repaired from the dashboard — the same tail risk as the
//! last administrator. See `Config` for their rationale.
//!
//! Changes apply live. The one exception would be something baked into a
//! long-lived object at boot; today nothing in [`RuntimeSettings`] is, and the
//! rate limiter reads its limit per request (see
//! [`crate::http::ratelimit::RateLimiter::set_limit`]).

use crate::audit::{record, AuditEvent};
use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::http::extract::AuditIp;
use crate::roles::require_admin_role;
use crate::state::AppState;
use axum::extract::{Extension, Query, State};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashMap;

/// Prefix for the `app_settings` keys this module owns.
const PREFIX: &str = "runtime.";

/// The operational knobs an administrator can change without a redeploy.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RuntimeSettings {
    pub session_ttl_hours: i64,
    pub auth_code_ttl_secs: i64,
    pub access_token_ttl_secs: i64,
    pub id_token_ttl_secs: i64,
    pub refresh_token_ttl_days: i64,
    pub max_login_attempts: i64,
    pub lockout_minutes: i64,
    pub password_min_length: usize,
    pub password_history_size: i64,
    pub audit_retention_days: i64,
    pub rate_limit_per_minute: usize,
}

impl RuntimeSettings {
    /// The values the environment (or the built-in defaults) asks for. These are
    /// the fallbacks for every field the database does not override.
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            session_ttl_hours: cfg.session_ttl_hours,
            auth_code_ttl_secs: cfg.auth_code_ttl_secs,
            access_token_ttl_secs: cfg.access_token_ttl_secs,
            id_token_ttl_secs: cfg.id_token_ttl_secs,
            refresh_token_ttl_days: cfg.refresh_token_ttl_days,
            max_login_attempts: cfg.max_login_attempts,
            lockout_minutes: cfg.lockout_minutes,
            password_min_length: cfg.password_min_length,
            password_history_size: cfg.password_history_size,
            audit_retention_days: cfg.audit_retention_days,
            rate_limit_per_minute: cfg.rate_limit_per_minute,
        }
    }

    /// Range checks shared by the write path and the boot-time read.
    ///
    /// Ranges are wide enough to express real intent and narrow enough that a
    /// typo cannot disable a control: a session TTL of 0 would expire on
    /// creation, a password minimum of 1 is not a policy, and a retention of 0
    /// deletes the whole audit trail.
    fn validate(&self) -> Result<(), String> {
        let checks: [(&str, i64, i64, i64); 8] = [
            ("session_ttl_hours", self.session_ttl_hours, 1, 720),
            ("auth_code_ttl_secs", self.auth_code_ttl_secs, 30, 3600),
            (
                "access_token_ttl_secs",
                self.access_token_ttl_secs,
                60,
                86_400,
            ),
            ("id_token_ttl_secs", self.id_token_ttl_secs, 60, 86_400),
            (
                "refresh_token_ttl_days",
                self.refresh_token_ttl_days,
                1,
                365,
            ),
            ("max_login_attempts", self.max_login_attempts, 1, 100),
            ("lockout_minutes", self.lockout_minutes, 1, 1440),
            ("password_history_size", self.password_history_size, 0, 24),
        ];
        for (name, value, min, max) in checks {
            if !(min..=max).contains(&value) {
                return Err(format!("{name} must be between {min} and {max}"));
            }
        }
        if !(8..=128).contains(&self.password_min_length) {
            return Err("password_min_length must be between 8 and 128".into());
        }
        if !(1..=3650).contains(&self.audit_retention_days) {
            return Err("audit_retention_days must be between 1 and 3650".into());
        }
        if !(1..=100_000).contains(&self.rate_limit_per_minute) {
            return Err("rate_limit_per_minute must be between 1 and 100000".into());
        }
        Ok(())
    }
}

/// Reads the DB overrides and layers them over `cfg`.
///
/// A row that cannot be parsed is ignored with a warning rather than failing
/// boot: the field keeps its env/default value, which is the safer reading of a
/// hand-edited row. (Contrast `crypto.encryption_key_fingerprint`, which is a
/// correctness invariant and does fail closed.)
pub async fn load(pool: &PgPool, cfg: &Config) -> (RuntimeSettings, Vec<&'static str>) {
    let mut settings = RuntimeSettings::from_config(cfg);
    let rows: HashMap<String, Value> = match sqlx::query_as::<_, (String, Value)>(
        "SELECT key, value FROM app_settings WHERE key LIKE $1",
    )
    .bind(format!("{PREFIX}%"))
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows.into_iter().collect(),
        Err(e) => {
            tracing::warn!(error = %e, "could not read runtime settings; using env/defaults");
            return (settings, Vec::new());
        }
    };

    let mut overridden = Vec::new();
    macro_rules! int_field {
        ($field:ident, $ty:ty) => {
            if let Some(v) = rows
                .get(concat!("runtime.", stringify!($field)))
                .and_then(Value::as_i64)
            {
                settings.$field = v as $ty;
                overridden.push(stringify!($field));
            }
        };
    }
    int_field!(session_ttl_hours, i64);
    int_field!(auth_code_ttl_secs, i64);
    int_field!(access_token_ttl_secs, i64);
    int_field!(id_token_ttl_secs, i64);
    int_field!(refresh_token_ttl_days, i64);
    int_field!(max_login_attempts, i64);
    int_field!(lockout_minutes, i64);
    int_field!(password_min_length, usize);
    int_field!(password_history_size, i64);
    int_field!(audit_retention_days, i64);
    int_field!(rate_limit_per_minute, usize);

    if let Err(e) = settings.validate() {
        // A stored value outside its range (hand-edited row, older release)
        // falls back wholesale rather than serving a broken policy.
        tracing::warn!(error = %e, "stored runtime settings invalid; using env/defaults");
        return (RuntimeSettings::from_config(cfg), Vec::new());
    }
    (settings, overridden)
}

/// The PATCH body: every field optional, absent means "leave it".
#[derive(Debug, Deserialize)]
pub struct RuntimePatch {
    session_ttl_hours: Option<i64>,
    auth_code_ttl_secs: Option<i64>,
    access_token_ttl_secs: Option<i64>,
    id_token_ttl_secs: Option<i64>,
    refresh_token_ttl_days: Option<i64>,
    max_login_attempts: Option<i64>,
    lockout_minutes: Option<i64>,
    password_min_length: Option<usize>,
    password_history_size: Option<i64>,
    audit_retention_days: Option<i64>,
    rate_limit_per_minute: Option<usize>,
}

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/admin/settings/runtime",
        get(get_runtime).patch(patch_runtime).delete(reset_runtime),
    )
}

/// `?fields=session_ttl_hours,lockout_minutes`, or no query for "all".
///
/// Query parameters rather than a JSON body: a bodiless DELETE is the natural
/// shape for "remove these rows", and it keeps the empty-body case unambiguous
/// (no content-type to negotiate).
#[derive(Debug, Deserialize)]
pub struct RuntimeReset {
    fields: Option<String>,
}

/// Field names accepted by the reset endpoint; mirrors every field the patch
/// body has.
const KNOWN_FIELDS: &[&str] = &[
    "session_ttl_hours",
    "auth_code_ttl_secs",
    "access_token_ttl_secs",
    "id_token_ttl_secs",
    "refresh_token_ttl_days",
    "max_login_attempts",
    "lockout_minutes",
    "password_min_length",
    "password_history_size",
    "audit_retention_days",
    "rate_limit_per_minute",
];

/// Drops saved overrides so the environment applies again.
///
/// Without this, a value saved once is permanent even after the environment
/// changes — the only way back would be a hand-run DELETE, and the "env" marker
/// in the UI would become a lie. The in-memory snapshot is reloaded from the
/// database and the environment before answering, so the next request already
/// sees the fallback.
async fn reset_runtime(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Query(query): Query<RuntimeReset>,
) -> AppResult<Json<Value>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let ip = crate::http::extract::audit_ip(audit_ip);

    let requested: Option<Vec<String>> = query.fields.map(|raw| {
        raw.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    });
    let before = state.rt();
    let deleted = match &requested {
        Some(fields) => {
            for field in fields {
                if !KNOWN_FIELDS.contains(&field.as_str()) {
                    return Err(AppError::bad_request(format!("unknown field {field}")));
                }
            }
            let keys: Vec<String> = fields.iter().map(|f| format!("{PREFIX}{f}")).collect();
            sqlx::query("DELETE FROM app_settings WHERE key = ANY($1)")
                .bind(&keys)
                .execute(&state.pool)
                .await?
                .rows_affected()
        }
        None => sqlx::query("DELETE FROM app_settings WHERE key LIKE $1")
            .bind(format!("{PREFIX}%"))
            .execute(&state.pool)
            .await?
            .rows_affected(),
    };

    let (next, overridden) = load(&state.pool, &state.config).await;
    state.publish_settings(next);
    state.rate_limiter.set_limit(next.rate_limit_per_minute);
    state.replace_overridden(overridden);

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "settings.runtime_reset",
            resource_type: "settings",
            resource_id: Some("runtime".into()),
            detail: json!({
                "fields": requested,
                "rows_deleted": deleted,
                "before": before,
                "after": next,
            }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({
        "settings": next,
        "overridden": state.overridden(),
    })))
}

async fn get_runtime(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let overridden = state.overridden();
    let settings = state.rt();
    Ok(Json(json!({
        "settings": settings,
        "overridden": overridden,
        // Nothing here is baked into a boot-time object; kept in the payload so
        // the UI can grow a flag when that stops being true.
        "restart_required": [],
    })))
}

async fn patch_runtime(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Json(body): Json<RuntimePatch>,
) -> AppResult<Json<Value>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let ip = crate::http::extract::audit_ip(audit_ip);

    let before = state.rt();
    let mut next = before;
    let mut changed: Vec<&'static str> = Vec::new();
    macro_rules! apply {
        ($field:ident, $label:literal) => {
            if let Some(v) = body.$field {
                if next.$field != v {
                    next.$field = v;
                    changed.push($label);
                }
            }
        };
    }
    apply!(session_ttl_hours, "session_ttl_hours");
    apply!(auth_code_ttl_secs, "auth_code_ttl_secs");
    apply!(access_token_ttl_secs, "access_token_ttl_secs");
    apply!(id_token_ttl_secs, "id_token_ttl_secs");
    apply!(refresh_token_ttl_days, "refresh_token_ttl_days");
    apply!(max_login_attempts, "max_login_attempts");
    apply!(lockout_minutes, "lockout_minutes");
    apply!(password_min_length, "password_min_length");
    apply!(password_history_size, "password_history_size");
    apply!(audit_retention_days, "audit_retention_days");
    apply!(rate_limit_per_minute, "rate_limit_per_minute");

    next.validate().map_err(AppError::bad_request)?;
    if changed.is_empty() {
        return Ok(Json(json!({ "settings": next, "changed": [] })));
    }

    // One transaction: a partial write would leave half a policy in force.
    let mut tx = state.pool.begin().await?;
    for field in &changed {
        let value = match *field {
            "session_ttl_hours" => json!(next.session_ttl_hours),
            "auth_code_ttl_secs" => json!(next.auth_code_ttl_secs),
            "access_token_ttl_secs" => json!(next.access_token_ttl_secs),
            "id_token_ttl_secs" => json!(next.id_token_ttl_secs),
            "refresh_token_ttl_days" => json!(next.refresh_token_ttl_days),
            "max_login_attempts" => json!(next.max_login_attempts),
            "lockout_minutes" => json!(next.lockout_minutes),
            "password_min_length" => json!(next.password_min_length),
            "password_history_size" => json!(next.password_history_size),
            "audit_retention_days" => json!(next.audit_retention_days),
            "rate_limit_per_minute" => json!(next.rate_limit_per_minute),
            other => return Err(AppError::bad_request(format!("unknown field {other}"))),
        };
        sqlx::query(
            r#"
            INSERT INTO app_settings (key, value, updated_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
            "#,
        )
        .bind(format!("{PREFIX}{field}"))
        .bind(value)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    // Publish the new snapshot before answering, so the next request already
    // sees it — including the rate limiter, which is why it is not rebuilt.
    state.publish_settings(next);
    state.mark_overridden(&changed);
    state.rate_limiter.set_limit(next.rate_limit_per_minute);

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "settings.runtime_update",
            resource_type: "settings",
            resource_id: Some("runtime".into()),
            detail: json!({
                "changed": changed,
                "before": before,
                "after": next,
            }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(json!({
        "settings": next,
        "changed": changed,
        "overridden": state.overridden(),
    })))
}
