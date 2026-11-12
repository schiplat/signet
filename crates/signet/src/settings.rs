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
use axum::routing::{get, post};
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

/// Re-reads the database periodically so every replica converges on the saved
/// policy without a restart.
///
/// The PATCH path publishes to its own process instantly; this task is what
/// carries a change *across* replicas (and picks up a hand-edited
/// `app_settings` row). Interval over immediacy: a 30-second worst case is
/// fine for operational policy, and per-request DB reads on the token-mint
/// path would cost far more than they could ever buy. A failed re-read keeps
/// the previous snapshot — stale policy beats an unavailable IdP.
pub fn spawn_refresher(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
        ticker.tick().await; // the boot load already ran; skip tick zero
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let (next, overridden) = load(&state.pool, &state.config).await;
            state.publish_settings(next);
            state.replace_overridden(overridden);
            state.rate_limiter.set_limit(next.rate_limit_per_minute);
        }
    });
}

/// How often the background re-reader converges replicas.
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/settings/runtime",
            get(get_runtime).patch(patch_runtime).delete(reset_runtime),
        )
        .route(
            "/admin/settings/smtp",
            get(get_smtp).patch(patch_smtp).delete(reset_smtp),
        )
        .route("/admin/settings/smtp/test", post(test_smtp))
        .route(
            "/admin/settings/captcha",
            get(get_captcha).patch(patch_captcha).delete(reset_captcha),
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

// --- SMTP relay settings ---
//
// Mail configuration lives under its own `smtp.*` key namespace (not
// `runtime.*`), so the runtime-policy reset cannot silently unhook the mailer
// an operator relies on for password resets. The password is stored encrypted
// with the application key — same as webhook and TOTP secrets — and is
// write-only over the API: the GET reports `password_set`, never the value.

/// `app_settings` keys this section owns, without the `smtp.` prefix.
const SMTP_FIELDS: &[&str] = &["host", "port", "username", "password", "from"];

async fn smtp_overridden(pool: &PgPool) -> AppResult<Vec<&'static str>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT key FROM app_settings WHERE key LIKE 'smtp.%'")
            .fetch_all(pool)
            .await?;
    let mut fields: Vec<&'static str> = rows
        .into_iter()
        .filter_map(|(k,)| k.strip_prefix("smtp.").map(str::to_owned))
        .filter_map(|f| SMTP_FIELDS.iter().find(|known| **known == f).copied())
        .collect();
    fields.sort_unstable();
    Ok(fields)
}

/// Renders the effective relay view for GET/PATCH responses — always without
/// the password itself.
fn smtp_view(smtp: &Option<crate::email::EffectiveSmtp>) -> Value {
    match smtp {
        Some(s) => json!({
            "host": s.host,
            "port": s.port,
            "username": s.username,
            "from": s.from,
            "password_set": s.password.is_some(),
            "configured": true,
        }),
        None => json!({
            "host": null,
            "port": null,
            "username": null,
            "from": null,
            "password_set": false,
            "configured": false,
        }),
    }
}

async fn get_smtp(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let smtp = crate::email::resolve(&state).await;
    let mut view = smtp_view(&smtp);
    view["overridden"] = json!(smtp_overridden(&state.pool).await?);
    view["restart_required"] = json!([]);
    Ok(Json(view))
}

/// Keeps "explicit null" distinct from "absent" on an optional field: JSON
/// `null` becomes `Some(None)`, a value becomes `Some(Some(v))`, and an
/// absent field stays `None` (via `#[serde(default)]`).
///
/// The derived `Option<Option<T>>` cannot do this — serde_json's
/// `deserialize_option` maps `null` to the *outer* `None` — which is exactly
/// the distinction the PATCH semantics need.
fn double_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(deserializer)?))
}

#[derive(Debug, Deserialize)]
pub struct SmtpPatch {
    /// Three states per field (see [`double_option`]): absent (leave the
    /// stored override), `null` (clear it; the environment answers again),
    /// and a value (set it). An empty string is refused — clearing is null.
    #[serde(default, deserialize_with = "double_option")]
    host: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    port: Option<Option<u16>>,
    #[serde(default, deserialize_with = "double_option")]
    username: Option<Option<String>>,
    /// Write-only: a value stores the password encrypted; `null` clears the
    /// stored one. The plaintext is never sent back.
    #[serde(default, deserialize_with = "double_option")]
    password: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    from: Option<Option<String>>,
}

/// The validated text of a set-field, trimmed and refused when empty.
fn set_text(v: String, what: &str) -> AppResult<String> {
    let v = v.trim().to_string();
    if v.is_empty() {
        return Err(AppError::bad_request(format!(
            "use null to clear {what}, not an empty string"
        )));
    }
    Ok(v)
}

async fn patch_smtp(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Json(body): Json<SmtpPatch>,
) -> AppResult<Json<Value>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let ip = crate::http::extract::audit_ip(audit_ip);

    // Validate everything before writing anything: a relay the mailer cannot
    // use must never make it into app_settings.
    let host = match &body.host {
        Some(Some(v)) => {
            let v = set_text(v.clone(), "host")?;
            if v.len() > 253 {
                return Err(AppError::bad_request("host must be at most 253 characters"));
            }
            Some(v)
        }
        _ => None,
    };
    let port = match body.port {
        // `Some(None)` (explicit null) and `None` (absent) both mean no port
        // write; only a real value is validated here.
        Some(Some(p)) => {
            if !(1..=65535).contains(&p) {
                return Err(AppError::bad_request("port must be 1-65535"));
            }
            Some(p)
        }
        _ => None,
    };
    let username = match &body.username {
        Some(Some(v)) => Some(set_text(v.clone(), "username")?),
        _ => None,
    };
    let password = match &body.password {
        Some(Some(v)) => {
            if v.trim().is_empty() {
                return Err(AppError::bad_request(
                    "use null to clear the password, not an empty string",
                ));
            }
            if v.len() > 1024 {
                return Err(AppError::bad_request("password is too long"));
            }
            Some(v.clone())
        }
        _ => None,
    };
    let from = match &body.from {
        Some(Some(v)) => {
            let v = set_text(v.clone(), "from")?;
            v.parse::<lettre::message::Mailbox>().map_err(|_| {
                AppError::bad_request(
                    "from is not a mailbox (e.g. \"Signet <no-reply@example.com>\")",
                )
            })?;
            Some(v)
        }
        _ => None,
    };

    let mut changed: Vec<&'static str> = Vec::new();
    let mut clear: Vec<&'static str> = Vec::new();

    let before = crate::email::resolve(&state).await.map(|s| s.redacted());

    let mut tx = state.pool.begin().await?;
    for (field, spec) in [
        ("host", host.map(|v| json!(v))),
        ("port", port.map(|v| json!(v))),
        ("username", username.map(|v| json!(v))),
        // Encrypted at rest; the plaintext never lands in the database or a
        // log line.
        (
            "password",
            password.map(|v| json!(state.encryptor.encrypt(&v))),
        ),
        ("from", from.map(|v| json!(v))),
    ] {
        match (body_field(&body, field), spec) {
            (None, _) => {
                continue; // absent: leave the stored override as it is
            }
            // Explicit null: drop the override so the env applies again.
            (Some(false), _) => {
                sqlx::query("DELETE FROM app_settings WHERE key = $1")
                    .bind(format!("smtp.{field}"))
                    .execute(&mut *tx)
                    .await?;
                clear.push(field);
            }
            (Some(true), Some(stored)) => {
                sqlx::query(
                    r#"
                    INSERT INTO app_settings (key, value, updated_at)
                    VALUES ($1, $2, NOW())
                    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
                    "#,
                )
                .bind(format!("smtp.{field}"))
                .bind(stored)
                .execute(&mut *tx)
                .await?;
                changed.push(field);
            }
            // A validated set-value whose field cannot be re-read from the
            // body cannot happen (the pair above is built from the same body).
            (Some(true), None) => {
                return Err(AppError::bad_request("invalid field value"));
            }
        }
    }
    tx.commit().await?;

    let after = crate::email::resolve(&state).await.map(|s| s.redacted());

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "settings.smtp_update",
            resource_type: "settings",
            resource_id: Some("smtp".into()),
            detail: json!({
                "changed": changed,
                "cleared": clear,
                "before": before,
                "after": after,
            }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    let mut view = smtp_view(&crate::email::resolve(&state).await);
    view["changed"] = json!(changed);
    view["cleared"] = json!(clear);
    view["overridden"] = json!(smtp_overridden(&state.pool).await?);
    Ok(Json(view))
}

/// Whether the patch body carries `field`: `None` = absent, `Some(false)` =
/// explicit null (clear the override), `Some(true)` = a value to set.
fn body_field(body: &SmtpPatch, field: &str) -> Option<bool> {
    match field {
        "host" => body.host.as_ref().map(|v| v.is_some()),
        "port" => body.port.as_ref().map(|v| v.is_some()),
        "username" => body.username.as_ref().map(|v| v.is_some()),
        "password" => body.password.as_ref().map(|v| v.is_some()),
        "from" => body.from.as_ref().map(|v| v.is_some()),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
pub struct SmtpReset {
    fields: Option<String>,
}

/// Drops saved SMTP overrides so the environment applies again.
async fn reset_smtp(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Query(query): Query<SmtpReset>,
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
    let before = crate::email::resolve(&state).await.map(|s| s.redacted());
    let deleted = match &requested {
        Some(fields) => {
            for field in fields {
                if !SMTP_FIELDS.contains(&field.as_str()) {
                    return Err(AppError::bad_request(format!("unknown field {field}")));
                }
            }
            let keys: Vec<String> = fields.iter().map(|f| format!("smtp.{f}")).collect();
            sqlx::query("DELETE FROM app_settings WHERE key = ANY($1)")
                .bind(&keys)
                .execute(&state.pool)
                .await?
                .rows_affected()
        }
        None => sqlx::query("DELETE FROM app_settings WHERE key LIKE 'smtp.%'")
            .execute(&state.pool)
            .await?
            .rows_affected(),
    };

    let after = crate::email::resolve(&state).await.map(|s| s.redacted());
    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "settings.smtp_reset",
            resource_type: "settings",
            resource_id: Some("smtp".into()),
            detail: json!({
                "fields": requested,
                "rows_deleted": deleted,
                "before": before,
                "after": after,
            }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    let smtp = crate::email::resolve(&state).await;
    Ok(Json(json!({
        "configured": smtp.is_some(),
        "rows_deleted": deleted,
        "overridden": smtp_overridden(&state.pool).await?,
    })))
}

#[derive(Debug, Deserialize)]
pub struct SmtpTest {
    to: String,
}

/// Sends one test message through the *effective* relay, reporting the
/// transport error verbatim on failure — this endpoint exists precisely so an
/// operator sees "why does my mail not go out" without reading server logs.
async fn test_smtp(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Json(body): Json<SmtpTest>,
) -> AppResult<Json<Value>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let ip = crate::http::extract::audit_ip(audit_ip);
    let to = body.to.trim().to_string();

    let outcome = if !crate::email::configured(&state).await {
        Err("no SMTP relay is configured (set it here or via SIGNET_SMTP_HOST)".to_string())
    } else {
        crate::email::send(
            &state,
            &to,
            "Signet test message",
            "This is a test message from your Signet instance. If you can read this, \
             the relay settings work.",
            false,
        )
        .await
        .map_err(|e| e.to_string())
    };

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "settings.smtp_test",
            resource_type: "settings",
            resource_id: Some("smtp".into()),
            detail: json!({
                "to": to,
                "ok": outcome.is_ok(),
                "error": outcome.as_ref().err(),
            }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    match outcome {
        Ok(()) => Ok(Json(json!({ "ok": true }))),
        Err(e) => Ok(Json(json!({ "ok": false, "error": e }))),
    }
}

// --- CAPTCHA gate settings ---
//
// Turnstile or hCaptcha on the unauthenticated doors (login, password-reset
// request). Same three-state PATCH semantics and encrypted-secret handling as
// the SMTP section; the gate is enabled only when provider, site key and
// secret are all present, so a half-saved row cannot lock everyone out.

/// `app_settings` keys this section owns, without the `captcha.` prefix.
const CAPTCHA_FIELDS: &[&str] = &["provider", "site_key", "secret_key"];

async fn captcha_overridden(pool: &PgPool) -> AppResult<Vec<&'static str>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT key FROM app_settings WHERE key LIKE 'captcha.%'")
            .fetch_all(pool)
            .await?;
    let mut fields: Vec<&'static str> = rows
        .into_iter()
        .filter_map(|(k,)| k.strip_prefix("captcha.").map(str::to_owned))
        .filter_map(|f| CAPTCHA_FIELDS.iter().find(|known| **known == f).copied())
        .collect();
    fields.sort_unstable();
    Ok(fields)
}

/// The view without the secret — provider + site key are public knowledge
/// (the site key ships to every browser), but the secret never comes back.
fn captcha_view(gate: &Option<crate::captcha::Enabled>) -> Value {
    match gate {
        Some(g) => json!({
            "enabled": true,
            "provider": g.provider.as_str(),
            "site_key": g.site_key,
            "secret_set": true,
        }),
        None => json!({
            "enabled": false,
            "provider": null,
            "site_key": null,
            "secret_set": false,
        }),
    }
}

async fn get_captcha(State(state): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let gate = crate::captcha::resolve(&state).await;
    let mut view = captcha_view(&gate);
    view["overridden"] = json!(captcha_overridden(&state.pool).await?);
    Ok(Json(view))
}

#[derive(Debug, Deserialize)]
pub struct CaptchaPatch {
    /// `turnstile` | `hcaptcha` — the same siteverify shape, one endpoint each.
    #[serde(default, deserialize_with = "double_option")]
    provider: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    site_key: Option<Option<String>>,
    /// Write-only; stored encrypted like the SMTP password.
    #[serde(default, deserialize_with = "double_option")]
    secret_key: Option<Option<String>>,
}

async fn patch_captcha(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Json(body): Json<CaptchaPatch>,
) -> AppResult<Json<Value>> {
    let actor = crate::auth::current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    let ip = crate::http::extract::audit_ip(audit_ip);

    let provider = match &body.provider {
        Some(Some(v)) => {
            let v = set_text(v.clone(), "provider")?;
            if v != "off" && crate::captcha::Provider::parse(&v).is_none() {
                return Err(AppError::bad_request(
                    "provider must be \"off\", \"turnstile\" or \"hcaptcha\"",
                ));
            }
            Some(if v == "off" {
                String::new() // stored as an explicit off-marker
            } else {
                v
            })
        }
        _ => None,
    };
    let site_key = match &body.site_key {
        Some(Some(v)) => Some(set_text(v.clone(), "site_key")?),
        _ => None,
    };
    let secret_key = match &body.secret_key {
        Some(Some(v)) => {
            if v.trim().is_empty() {
                return Err(AppError::bad_request(
                    "use null to clear the secret, not an empty string",
                ));
            }
            if v.len() > 512 {
                return Err(AppError::bad_request("secret is too long"));
            }
            Some(v.clone())
        }
        _ => None,
    };

    let before = crate::captcha::resolve(&state)
        .await
        .map(|g| json!({ "enabled": true, "provider": g.provider.as_str() }));
    let mut changed: Vec<&'static str> = Vec::new();
    let mut clear: Vec<&'static str> = Vec::new();

    let mut tx = state.pool.begin().await?;
    for (field, spec, value) in [
        (
            "provider",
            body.provider.as_ref().map(|p| p.is_some()),
            provider.clone().map(|v| json!(v)),
        ),
        (
            "site_key",
            body.site_key.as_ref().map(|p| p.is_some()),
            site_key.clone().map(|v| json!(v)),
        ),
        (
            "secret_key",
            body.secret_key.as_ref().map(|p| p.is_some()),
            secret_key
                .clone()
                .map(|v| json!(state.encryptor.encrypt(&v))),
        ),
    ] {
        match (spec, value) {
            (None, _) | (Some(false), None) => continue, // absent: untouched
            (Some(false), _) => {
                sqlx::query("DELETE FROM app_settings WHERE key = $1")
                    .bind(format!("captcha.{field}"))
                    .execute(&mut *tx)
                    .await?;
                clear.push(field);
            }
            (Some(true), Some(stored)) => {
                sqlx::query(
                    r#"
                    INSERT INTO app_settings (key, value, updated_at)
                    VALUES ($1, $2, NOW())
                    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
                    "#,
                )
                .bind(format!("captcha.{field}"))
                .bind(stored)
                .execute(&mut *tx)
                .await?;
                changed.push(field);
            }
            (Some(true), None) => {
                return Err(AppError::bad_request("invalid field value"));
            }
        }
    }
    tx.commit().await?;

    let after = crate::captcha::resolve(&state)
        .await
        .map(|g| json!({ "enabled": true, "provider": g.provider.as_str() }));

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "settings.captcha_update",
            resource_type: "settings",
            resource_id: Some("captcha".into()),
            detail: json!({ "changed": changed, "cleared": clear, "before": before, "after": after }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    let gate = crate::captcha::resolve(&state).await;
    let mut view = captcha_view(&gate);
    view["changed"] = json!(changed);
    view["cleared"] = json!(clear);
    view["overridden"] = json!(captcha_overridden(&state.pool).await?);
    Ok(Json(view))
}

#[derive(Debug, Deserialize)]
pub struct CaptchaReset {
    fields: Option<String>,
}

async fn reset_captcha(
    State(state): State<AppState>,
    headers: HeaderMap,
    audit_ip: Option<Extension<AuditIp>>,
    Query(query): Query<CaptchaReset>,
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
    let before = crate::captcha::resolve(&state)
        .await
        .map(|g| json!({ "enabled": true, "provider": g.provider.as_str() }));
    let deleted = match &requested {
        Some(fields) => {
            for field in fields {
                if !CAPTCHA_FIELDS.contains(&field.as_str()) {
                    return Err(AppError::bad_request(format!("unknown field {field}")));
                }
            }
            let keys: Vec<String> = fields.iter().map(|f| format!("captcha.{f}")).collect();
            sqlx::query("DELETE FROM app_settings WHERE key = ANY($1)")
                .bind(&keys)
                .execute(&state.pool)
                .await?
                .rows_affected()
        }
        None => sqlx::query("DELETE FROM app_settings WHERE key LIKE 'captcha.%'")
            .execute(&state.pool)
            .await?
            .rows_affected(),
    };

    let after = crate::captcha::resolve(&state)
        .await
        .map(|g| json!({ "enabled": true, "provider": g.provider.as_str() }));
    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: "settings.captcha_reset",
            resource_type: "settings",
            resource_id: Some("captcha".into()),
            detail: json!({
                "fields": requested,
                "rows_deleted": deleted,
                "before": before,
                "after": after,
            }),
            ip,
            user_agent: crate::http::extract::user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    let gate = crate::captcha::resolve(&state).await;
    let mut view = captcha_view(&gate);
    view["rows_deleted"] = json!(deleted);
    view["overridden"] = json!(captcha_overridden(&state.pool).await?);
    Ok(Json(view))
}
