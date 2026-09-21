//! Who is allowed in: the email-domain allowlist that gates sign-in and
//! provisioning.
//!
//! Two different things carry the same field name (`email_domains`), and mixing
//! them up would turn a policy change into a mass offboarding:
//!
//! * [`crate::directory::plan::ScopeFilter`] is a source's **ownership**. An
//!   entry outside it is not that source's to manage, and a *linked* user who
//!   leaves it is disabled — the source is saying it no longer owns them.
//! * this module is **admission**. An address outside it may not sign in and
//!   must not be provisioned, and it never disables anybody. Narrowing the
//!   allowlist is a statement about who may come in, not about who left, so an
//!   account that falls outside keeps its data and its history and simply
//!   cannot sign in until an administrator widens the list again.
//!
//! Matching is deliberately narrow: a list of exact domains, each admitting its
//! real subdomains, compared on label boundaries — [`domain_matches`] is the one
//! place that comparison lives, so `evilcorp.example` is not admitted by
//! `corp.example` wherever the check is made. No wildcards, because a typo in a
//! pattern language widens or empties access silently and cannot be verified by
//! looking at it.
//!
//! An **empty list means no restriction**, which is what keeps every deployment
//! that never configures this — the whole test suite included — behaving exactly
//! as before. It also makes "the list silently became empty" the dangerous
//! direction, which is why the env var path fails loudly on a bad entry rather
//! than dropping it ([`validate_domains`]).
//!
//! The list comes from `app_settings.auth.allowed_email_domains`, falling back
//! to `SIGNET_ALLOWED_EMAIL_DOMAINS`. It is read through [`allowed_domains`], and
//! never held in a long-lived cache: the setting is expected to change without a
//! restart, and a stale allowlist is an outage or a hole depending on which way
//! it went.

use crate::audit::{record, AuditEvent};
use crate::auth::session::current_user;
use crate::error::{AppError, AppResult};
use crate::http::extract::user_agent;
use crate::models::User;
use crate::roles::require_admin_role;
use crate::state::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;

/// The `app_settings` row the allowlist lives in.
pub const SETTING_KEY: &str = "auth.allowed_email_domains";

/// Recorded when a sign-in is refused because of the allowlist.
pub const AUDIT_SIGN_IN_BLOCKED: &str = "auth.sign_in_blocked";
/// Recorded when a provisioning attempt is refused because of the allowlist.
pub const AUDIT_PROVISION_BLOCKED: &str = "user.provision_blocked";
/// Recorded when an administrator changes the list.
pub const AUDIT_SETTING_UPDATE: &str = "settings.sign_in_allowlist_update";

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/admin/settings/sign-in",
        get(get_sign_in_settings).patch(patch_sign_in_settings),
    )
}

/// Whether `domain` is `allowed` or a subdomain of it.
///
/// A plain suffix test would accept `evilcorp.example` for `corp.example`, which
/// is the mistake that turns a domain filter into an open door. Comparing on
/// label boundaries means a subdomain has to be a real one: `mail.corp.example`
/// passes, `notcorp.example` does not.
pub fn domain_matches(domain: &str, allowed: &str) -> bool {
    let allowed = allowed.trim().trim_start_matches('.').to_lowercase();
    if allowed.is_empty() {
        return false;
    }
    domain == allowed || domain.ends_with(&format!(".{allowed}"))
}

/// The domain of an address, or `None` when there is none to read.
///
/// The **last** `@` decides: an address with an `@` in the local part is unusual
/// but legal, and splitting on the first one would read the domain of
/// `weird@name@corp.example` as `name@corp.example`.
pub fn domain_of(email: &str) -> Option<String> {
    let normalized = email.trim().to_lowercase();
    let (local, domain) = normalized.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    Some(domain.to_string())
}

/// Whether an address is admitted by `domains`.
///
/// A configured list and an address with no readable domain means "no", not
/// "unknown": the address cannot be shown to belong to an admitted domain, and
/// treating an unreadable one as admitted would quietly let in exactly what the
/// administrator meant to keep out.
pub fn allows(domains: &[String], email: &str) -> bool {
    if domains.is_empty() {
        return true;
    }
    let Some(domain) = domain_of(email) else {
        return false;
    };
    domains
        .iter()
        .any(|allowed| domain_matches(&domain, allowed))
}

/// Checks and normalizes an operator-supplied domain list.
///
/// Returns the trimmed, lowercased, deduplicated list, so the comparison above
/// never has to normalize again. `setting` names the list in the error, because
/// the same check serves the env var, the settings row and the per-source scope
/// — and "email_domains must not contain an empty entry" is useless when three
/// different fields are called that.
pub fn validate_domains(domains: &[String], setting: &str) -> Result<Vec<String>, String> {
    let mut normalized = Vec::new();
    for domain in domains {
        let domain = domain.trim();
        if domain.is_empty() {
            return Err(format!("{setting} must not contain an empty entry"));
        }
        if domain.contains('@') {
            return Err(format!(
                "{setting} holds domains, not addresses; got `{domain}`"
            ));
        }
        if domain.contains('*') {
            return Err(format!(
                "{setting} has no wildcards — list each domain (subdomains are \
                 matched automatically); got `{domain}`"
            ));
        }
        let domain = domain.trim_start_matches('.').to_lowercase();
        if !normalized.contains(&domain) {
            normalized.push(domain);
        }
    }
    Ok(normalized)
}

/// The allowlist in force: the settings row if it exists, else the environment.
///
/// A row that is present but not an array of strings is treated as absent rather
/// than as "allow everything": it means someone wrote the setting by hand and
/// got it wrong, and the safe reading of a broken allowlist is the one that
/// matches the operator's clear intent, which was to restrict. The fallback is
/// the env value, which is itself validated at startup.
pub async fn allowed_domains(pool: &PgPool, env_default: &[String]) -> AppResult<Vec<String>> {
    let value: Option<Value> = sqlx::query_scalar("SELECT value FROM app_settings WHERE key = $1")
        .bind(SETTING_KEY)
        .fetch_optional(pool)
        .await?;

    Ok(read_setting(&value).unwrap_or_else(|| env_default.to_vec()))
}

/// Where the list in force came from, for the settings API.
///
/// The dashboard needs this to say "from the environment" instead of showing an
/// editable box whose value a restart would overwrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Setting,
    Environment,
    /// Neither is configured, so nothing is restricted.
    Unrestricted,
}

pub async fn origin(pool: &PgPool, env_default: &[String]) -> AppResult<Origin> {
    let value: Option<Value> = sqlx::query_scalar("SELECT value FROM app_settings WHERE key = $1")
        .bind(SETTING_KEY)
        .fetch_optional(pool)
        .await?;
    Ok(match read_setting(&value) {
        Some(_) => Origin::Setting,
        None if env_default.is_empty() => Origin::Unrestricted,
        None => Origin::Environment,
    })
}

fn read_setting(value: &Option<Value>) -> Option<Vec<String>> {
    value.as_ref()?.as_array().map(|items| {
        items
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>()
    })
}

/// Writes the allowlist, or removes the row so the environment applies again.
pub async fn set_allowed_domains(pool: &PgPool, domains: Option<&[String]>) -> AppResult<()> {
    match domains {
        Some(domains) => {
            sqlx::query(
                r#"
                INSERT INTO app_settings (key, value, updated_at)
                VALUES ($1, $2, NOW())
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
                "#,
            )
            .bind(SETTING_KEY)
            .bind(json!(domains))
            .execute(pool)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM app_settings WHERE key = $1")
                .bind(SETTING_KEY)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

/// Which path a blocked attempt came through, for the audit detail.
///
/// A value rather than an enum because the providers are named by a stored
/// `code`, but the point is the same: an operator reading the log has to be able
/// to tell "the IdP pushed him" from "he tried his password".
pub mod via {
    pub const PASSWORD: &str = "password";
    pub const PASSKEY: &str = "passkey";
    pub const SSO: &str = "sso";
    pub const ADMIN: &str = "admin";
    pub const SCIM: &str = "scim";
    pub const SSO_JIT: &str = "sso_jit";
}

/// Refuses a sign-in for an address the allowlist excludes, and records it.
///
/// Called with a user whose credentials have already been accepted, which is why
/// the error may name the domain: the only person who sees it has just proved
/// they own the account. Refusing this late is also what keeps the response from
/// being an enumeration oracle — an unknown address still fails at the
/// credential step, with the same generic message as a wrong password.
pub async fn ensure_sign_in_allowed(
    state: &AppState,
    user: &User,
    via: &str,
    user_agent: Option<String>,
) -> AppResult<()> {
    let domains = allowed_domains(&state.pool, &state.config.allowed_email_domains).await?;
    if allows(&domains, &user.email) {
        return Ok(());
    }

    let domain = domain_of(&user.email);
    crate::audit::record(
        state,
        crate::audit::AuditEvent {
            actor: Some(user.clone()),
            action: AUDIT_SIGN_IN_BLOCKED,
            resource_type: "user",
            resource_id: Some(user.id.to_string()),
            detail: json!({ "via": via, "email_domain": domain }),
            ip: None,
            user_agent,
            client_id: None,
        },
    )
    .await;

    Err(AppError::unauthorized(match domain {
        Some(domain) => format!("sign-in is not allowed for the {domain} email domain"),
        None => "sign-in is not allowed for this email domain".to_string(),
    }))
}

/// Refuses to create or move an account onto an excluded domain, and records it.
///
/// An error rather than a silent skip: every caller here is a push someone else
/// is watching. An IdP that is told "201 Created" while nothing was created
/// keeps believing the account exists, and the divergence only shows up as a
/// user who cannot sign in weeks later.
pub async fn ensure_provision_allowed(
    state: &AppState,
    email: &str,
    via: &str,
    user_agent: Option<String>,
) -> AppResult<()> {
    let domains = allowed_domains(&state.pool, &state.config.allowed_email_domains).await?;
    if allows(&domains, email) {
        return Ok(());
    }

    let domain = domain_of(email);
    crate::audit::record(
        state,
        crate::audit::AuditEvent {
            actor: None,
            action: AUDIT_PROVISION_BLOCKED,
            resource_type: "user",
            resource_id: None,
            detail: json!({ "via": via, "email_domain": domain }),
            ip: None,
            user_agent,
            client_id: None,
        },
    )
    .await;

    Err(AppError::bad_request(match domain {
        Some(domain) => format!("the {domain} email domain is not allowed"),
        None => "this email domain is not allowed".to_string(),
    }))
}

// --- settings ---

/// What the dashboard shows: the effective list, and where it came from.
///
/// The origin is not decoration. A list that comes from the environment cannot
/// be changed here, and one that comes from a settings row survives a restart —
/// an admin editing "the allowlist" without knowing which of the two they are
/// looking at would either be surprised by a restart or waste a change on a value
/// that is already overridden.
async fn get_sign_in_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let actor = current_user(&state, &headers).await?;
    require_admin_role(&actor)?;
    Ok(Json(state_json(&state).await?))
}

#[derive(Debug, Deserialize)]
struct PatchSignInSettings {
    /// `null` (or an absent field) removes the row, so the environment applies
    /// again; `[]` is an explicit "no restriction". Both end up admitting
    /// everyone, but only the first can be undone by unsetting a variable.
    #[serde(default)]
    allowed_email_domains: Option<Vec<String>>,
}

async fn patch_sign_in_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PatchSignInSettings>,
) -> AppResult<Json<Value>> {
    let actor = current_user(&state, &headers).await?;
    require_admin_role(&actor)?;

    let normalized = match &body.allowed_email_domains {
        Some(domains) => Some(
            validate_domains(domains, "allowed_email_domains").map_err(AppError::bad_request)?,
        ),
        None => None,
    };

    // The lockout guard. Saving a list that excludes the acting admin's own
    // domain is refused, because it is the one mistake this setting can make that
    // nothing inside the product can undo: every path back into the dashboard
    // goes through a sign-in the new list would refuse. The environment variable
    // can still do it — that is the operator's own foot-gun, and startup warns
    // about it — but "the admin typed it into a form and locked everyone out"
    // must not be reachable.
    if let Some(domains) = &normalized {
        if !allows(domains, &actor.email) {
            return Err(AppError::bad_request(
                "refusing to save: your own email domain would no longer be allowed, \
                 and no one could sign in to undo it. Add it to the list, or change \
                 your email first.",
            ));
        }
    }

    set_allowed_domains(&state.pool, normalized.as_deref()).await?;
    let effective = state_json(&state).await?;

    // Who this leaves out, recorded rather than merely returned: the guard above
    // covers the acting admin, but an admin who excludes *another* admin has to
    // be able to find that out later, and the account in question cannot tell
    // anyone why it stopped working.
    let excluded_admins = match &normalized {
        Some(_) => excluded_admins(&state.pool).await?,
        None => Vec::new(),
    };

    record(
        &state,
        AuditEvent {
            actor: Some(actor),
            action: AUDIT_SETTING_UPDATE,
            resource_type: "settings",
            resource_id: Some(SETTING_KEY.into()),
            detail: json!({
                "allowed_email_domains": effective["allowed_email_domains"],
                "origin": effective["origin"],
                "excluded_admins": excluded_admins,
            }),
            ip: None,
            user_agent: user_agent(&headers),
            client_id: None,
        },
    )
    .await;

    Ok(Json(effective))
}

async fn state_json(state: &AppState) -> AppResult<Value> {
    let env = &state.config.allowed_email_domains;
    let domains = allowed_domains(&state.pool, env).await?;
    let origin = origin(&state.pool, env).await?;
    Ok(json!({
        "allowed_email_domains": domains,
        "origin": match origin {
            Origin::Setting => "setting",
            Origin::Environment => "environment",
            Origin::Unrestricted => "unrestricted",
        },
    }))
}

/// Warns at startup when no active admin can sign in under the list in force.
///
/// The settings route refuses to save such a list for the acting admin, but the
/// environment can still produce one — and it is the state with the worst failure
/// mode in the whole feature: the dashboard is where the list is edited, and
/// reaching the dashboard requires a sign-in the list refuses. Nothing inside the
/// product can recover from it, so the operator has to be told in the logs, along
/// with the accounts that are stranded.
///
/// No admins at all is not this case: an instance that has not been set up yet
/// has no one to strand, and setup is exempt.
pub async fn warn_if_all_admins_excluded(pool: &PgPool, env_default: &[String]) {
    let domains = match allowed_domains(pool, env_default).await {
        Ok(domains) => domains,
        // Startup must not die over a warning that is not the reason it ran.
        Err(err) => {
            tracing::warn!(error = %err, "could not read the email domain allowlist");
            return;
        }
    };
    if domains.is_empty() {
        return;
    }

    let admins: Vec<(String,)> =
        match sqlx::query_as("SELECT email FROM users WHERE role = 'admin' AND status = 'active'")
            .fetch_all(pool)
            .await
        {
            Ok(admins) => admins,
            Err(err) => {
                tracing::warn!(error = %err, "could not read the admin accounts");
                return;
            }
        };

    let total = admins.len();
    let stranded: Vec<String> = admins
        .into_iter()
        .map(|(email,)| email)
        .filter(|email| !allows(&domains, email))
        .collect();

    // Every admin, not merely one: a single stranded admin is an inconvenience
    // they can see for themselves, while all of them is an instance nobody can
    // sign in to.
    if total > 0 && stranded.len() == total {
        tracing::warn!(
            admins = total,
            stranded_admins = ?stranded,
            allowed_email_domains = ?domains,
            "no active admin can sign in under the email domain allowlist; widen \
             SIGNET_ALLOWED_EMAIL_DOMAINS or the settings row"
        );
    }
}

/// Admins who would no longer be able to sign in under the list in force.
///
/// Active admins only: an already-frozen account cannot sign in either way, so
/// listing it would bury the accounts that actually changed state.
async fn excluded_admins(pool: &PgPool) -> AppResult<Vec<String>> {
    let domains = allowed_domains(pool, &[]).await?;
    let admins: Vec<(String,)> =
        sqlx::query_as("SELECT email FROM users WHERE role = 'admin' AND status = 'active'")
            .fetch_all(pool)
            .await?;
    Ok(admins
        .into_iter()
        .map(|(email,)| email)
        .filter(|email| !allows(&domains, email))
        .collect())
}
