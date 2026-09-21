//! LDAP bind-through authentication (D2, §8).
//!
//! Directory-provisioned users have no local password: `password_hash` is empty
//! by construction, so the login path must authenticate them somewhere else.
//! This module answers two questions for [`crate::auth::routes::login`]:
//!
//! 1. **Who owns this user?** ([`resolve`]) — the highest-precedence *enabled*
//!    LDAP source linking them, or nobody. Only enabled sources count: a source
//!    an admin switched off must not keep authenticating people.
//! 2. **Are these credentials good?** ([`verify`]) — a single bind as the user's
//!    own DN.
//!
//! Two decisions are load-bearing here and are why the outcome is a three-valued
//! [`Credential`] rather than a `bool`:
//!
//! * **D6, fail closed.** An unreachable directory is *not* a credential
//!   failure. Reporting 401 would tell the user their password is wrong while
//!   the truth is that nobody could check — and it would invite a local-password
//!   fallback for accounts that deliberately have none. It becomes a 503.
//! * **§8.4, no double lockout.** A rejected password is charged to the local
//!   lockout counter only when *we* verified it. Increasing it for an AD
//!   rejection would let the directory's own lockout policy and ours stack,
//!   locking a user out twice over and obscuring which system did it.

use crate::directory::ldap::{bind_as, BindOutcome};
use crate::directory::source::LdapConfig;
use crate::error::AppResult;
use crate::state::AppState;
use sqlx::PgPool;
use uuid::Uuid;

/// Which source will decide whether this user's password is good.
#[derive(Debug)]
pub enum LoginPath {
    /// No enabled LDAP source owns the user: verify the local argon2 hash, which
    /// is also the answer for every SSO/JIT user and the local admin.
    Local,
    /// An enabled LDAP source owns the user: bind against it (§8.2).
    Ldap(Box<BindTarget>),
}

/// Everything one bind-through attempt needs, resolved once per login.
#[derive(Debug)]
pub struct BindTarget {
    /// Recorded in the audit detail on failure, so an operator can tell which
    /// directory made the decision.
    pub source_code: String,
    pub config: LdapConfig,
    pub ca_cert_pem: Option<String>,
    /// The user's own DN, as stored by the sync.
    pub external_dn: String,
}

/// The verdict on a submitted password.
#[derive(Debug, PartialEq, Eq)]
pub enum Credential {
    /// Accepted.
    Valid,
    /// Rejected. `counts_toward_lockout` is false for a directory rejection, so
    /// the local counter is not incremented (§8.4).
    Invalid { counts_toward_lockout: bool },
    /// The directory could not be reached or refused the operation for a reason
    /// other than the password. Fail closed: no local fallback (D6).
    Unavailable { source_code: String, detail: String },
}

/// Finds the enabled LDAP source that owns `user_id`, if any.
///
/// Selection matches the rest of the feature: lowest `priority` wins, `code`
/// breaks ties, so this agrees with `managing_source` and with the sync planner's
/// notion of ownership (§4.1).
///
/// A linked row with no `external_dn` is treated as unmanaged, per §8.3: without
/// a DN there is nothing to bind as, and the run that produced the link cannot
/// have been a successful LDAP sync. Falling through to the local path keeps the
/// failure honest (a directory user has no local hash, so they still get a 401).
pub async fn resolve(state: &AppState, user_id: Uuid) -> AppResult<LoginPath> {
    let Some(row) = owning_source(&state.pool, user_id).await? else {
        return Ok(LoginPath::Local);
    };
    let Some(external_dn) = row
        .external_dn
        .as_deref()
        .filter(|dn| !dn.trim().is_empty())
    else {
        tracing::warn!(
            %user_id,
            source = %row.code,
            "user is linked to an ldap source but has no stored DN; the next sync will fill it"
        );
        return Ok(LoginPath::Local);
    };

    // A source whose config cannot be parsed cannot be bound against. This is a
    // broken installation rather than a user mistake, so it fails loudly instead
    // of quietly sliding into the local path — a directory user has no local
    // password, and silently reporting "invalid password" would send someone to
    // reset a password that does not exist (§8.3, D6).
    let config = LdapConfig::parse(&row.config)?;
    Ok(LoginPath::Ldap(Box::new(BindTarget {
        source_code: row.code,
        config,
        ca_cert_pem: row.ca_cert_pem,
        external_dn: external_dn.to_string(),
    })))
}

/// Checks the submitted password against the directory.
///
/// The service-account credential is *not* used: this binds as the user. It is
/// therefore irrelevant here whether the source has one — an anonymous-capable
/// directory works fine.
pub async fn verify(target: &BindTarget, password: &str) -> Credential {
    // A zero-length password must never reach `simple_bind`. RFC 4513 §5.1.2
    // defines `simple_bind(dn, "")` as an *unauthenticated* bind — a request to
    // be treated as anonymous — and a server that accepts it (OpenLDAP with
    // `allow bind_anon_cred`) answers with success. This function would read
    // that success as a valid credential and hand out a session for whoever owns
    // the DN, which is account takeover with no password at all. The request
    // says "no password", not "anonymous", so it is answered here instead.
    //
    // Only zero length. A whitespace-only password is an attempt at a real
    // password and the directory is the right place to reject it — and this
    // verdict is ours, not the directory's, so it is charged to the local
    // counter like any other password we checked (§8.4).
    if password.is_empty() {
        tracing::info!(
            source = %target.source_code,
            "refusing an empty password without asking the directory"
        );
        return Credential::Invalid {
            counts_toward_lockout: true,
        };
    }

    let started = std::time::Instant::now();
    let outcome = bind_as(
        &target.config,
        &target.external_dn,
        password,
        target.ca_cert_pem.as_deref(),
    )
    .await;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    match outcome {
        BindOutcome::Valid => {
            tracing::info!(
                source = %target.source_code,
                elapsed_ms,
                "directory bind succeeded"
            );
            Credential::Valid
        }
        BindOutcome::InvalidCredentials => {
            // INFO, not WARN: a wrong password is routine, and §8.4 keeps the
            // brute-force signal in the audit log and metrics rather than in a
            // log level an operator is expected to page on.
            tracing::info!(
                source = %target.source_code,
                elapsed_ms,
                "directory bind rejected the credentials"
            );
            Credential::Invalid {
                counts_toward_lockout: false,
            }
        }
        BindOutcome::Unavailable(detail) => {
            tracing::error!(
                source = %target.source_code,
                elapsed_ms,
                error = %detail,
                "directory unavailable during login"
            );
            Credential::Unavailable {
                source_code: target.source_code.clone(),
                detail,
            }
        }
    }
}

/// The one row a login needs from the source, fetched in a single query.
///
/// Deliberately does **not** load `credential_enc`: bind-through authenticates as
/// the user, so the service-account secret never enters the login path at all.
#[derive(Debug, sqlx::FromRow)]
struct OwnedRow {
    code: String,
    config: serde_json::Value,
    ca_cert_pem: Option<String>,
    external_dn: Option<String>,
}

async fn owning_source(pool: &PgPool, user_id: Uuid) -> AppResult<Option<OwnedRow>> {
    let row = sqlx::query_as::<_, OwnedRow>(
        r#"
        SELECT s.code, s.config, s.ca_cert_pem, e.external_dn
        FROM directory_entries e
        JOIN directory_sources s ON s.id = e.source_id
        WHERE e.user_id = $1 AND s.kind = 'ldap' AND s.enabled
        ORDER BY s.priority ASC, s.code ASC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}
