//! Directory source configuration (§4.1) and its typed, validated forms.
//!
//! A source row holds `config JSONB` (kind-specific settings, never secrets) plus
//! `credential_enc` (service-account password, AES-256-GCM) and `ca_cert_pem`
//! (a public certificate, stored as-is). Everything here is validated *before*
//! it is persisted, so a typo in an attribute name or a plaintext LDAP URL is
//! rejected at configuration time rather than surfacing as a broken sync later.

use crate::directory::plan::ScopeFilter;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// Source kinds accepted by the `directory_sources.kind` CHECK constraint.
pub const KINDS: &[&str] = &["ldap", "scim", "http_json"];

/// API-shaped source row. Deliberately excludes `credential_enc` and the
/// certificate body: the admin UI only needs to know whether they are set.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct SourceView {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub kind: String,
    pub enabled: bool,
    pub priority: i32,
    pub config: Value,
    /// True when a credential is stored; the value itself is never returned.
    pub credential_set: bool,
    /// True when a CA certificate is stored.
    pub ca_cert_set: bool,
    pub sync_groups: bool,
    pub interval_minutes: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub const SOURCE_VIEW_COLS: &str = "id, code, name, kind, enabled, priority, config, \
    (credential_enc IS NOT NULL) AS credential_set, (ca_cert_pem IS NOT NULL) AS ca_cert_set, \
    sync_groups, interval_minutes, created_at, updated_at";

/// Full source row, including the encrypted credential. Only the sync engine
/// decrypts this.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SourceRow {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub kind: String,
    pub enabled: bool,
    pub priority: i32,
    pub config: Value,
    pub credential_enc: Option<String>,
    pub ca_cert_pem: Option<String>,
    pub sync_groups: bool,
    pub interval_minutes: Option<i32>,
}

pub const SOURCE_ROW_COLS: &str = "id, code, name, kind, enabled, priority, config, \
    credential_enc, ca_cert_pem, sync_groups, interval_minutes";

pub async fn list(pool: &PgPool) -> AppResult<Vec<SourceView>> {
    let rows = sqlx::query_as::<_, SourceView>(&format!(
        "SELECT {SOURCE_VIEW_COLS} FROM directory_sources ORDER BY priority ASC, code ASC"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_by_code(pool: &PgPool, code: &str) -> AppResult<SourceRow> {
    sqlx::query_as::<_, SourceRow>(&format!(
        "SELECT {SOURCE_ROW_COLS} FROM directory_sources WHERE code = $1"
    ))
    .bind(code)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::not_found(format!("directory source not found: {code}")))
}

pub async fn view_by_code(pool: &PgPool, code: &str) -> AppResult<SourceView> {
    sqlx::query_as::<_, SourceView>(&format!(
        "SELECT {SOURCE_VIEW_COLS} FROM directory_sources WHERE code = $1"
    ))
    .bind(code)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::not_found(format!("directory source not found: {code}")))
}

/// The service-account password / token in the clear, for the lifetime of one
/// sync. Never logged, never returned over HTTP.
///
/// A credential that cannot be decrypted (key rotated, blob corrupt) is an
/// error rather than `None`: silently falling back to an anonymous bind would
/// produce a confusing partial sync.
pub fn decrypt_credential(state: &AppState, row: &SourceRow) -> AppResult<Option<String>> {
    match row.credential_enc.as_deref() {
        None => Ok(None),
        Some(enc) => state.encryptor.decrypt(enc).map(Some).ok_or_else(|| {
            AppError::bad_request("stored directory credential cannot be decrypted")
        }),
    }
}

/// Typed `config` for `kind = 'ldap'` (§7.2).
///
/// `deny_unknown_fields` is on purpose: this blob is hand-written JSON, and a
/// misspelled key (say `externl_id_attribute`) would otherwise be dropped
/// silently, producing a sync that misbehaves for no visible reason.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LdapConfig {
    /// Must be `ldaps://` — see [`LdapConfig::validate`].
    pub url: String,
    pub bind_dn: String,
    pub base_dn: String,
    #[serde(default = "default_user_filter")]
    pub user_filter: String,
    /// Domains this source may own, matched against the email (§7).
    ///
    /// Complements `user_filter` rather than replacing it: `user_filter` is the
    /// server-side coarse narrowing that the preview cannot verify, while this is
    /// the fine filter the preview can report on. Both must pass.
    #[serde(default)]
    pub email_domains: Vec<String>,
    /// Attribute holding the department, e.g. `department` (AD) or
    /// `departmentNumber` (inetOrgPerson). Read only by the scope predicate.
    #[serde(default)]
    pub department_attribute: Option<String>,
    /// Departments this source may own (§7). Empty means no department scoping.
    #[serde(default)]
    pub department_values: Vec<String>,
    /// Attribute holding the login name. Required: guessing it would silently
    /// write wrong usernames. OpenLDAP: `uid`; AD: `sAMAccountName`.
    pub username_attribute: String,
    #[serde(default = "default_email_attribute")]
    pub email_attribute: String,
    /// Falls back to the email local part when absent or empty (§6.2).
    #[serde(default)]
    pub display_name_attribute: Option<String>,
    /// Stable per-entry identifier. Required — see [`LdapConfig::validate`].
    /// OpenLDAP: `entryUUID`; AD: `objectGUID`.
    pub external_id_attribute: String,
    #[serde(default)]
    pub group_base_dn: Option<String>,
    #[serde(default = "default_group_filter")]
    pub group_filter: String,
    #[serde(default = "default_group_member_attribute")]
    pub group_member_attribute: String,
    #[serde(default = "default_group_name_attribute")]
    pub group_name_attribute: String,
    #[serde(default = "default_page_size")]
    pub page_size: i32,
}

/// The documented defaults, `pub(crate)` so the mapping preview can assemble a
/// config from a partially-filled form and still read the same values a sync
/// would for the keys the admin left alone.
pub(crate) fn default_user_filter() -> String {
    "(&(objectClass=person)(mail=*))".into()
}
pub(crate) fn default_email_attribute() -> String {
    "mail".into()
}
fn default_group_filter() -> String {
    "(objectClass=groupOfNames)".into()
}
pub(crate) fn default_group_member_attribute() -> String {
    "member".into()
}
pub(crate) fn default_group_name_attribute() -> String {
    "cn".into()
}
pub(crate) fn default_page_size() -> i32 {
    500
}

/// AD caps paged searches at 1000 by default; asking for more just wastes a
/// round trip.
pub const MAX_PAGE_SIZE: i32 = 1000;

impl LdapConfig {
    /// Parses and validates the `config` blob for a `kind = 'ldap'` source.
    pub fn parse(config: &Value) -> AppResult<Self> {
        let cfg: Self = serde_json::from_value(config.clone())
            .map_err(|e| AppError::bad_request(format!("invalid ldap source config: {e}")))?;
        cfg.validate().map_err(AppError::bad_request)?;
        Ok(cfg)
    }

    /// Validation split out so it is testable without JSON.
    pub fn validate(&self) -> Result<(), String> {
        // D4: LDAPS is mandatory and certificate verification cannot be turned
        // off, so a plaintext `ldap://` endpoint (or `ldapi://`/`ldap+tls://`)
        // is refused outright rather than upgraded.
        if !self.url.trim().to_lowercase().starts_with("ldaps://") {
            return Err(format!(
                "ldap url must use ldaps:// (D4: LDAPS with mandatory certificate \
                 verification); got `{}`",
                self.url
            ));
        }
        if self.bind_dn.trim().is_empty() {
            return Err("bind_dn must not be empty".into());
        }
        if self.base_dn.trim().is_empty() {
            return Err("base_dn must not be empty".into());
        }
        if self.user_filter.trim().is_empty() {
            return Err("user_filter must not be empty".into());
        }
        for (name, value) in [
            ("username_attribute", &self.username_attribute),
            ("email_attribute", &self.email_attribute),
            ("external_id_attribute", &self.external_id_attribute),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{name} must not be empty"));
            }
        }
        if let Some(attr) = &self.display_name_attribute {
            if attr.trim().is_empty() {
                return Err(
                    "display_name_attribute must be empty or a valid attribute name".into(),
                );
            }
        }
        if !(1..=MAX_PAGE_SIZE).contains(&self.page_size) {
            return Err(format!(
                "page_size must be between 1 and {MAX_PAGE_SIZE}, got {}",
                self.page_size
            ));
        }
        // Group config is only meaningful when a group search is configured, so
        // an empty group_base_dn simply disables group sync for the source.
        if self
            .group_base_dn
            .as_deref()
            .is_some_and(|s| s.trim().is_empty())
        {
            return Err("group_base_dn must be omitted or a valid DN".into());
        }
        if self.group_name_attribute.trim().is_empty() {
            return Err("group_name_attribute must not be empty".into());
        }
        if self.group_member_attribute.trim().is_empty() {
            return Err("group_member_attribute must not be empty".into());
        }
        validate_scope(
            &self.email_domains,
            &self.department_values,
            self.department_attribute.as_deref(),
            "department_attribute",
        )?;
        Ok(())
    }

    /// The scope this source may own (§7). Empty when nothing is configured.
    pub fn scope(&self) -> ScopeFilter {
        ScopeFilter {
            email_domains: self.email_domains.clone(),
            department_values: self.department_values.clone(),
        }
    }
}

/// Shared checks for the scope fields of both source kinds, so the same typo is
/// rejected the same way whichever connector is configured.
///
/// Everything here is a save-time check against a mistake the scope predicate
/// would otherwise swallow silently: a filter that matches nobody disables
/// everyone the source manages, and "the config was a typo" must not look like
/// "the directory is empty".
fn validate_scope(
    email_domains: &[String],
    department_values: &[String],
    department_source: Option<&str>,
    department_source_field: &str,
) -> Result<(), String> {
    for domain in email_domains {
        let domain = domain.trim();
        if domain.is_empty() {
            return Err("email_domains must not contain an empty entry".into());
        }
        if domain.contains('@') {
            return Err(format!(
                "email_domains holds domains, not addresses; got `{domain}`"
            ));
        }
        if domain.contains('*') {
            return Err(format!(
                "email_domains has no wildcards — list each domain (subdomains are \
                 matched automatically); got `{domain}`"
            ));
        }
    }
    for value in department_values {
        if value.trim().is_empty() {
            return Err("department_values must not contain an empty entry".into());
        }
    }
    if let Some(source) = department_source {
        if source.trim().is_empty() {
            return Err(format!(
                "{department_source_field} must be omitted or a valid name"
            ));
        }
    }
    // Values with nothing to read them from would match nobody, which is
    // indistinguishable from a directory that has no such departments.
    if !department_values.is_empty() && department_source.is_none() {
        return Err(format!(
            "department_values needs {department_source_field} to read them from"
        ));
    }
    Ok(())
}

/// Validates an admin-supplied CA certificate before it is stored, so a bad PEM
/// fails at save time instead of at the next sync.
pub fn validate_ca_pem(pem: &str) -> Result<(), String> {
    crate::directory::ldap::parse_ca_pem(pem)
        .map(|_| ())
        .map_err(|e| format!("invalid CA certificate: {e}"))
}

/// How the HTTP JSON source authenticates (§13).
///
/// The secret itself never lives in `config`: it is the source's
/// `credential_enc`, decrypted only for the duration of a sync. `Basic` is the
/// one case where a non-secret part exists — the username — and it is kept here
/// so the log-safe view of a source can show which account is used.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpAuth {
    /// No `Authorization` header. Only sensible for an endpoint that is
    /// reachable by network policy alone.
    #[default]
    None,
    /// `Authorization: Bearer <credential>`.
    Bearer,
    /// `Authorization: Basic base64(username:credential)`.
    Basic { username: String },
}

impl HttpAuth {
    /// True when the scheme needs a stored credential. Used for validation, so
    /// a Bearer source without a token is refused at save time rather than
    /// producing an anonymous request that the upstream answers with a 401.
    pub fn requires_credential(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// How the connector walks a multi-page listing (§13).
///
/// Every variant is bounded by `max_pages`: a paginating upstream that never
/// signals its end would otherwise loop forever inside a sync, holding a
/// service-account token.
///
/// Note: serde cannot enforce `deny_unknown_fields` on an internally tagged
/// enum, so a key belonging to another variant (say `next_path` on `page`) is
/// ignored rather than refused. The fields that are read are still all required
/// and range-checked, which is what the connector depends on.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Pagination {
    /// The response is the complete listing.
    #[default]
    None,
    /// `?{param}={start..}` (plus `&{size_param}={size}` when configured).
    /// Stops at `max_pages`, or earlier when the response has no more entries —
    /// but *not* on a short page, since a full page whose length happens to
    /// divide evenly is indistinguishable from the last one, and one wasted
    /// request is cheaper than a truncated directory.
    Page {
        param: String,
        #[serde(default = "default_page_start")]
        start: u32,
        #[serde(default = "default_http_page_size_param")]
        size_param: String,
        #[serde(default = "default_http_page_size")]
        size: u32,
        max_pages: u32,
    },
    /// Opaque cursor: the next value is read from `next_path` in each response.
    /// Stops when that path is absent, null or empty.
    Cursor {
        param: String,
        next_path: String,
        max_pages: u32,
    },
}

fn default_page_start() -> u32 {
    1
}
fn default_http_page_size_param() -> String {
    "page_size".into()
}
fn default_http_page_size() -> u32 {
    200
}

/// Typed `config` for `kind = 'http_json'` (§13).
///
/// Field names are explicit dotted paths rather than a general mapping language:
/// the connector can then report "`data.users` is not an array" instead of
/// failing per entry, and a typo is caught by `deny_unknown_fields` at save time.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpJsonConfig {
    /// Must be `http(s)://` and pass the outbound guard (§12) on every request.
    pub url: String,
    #[serde(default = "default_http_method")]
    pub method: String,
    #[serde(default)]
    pub auth: HttpAuth,
    /// Dotted path to the array of user objects, e.g. `data.users` or `results`.
    pub users_path: String,
    /// Dotted path (relative to each entry) of the stable per-user id. Required:
    /// without it every run would look like every entry is new.
    pub external_id_path: String,
    pub email_path: String,
    #[serde(default)]
    pub username_path: Option<String>,
    #[serde(default)]
    pub display_name_path: Option<String>,
    /// Path to an array of group names. Only read when `sync_groups` is on.
    #[serde(default)]
    pub groups_path: Option<String>,
    /// Domains this source may own, matched against the email (§7).
    #[serde(default)]
    pub email_domains: Vec<String>,
    /// Path (relative to each entry) holding the department. Read only by the
    /// scope predicate.
    #[serde(default)]
    pub department_path: Option<String>,
    /// Departments this source may own (§7). Empty means no department scoping.
    #[serde(default)]
    pub department_values: Vec<String>,
    #[serde(default)]
    pub pagination: Pagination,
}

pub(crate) fn default_http_method() -> String {
    "GET".into()
}

impl HttpJsonConfig {
    pub fn parse(config: &Value) -> AppResult<Self> {
        let cfg: Self = serde_json::from_value(config.clone())
            .map_err(|e| AppError::bad_request(format!("invalid http_json source config: {e}")))?;
        cfg.validate().map_err(AppError::bad_request)?;
        Ok(cfg)
    }

    /// Validation split out so it is testable without JSON.
    pub fn validate(&self) -> Result<(), String> {
        // Only the shape is checked here; routability is re-checked per request
        // (§12: a stored URL must not be trusted, DNS can be re-pointed).
        crate::outbound::validate_shape(&self.url, true)
            .map_err(|e| format!("url is not usable: {e}"))?;
        if self.method.trim().to_uppercase() != "GET" {
            // A body would have to be configured too, and a directory read that
            // needs a POST body is out of scope for v1 — say so rather than
            // silently sending a GET that the upstream rejects.
            return Err(format!(
                "method must be GET, got `{}` (POST bodies are not supported yet)",
                self.method
            ));
        }
        for (name, value) in [
            ("users_path", &self.users_path),
            ("external_id_path", &self.external_id_path),
            ("email_path", &self.email_path),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{name} must not be empty"));
            }
        }
        for (name, value) in [
            ("username_path", &self.username_path),
            ("display_name_path", &self.display_name_path),
            ("groups_path", &self.groups_path),
        ] {
            if value.as_deref().is_some_and(|p| p.trim().is_empty()) {
                return Err(format!("{name} must be omitted or a valid path"));
            }
        }
        if let HttpAuth::Basic { username } = &self.auth {
            if username.trim().is_empty() {
                return Err("auth.username must not be empty for basic auth".into());
            }
        }
        validate_scope(
            &self.email_domains,
            &self.department_values,
            self.department_path.as_deref(),
            "department_path",
        )?;
        match &self.pagination {
            Pagination::None => {}
            Pagination::Page {
                param,
                size_param,
                size,
                max_pages,
                ..
            } => {
                if param.trim().is_empty() {
                    return Err("pagination.param must not be empty".into());
                }
                if size_param.trim().is_empty() {
                    return Err("pagination.size_param must not be empty".into());
                }
                if *size == 0 || *size > MAX_PAGE_SIZE as u32 {
                    return Err(format!(
                        "pagination.size must be between 1 and {MAX_PAGE_SIZE}, got {size}"
                    ));
                }
                validate_max_pages(*max_pages)?;
            }
            Pagination::Cursor {
                param,
                next_path,
                max_pages,
            } => {
                if param.trim().is_empty() {
                    return Err("pagination.param must not be empty".into());
                }
                if next_path.trim().is_empty() {
                    return Err("pagination.next_path must not be empty".into());
                }
                validate_max_pages(*max_pages)?;
            }
        }
        Ok(())
    }

    /// Whether a run of this source owns `users.directory_groups`. Mirrors the
    /// LDAP rule (`sync_groups && group_base_dn.is_some()`): the admin's toggle
    /// decides, and a source with nowhere to read groups from is a no-op.
    pub fn groups_configured(&self) -> bool {
        self.groups_path
            .as_deref()
            .is_some_and(|p| !p.trim().is_empty())
    }

    /// The scope this source may own (§7). Empty when nothing is configured.
    pub fn scope(&self) -> ScopeFilter {
        ScopeFilter {
            email_domains: self.email_domains.clone(),
            department_values: self.department_values.clone(),
        }
    }
}

/// One page walk can never exceed this, whatever the config says: the guard is
/// against a config typo (`max_pages: 100000`) as much as against a hostile
/// upstream.
const MAX_PAGES_LIMIT: u32 = 1000;

fn validate_max_pages(max_pages: u32) -> Result<(), String> {
    if !(1..=MAX_PAGES_LIMIT).contains(&max_pages) {
        return Err(format!(
            "pagination.max_pages must be between 1 and {MAX_PAGES_LIMIT}, got {max_pages}"
        ));
    }
    Ok(())
}

/// The kind-specific half of a source's configuration.
///
/// The engine matches on this instead of re-reading `row.kind` at each step, so
/// "this source is LDAP" is decided once, in one place, and a connector cannot
/// be reached with a config of the wrong shape.
#[derive(Debug, Clone)]
pub enum SourceConfig {
    Ldap(Box<LdapConfig>),
    HttpJson(Box<HttpJsonConfig>),
}

impl SourceConfig {
    /// Parses `config` according to `kind`, refusing kinds with no connector.
    pub fn parse(kind: &str, config: &Value) -> AppResult<Self> {
        match kind {
            "ldap" => Ok(Self::Ldap(Box::new(LdapConfig::parse(config)?))),
            "http_json" => Ok(Self::HttpJson(Box::new(HttpJsonConfig::parse(config)?))),
            other => Err(AppError::bad_request(format!(
                "source kind `{other}` has no connector yet"
            ))),
        }
    }

    /// Which entries this source may own in a sync (§7).
    ///
    /// The department value itself is read per entry by the connector (an LDAP
    /// attribute or a JSON path), so only the values to compare against are
    /// needed here: the filter stays a pure function of the entry.
    pub fn scope(&self) -> ScopeFilter {
        match self {
            Self::Ldap(cfg) => cfg.scope(),
            Self::HttpJson(cfg) => cfg.scope(),
        }
    }

    /// Whether this run owns group membership, per the source's own config.
    pub fn groups_configured(&self, sync_groups: bool) -> bool {
        if !sync_groups {
            return false;
        }
        match self {
            Self::Ldap(cfg) => cfg.group_base_dn.is_some(),
            Self::HttpJson(cfg) => cfg.groups_configured(),
        }
    }

    /// Whether a stored credential is required for this source to work.
    ///
    /// LDAP always requires one: an anonymous bind usually succeeds but quietly
    /// returns a reduced view of the directory, which is far harder to diagnose
    /// than an error at save time. For HTTP JSON it follows the auth scheme, so
    /// an endpoint reachable by network policy alone can be configured without
    /// inventing a secret.
    pub fn requires_credential(&self) -> bool {
        match self {
            Self::Ldap(_) => true,
            Self::HttpJson(cfg) => cfg.auth.requires_credential(),
        }
    }

    /// Short label for the audit detail and log lines.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Ldap(_) => "ldap",
            Self::HttpJson(_) => "http_json",
        }
    }
}

/// Validates the whole source payload, returning the pieces to persist.
///
/// Kept separate from the handlers so the API and the CLI agree on what is
/// acceptable.
pub struct NewSource {
    pub code: String,
    pub name: String,
    pub kind: String,
    pub enabled: bool,
    pub priority: i32,
    pub config: Value,
    pub credential: Option<String>,
    pub ca_cert_pem: Option<String>,
    pub sync_groups: bool,
    pub interval_minutes: Option<i32>,
}

/// Normalizes and validates inputs that are common to create and update.
///
/// `config` is checked against the source `kind` so a `http_json` source with
/// LDAP keys, or vice versa, cannot be stored.
pub fn validate_payload(
    code: &str,
    name: &str,
    kind: &str,
    config: &Value,
    ca_cert_pem: Option<&str>,
    interval_minutes: Option<i32>,
) -> AppResult<()> {
    if code.trim().is_empty() {
        return Err(AppError::bad_request("code must not be empty"));
    }
    if !code
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::bad_request(
            "code may only contain ASCII letters, digits, '-' and '_'",
        ));
    }
    if name.trim().is_empty() {
        return Err(AppError::bad_request("name must not be empty"));
    }
    if !KINDS.contains(&kind) {
        return Err(AppError::bad_request(format!(
            "unsupported kind: {kind} (expected one of {})",
            KINDS.join(", ")
        )));
    }
    match kind {
        "ldap" => {
            LdapConfig::parse(config)?;
        }
        "http_json" => {
            HttpJsonConfig::parse(config)?;
        }
        // The SCIM *pull* connector lands in P5 alongside the inbound push work;
        // accepting and storing its config now would only produce runs that fail
        // at connect time.
        other => {
            return Err(AppError::bad_request(format!(
                "kind `{other}` is not supported yet"
            )))
        }
    }
    if let Some(pem) = ca_cert_pem {
        if kind != "ldap" {
            return Err(AppError::bad_request(
                "ca_cert_pem is only meaningful for kind `ldap`",
            ));
        }
        validate_ca_pem(pem).map_err(AppError::bad_request)?;
    }
    if let Some(mins) = interval_minutes {
        if mins < 1 {
            return Err(AppError::bad_request(
                "interval_minutes must be >= 1 (omit it for manual-only sources)",
            ));
        }
    }
    Ok(())
}

/// Applies the deployment's outbound policy to a source's destination.
///
/// [`HttpJsonConfig::validate`] can only check the URL's shape: it cannot
/// resolve DNS, and it deliberately does not know about
/// `SIGNET_OUTBOUND_ALLOW_PRIVATE`. That flag is what decides whether an
/// intranet destination is a mistake or the point, so the routability check
/// happens here — the same layering `webhooks` uses when a destination is saved.
///
/// The fetch path re-checks on every request (§12): DNS can be re-pointed
/// between saving a source and syncing it, so this is a usability check, not the
/// security boundary.
pub async fn ensure_destination_allowed(state: &AppState, cfg: &SourceConfig) -> AppResult<()> {
    match cfg {
        // LDAP does not use the HTTP client. Its transport is LDAPS-only with
        // mandatory certificate verification, enforced by `LdapConfig::validate`.
        SourceConfig::Ldap(_) => Ok(()),
        SourceConfig::HttpJson(cfg) => {
            crate::outbound::ensure_allowed(&cfg.url, state.config.outbound_allow_private)
                .await
                .map(|_| ())
        }
    }
}

/// Encrypts an optional credential for storage. Whitespace-only is treated as
/// absent, matching how webhook secrets are handled.
pub fn encrypt_credential(state: &AppState, credential: Option<&str>) -> Option<String> {
    credential
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| state.encryptor.encrypt(s))
}
