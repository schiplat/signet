use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

pub const USER_COLS: &str = "id, sub, email, username, display_name, password_hash, status, role, \
    mfa_required, must_change_password, totp_enabled, totp_secret, groups, phone, \
    provisioned_via, local_disabled, directory_groups, created_at, updated_at";

/// [`USER_COLS`] qualified with a table alias, for queries that join `users`
/// with another table.
///
/// A bare list cannot be used there: `sessions`, `oauth_authorization_codes` and
/// friends also have `id`/`created_at`, so an unqualified `SELECT id` is
/// ambiguous. Aliasing must go through this function rather than a second
/// hand-written list — a copy of the column list is exactly what silently
/// breaks the moment a column is added to `User` (the row then fails to map
/// with `no column found for name: ...`, which surfaces as a 500).
pub fn user_cols_with(alias: &str) -> String {
    USER_COLS
        .split(',')
        .map(|col| format!("{alias}.{}", col.trim()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Normalizes a username for storage and lookup: trimmed, lowercased, and
/// mapped to `None` when empty so email-only accounts keep a NULL username.
pub fn normalize_username(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .map(str::to_lowercase)
        .filter(|s| !s.is_empty())
}

/// The value of the OIDC `groups` claim: locally-managed groups plus
/// directory-sourced ones.
///
/// The two live in separate columns on purpose (docs/directory-sync.md §6.5), so
/// that a sync replacing `directory_groups` cannot clobber a group an admin
/// assigned by hand. Clients only ever see one list, so the claim is their union.
///
/// Deduplicated and sorted: the claim is emitted on every token and userinfo
/// response, and a client that diffs it (many do, to drive authorization) must
/// not see spurious changes when the underlying `TEXT[]` order differs — which it
/// does, since Postgres does not preserve array order through an `UPDATE`.
pub fn effective_groups(groups: &[String], directory_groups: &[String]) -> Vec<String> {
    let mut out: Vec<String> = groups
        .iter()
        .chain(directory_groups.iter())
        .map(|g| g.trim())
        .filter(|g| !g.is_empty())
        .map(str::to_string)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Loads a single user by id.
///
/// Exposed for the directory sync engine, which resolves an audit actor from a
/// stored id rather than from an HTTP request.
pub async fn user_by_id(pool: &sqlx::PgPool, id: Uuid) -> crate::error::AppResult<User> {
    sqlx::query_as::<_, User>(&format!("SELECT {USER_COLS} FROM users WHERE id = $1"))
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| crate::error::AppError::not_found("user not found"))
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    pub sub: String,
    pub email: String,
    pub username: Option<String>,
    pub display_name: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub status: String,
    pub role: String,
    pub mfa_required: bool,
    pub must_change_password: bool,
    pub totp_enabled: bool,
    #[serde(skip_serializing)]
    pub totp_secret: Option<String>,
    pub groups: Vec<String>,
    pub phone: Option<String>,
    /// How the account was first created (`sso_jit`, …). `None` = local/admin/SCIM/legacy.
    pub provisioned_via: Option<String>,
    /// Local disable intent, kept separate from the upstream status so the next
    /// directory sync cannot silently re-enable an account an admin disabled.
    /// Only an explicit admin enable clears it (migration `024`).
    pub local_disabled: bool,
    /// Groups sourced from the directory, kept apart from the locally-managed
    /// `groups` column so sync replaces only its own membership.
    pub directory_groups: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClientApp {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret_hash: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub pkce_required: bool,
    pub scopes: Vec<String>,
    pub enabled: bool,
    pub ip_allowlist_enabled: bool,
    pub allowed_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicUser {
    pub id: Uuid,
    pub sub: String,
    pub email: String,
    pub username: Option<String>,
    pub display_name: String,
    pub status: String,
    pub role: String,
    /// Convenience flag; true when role == "admin".
    pub is_admin: bool,
    pub mfa_required: bool,
    pub must_change_password: bool,
    pub totp_enabled: bool,
    pub groups: Vec<String>,
    pub phone: Option<String>,
    /// First-create source (`sso_jit`, …). `None` for local/admin/SCIM/legacy.
    pub provisioned_via: Option<String>,
    /// True when a directory source owns this user's directory-managed
    /// attributes, i.e. the values cannot be edited locally.
    pub local_disabled: bool,
    /// Groups sourced from the directory (read-only locally).
    pub directory_groups: Vec<String>,
    pub created_at: DateTime<Utc>,
}

impl From<User> for PublicUser {
    fn from(u: User) -> Self {
        let is_admin = u.role == "admin";
        Self {
            id: u.id,
            sub: u.sub,
            email: u.email,
            username: u.username,
            display_name: u.display_name,
            status: u.status,
            role: u.role,
            is_admin,
            mfa_required: u.mfa_required,
            must_change_password: u.must_change_password,
            totp_enabled: u.totp_enabled,
            groups: u.groups,
            phone: u.phone,
            provisioned_via: u.provisioned_via,
            local_disabled: u.local_disabled,
            directory_groups: u.directory_groups,
            created_at: u.created_at,
        }
    }
}
