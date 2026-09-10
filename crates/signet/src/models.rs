use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

pub const USER_COLS: &str = "id, sub, email, username, display_name, password_hash, status, role, \
    mfa_required, must_change_password, totp_enabled, totp_secret, groups, phone, \
    provisioned_via, created_at, updated_at";

/// Normalizes a username for storage and lookup: trimmed, lowercased, and
/// mapped to `None` when empty so email-only accounts keep a NULL username.
pub fn normalize_username(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .map(str::to_lowercase)
        .filter(|s| !s.is_empty())
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
            created_at: u.created_at,
        }
    }
}
