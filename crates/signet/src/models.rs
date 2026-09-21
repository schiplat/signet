use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

pub const USER_COLS: &str = "id, sub, email, username, display_name, password_hash, status, role, \
    mfa_required, must_change_password, totp_enabled, totp_secret, groups, phone, \
    provisioned_via, local_disabled, directory_disabled, scim_disabled, directory_groups, \
    created_at, updated_at, external_id";

/// The rule that turns the three disable flags into `status`, as SQL.
///
/// Each authority records its own intent — `local_disabled` for an admin,
/// `directory_disabled` for "absent from a live directory source",
/// `scim_disabled` for the IdP's `active: false` — and `status` is only ever the
/// answer derived from them. No authority writes `status` on its own; that is
/// what let the sync and SCIM silently undo each other.
///
/// Column-referencing, so an `UPDATE` that sets one flag re-derives `status`
/// from the row's other two without a second query. An `UPDATE` that *changes* a
/// flag cannot use it verbatim — `SET` expressions read the old row, so the new
/// value has to be substituted for that flag by hand. Inserts have no row to
/// reference and use [`status_from_flags`] instead; all three spellings are kept
/// honest by migration `026`'s `users_status_matches_flags` CHECK, which rejects
/// any row where the stored `status` disagrees with the flags, and by
/// `tests/disable_flags.rs`, which walks every flag combination through both the
/// Rust helper and the database.
pub const STATUS_FROM_FLAGS: &str =
    "CASE WHEN local_disabled OR directory_disabled OR scim_disabled \
     THEN 'disabled' ELSE 'active' END";

/// The same rule as [`STATUS_FROM_FLAGS`], for a row that does not exist yet.
pub fn status_from_flags(
    local_disabled: bool,
    directory_disabled: bool,
    scim_disabled: bool,
) -> &'static str {
    if local_disabled || directory_disabled || scim_disabled {
        "disabled"
    } else {
        "active"
    }
}

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

/// Loads a user by id, requiring `status = 'active'`.
///
/// Deliberately a second function rather than a flag on [`user_by_id`]. The
/// status filter is a security boundary: a disabled account must not be handed
/// to anything that mints credentials or accepts one. Keeping it in the name
/// means a call site cannot pick the wrong behaviour by accident, and a
/// reviewer can see which guarantee is in force without opening this file.
///
/// The 401 vs 404 split is the other half of that boundary. [`user_by_id`]
/// reports "not found" because its callers are admin paths that must
/// distinguish a missing row; this one reports "inactive" because its callers
/// are authentication paths, where the caller already proved it knows the id
/// and the only useful thing left to say is that the account is not usable.
pub async fn active_user_by_id(pool: &sqlx::PgPool, id: Uuid) -> crate::error::AppResult<User> {
    sqlx::query_as::<_, User>(&format!(
        "SELECT {USER_COLS} FROM users WHERE id = $1 AND status = 'active'"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| crate::error::AppError::unauthorized("user inactive"))
}

/// The columns a creation path may set on a new `users` row.
///
/// The write-side counterpart of [`USER_COLS`]. `INSERT INTO users` was written
/// out by hand on every creation path, each with its own column list. Because
/// the statement is a string, a column added later without a database default
/// failed at *runtime*, once per path — the same drift `USER_COLS` exists to
/// prevent on the read side.
///
/// The field list is exactly what the local/admin/SCIM paths set, deliberately
/// not every column. Columns only the directory sync or the SSO JIT path write
/// (`local_disabled`, `directory_groups`, `mfa_required`, `provisioned_via`)
/// keep relying on their schema defaults: naming them here would put the
/// default in two places, and the schema would stop being the source of truth.
pub struct NewUser<'a> {
    /// Required columns: `NOT NULL` with no default, so every caller must say.
    pub id: Uuid,
    pub sub: &'a str,
    pub email: &'a str,
    pub display_name: &'a str,
    pub password_hash: &'a str,

    /// Defaulted here because the INSERT names the column, so the database
    /// default is never reached. Values mirror the schema: `role` is `'member'`
    /// (migration `002`), `groups` is `'{}'` (`006`), `must_change_password` is
    /// `FALSE` (`016`).
    pub role: &'a str,
    pub username: Option<&'a str>,
    pub phone: Option<&'a str>,
    pub groups: &'a [String],
    pub external_id: Option<&'a str>,
    pub must_change_password: bool,

    /// The IdP asked for the account to start disabled (SCIM's `active: false`).
    ///
    /// The creation paths used to set `status` itself, which is the thing that
    /// let an authority's intent be overwritten by whoever ran next. They now
    /// state their intent as a flag and `insert_user` derives `status` from the
    /// flags, so an insert cannot ask for a combination the schema rejects.
    pub scim_disabled: bool,
}

impl<'a> NewUser<'a> {
    /// A new account with the defaults above; callers override what they set.
    ///
    /// Borrows the required values rather than taking them, so a caller that
    /// still needs the email for its audit entry does not have to clone it.
    /// `password_hash` may be empty: the SSO JIT and sync paths create accounts
    /// with no local password, and `''` is what they store.
    pub fn new(
        id: Uuid,
        sub: &'a str,
        email: &'a str,
        display_name: &'a str,
        password_hash: &'a str,
    ) -> Self {
        Self {
            id,
            sub,
            email,
            display_name,
            password_hash,
            role: "member",
            username: None,
            phone: None,
            groups: &[],
            external_id: None,
            must_change_password: false,
            scim_disabled: false,
        }
    }
}

/// Inserts a new user and returns the stored row.
///
/// Returns the raw [`sqlx::Error`] rather than an `AppResult` on purpose: a
/// unique violation has to be described differently per surface, and folding
/// the mapping in here would force one vocabulary on all of them. SCIM answers
/// `userName already exists` in SCIM's own spelling, the admin API answers
/// `username already exists`, and the sync engine answers 409 with re-run
/// advice. Each caller keeps its `map_err`, and this function owns only what
/// they genuinely share — the column list and the defaults.
///
/// Generic over the executor so the bootstrap path can pass its transaction
/// (`&mut *tx`) exactly as it passes a pool.
pub async fn insert_user<'e, E>(executor: E, new: &NewUser<'_>) -> Result<User, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as::<_, User>(&format!(
        r#"
        INSERT INTO users (id, sub, email, username, display_name, password_hash, status, role,
                           groups, phone, external_id, must_change_password, scim_disabled,
                           created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
        RETURNING {USER_COLS}
        "#
    ))
    .bind(new.id)
    .bind(new.sub)
    .bind(new.email)
    .bind(new.username)
    .bind(new.display_name)
    .bind(new.password_hash)
    // Derived, never taken from the caller: the only flag a creation path can
    // set is SCIM's, and the other two start clear because a brand new row has
    // no admin intent and no directory claim yet.
    .bind(status_from_flags(false, false, new.scim_disabled))
    .bind(new.role)
    .bind(new.groups)
    .bind(new.phone)
    .bind(new.external_id)
    .bind(new.must_change_password)
    .bind(new.scim_disabled)
    .bind(new.external_id)
    .bind(new.must_change_password)
    .fetch_one(executor)
    .await
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
    /// "Absent from a live directory source": the sync's disable intent, held
    /// separately so a SCIM `active: true` cannot release it (migration `026`).
    pub directory_disabled: bool,
    /// The IdP's `active: false`, held separately so a directory re-sync cannot
    /// release it (migration `026`).
    pub scim_disabled: bool,
    /// Groups sourced from the directory, kept apart from the locally-managed
    /// `groups` column so sync replaces only its own membership.
    pub directory_groups: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// The upstream identifier: SCIM's `externalId`, or the LDAP directory entry
    /// a sync provisioned this account from. Unique when set, and nullable
    /// because local, admin and JIT-created accounts have no upstream.
    ///
    /// Not public output — `PublicUser` is what reaches clients — so it is
    /// skipped when a `User` is serialized, alongside the credential fields.
    #[serde(skip_serializing)]
    pub external_id: Option<String>,
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
