//! The LDAP connector (§7).
//!
//! Two things are deliberately non-negotiable here:
//!
//! * **LDAPS with mandatory verification (D4).** `LdapConfig::validate` refuses a
//!   plaintext `ldap://` URL, and this module always installs an explicit rustls
//!   [`ClientConfig`] built from the system roots plus any imported self-signed
//!   CA. `ldap3`'s "skip verification" switch is never exposed, so there is no
//!   way to configure a connection that cannot detect a man in the middle.
//! * **Escaping is irrelevant, by construction.** Filters come from the source
//!   configuration, never from user input, so no value is ever interpolated into
//!   a filter — the injection surface §7.2 warns about does not exist rather
//!   than being escaped.
//!
//! The connector only *reads*. It hands the engine a normalized
//! [`UpstreamUser`] list and never touches the database.

use crate::directory::plan::UpstreamUser;
use crate::directory::source::LdapConfig;
use crate::error::{AppError, AppResult};
use ldap3::adapters::PagedResults;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// §8.3 prescribes 5s connect / 10s operation for the login bind path. A sync
/// reads many pages, so the per-operation budget is more generous — but both
/// timeouts are mandatory, because an LDAP server that stops answering must not
/// pin a task forever.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OP_TIMEOUT: Duration = Duration::from_secs(30);

/// A login is on someone's critical path, so its per-operation budget is
/// tighter than a sync's — §8.3's 10s.
const LOGIN_OP_TIMEOUT: Duration = Duration::from_secs(10);

/// LDAP result code for `invalidCredentials` (RFC 4511 §A.1). The only failure
/// that means "wrong password" rather than "the directory is unhappy", so it is
/// the only one the login path may report as a credential error.
const RC_INVALID_CREDENTIALS: u32 = 49;

/// Outcome of a bind-through credential check (§8.2).
///
/// The three cases must stay distinct: the first is a 401, the second is a 401
/// that is *not* charged against the local lockout counter (§8.4), and the third
/// is a 503 that must never fall back to the local password (D6).
#[derive(Debug)]
pub enum BindOutcome {
    Valid,
    InvalidCredentials,
    /// Unreachable, timed out, TLS failure, or any other server-side error.
    Unavailable(String),
}

/// Verifies a user's password by binding as their own DN.
///
/// `dn` comes from the stored `directory_entries.external_dn`, so a login is a
/// single bind rather than "search as the service account, then bind" — no
/// search privilege is needed on the login path and there is one round trip
/// fewer (§8.2).
///
/// Never propagates an error: every failure mode is a documented outcome, and
/// the caller decides between 401 and 503. The password is used for this bind
/// only — not stored, not logged, not cached.
pub async fn bind_as(
    cfg: &LdapConfig,
    dn: &str,
    password: &str,
    ca_pem: Option<&str>,
) -> BindOutcome {
    let tls = match build_client_config(ca_pem) {
        Ok(tls) => tls,
        Err(e) => {
            tracing::error!(error = %e, url = %cfg.url, "ldap bind-through TLS setup failed");
            return BindOutcome::Unavailable(e);
        }
    };
    let settings = LdapConnSettings::new()
        .set_conn_timeout(CONNECT_TIMEOUT)
        .set_config(tls);

    let (conn, mut ldap) = match LdapConnAsync::with_settings(settings, &cfg.url).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(error = %e, url = %cfg.url, "ldap bind-through connection failed");
            return BindOutcome::Unavailable(e.to_string());
        }
    };
    ldap3::drive!(conn);
    ldap.with_timeout(LOGIN_OP_TIMEOUT);

    let outcome = match ldap.simple_bind(dn, password).await {
        Ok(res) => match res.success() {
            Ok(_) => BindOutcome::Valid,
            Err(ldap3::LdapError::LdapResult { result }) if result.rc == RC_INVALID_CREDENTIALS => {
                BindOutcome::InvalidCredentials
            }
            Err(e) => BindOutcome::Unavailable(e.to_string()),
        },
        Err(e) => BindOutcome::Unavailable(e.to_string()),
    };

    // Always close the connection: a login burst must not leak sockets into the
    // directory, and an unbound-by-timeout session would linger server-side.
    if let Err(e) = ldap.unbind().await {
        tracing::debug!(error = %e, "ldap bind-through unbind failed");
    }
    outcome
}

/// Parses one or more `CERTIFICATE` blocks. Exposed so the admin API can reject
/// a bad certificate when it is saved rather than at the next sync.
pub fn parse_ca_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse PEM data: {e}"))?;
    if certs.is_empty() {
        return Err("no CERTIFICATE block found".into());
    }
    Ok(certs)
}

/// Builds the rustls configuration for an LDAPS connection.
///
/// Trust is *additive*: the system roots plus, when supplied, the source's
/// self-signed CA. An imported CA therefore extends trust rather than replacing
/// it, so the same code serves a public-CA cloud LDAP and an on-premises
/// directory with an internal CA.
///
/// A [`ClientConfig`] is always supplied to `ldap3`, even without a custom CA,
/// so that the crypto provider is chosen here rather than inherited from
/// whichever provider happens to be installed process-wide.
pub fn build_client_config(ca_pem: Option<&str>) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();

    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        // Partial failures are routine on macOS; only a completely empty store
        // is fatal, and only when there is no explicit CA to fall back on.
        tracing::debug!(
            count = native.errors.len(),
            "some system root certificates could not be loaded"
        );
    }
    let mut native_added = 0usize;
    for cert in native.certs {
        if roots.add(cert).is_ok() {
            native_added += 1;
        }
    }

    let mut custom_added = 0usize;
    if let Some(pem) = ca_pem {
        for cert in parse_ca_pem(pem)? {
            roots
                .add(cert)
                .map_err(|e| format!("cannot trust the supplied CA certificate: {e}"))?;
            custom_added += 1;
        }
    }

    if native_added == 0 && custom_added == 0 {
        return Err(
            "no trusted CA certificates available (system store empty, none supplied)".into(),
        );
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("cannot build the TLS configuration: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Canonical string form of a 16-byte GUID as returned by AD's `objectGUID`.
///
/// The MS-DTYP GUID layout stores the first three fields little-endian and the
/// last eight bytes as-is, which is *not* the byte order of the printed string.
/// Getting this wrong yields a stable-looking but wrong identifier, and every
/// re-run would then be unable to match the accounts it created — hence the
/// dedicated unit test pinning the field order.
pub fn format_guid(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 16 {
        return None;
    }
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    Some(format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
}

fn upstream_error(operation: &'static str, e: ldap3::result::LdapError) -> AppError {
    tracing::error!(error = %e, operation, "ldap operation failed");
    AppError::upstream(format!("{operation}: {e}"))
}

/// One directory entry with case-insensitive attribute lookup.
///
/// LDAP attribute names are case-insensitive, and servers do not reliably echo
/// the casing the client requested (`samaccountname` may come back as
/// `sAMAccountName`). Normalizing once per entry means a config attribute name
/// works regardless of who canonicalized it.
///
/// Public because the mapping preview ([`crate::directory::mapping`]) builds the
/// same value from a pasted LDIF entry: an admin checking their attribute names
/// must be told exactly what the sync would read, which means going through this
/// type rather than reimplementing attribute lookup.
pub struct RawEntry {
    pub dn: String,
    pub text: HashMap<String, Vec<String>>,
    /// Single binary value per attribute; only ever used for identifiers.
    pub binary: HashMap<String, Vec<u8>>,
    /// Lowercased key → the spelling the entry actually used.
    ///
    /// Lookup must be case-insensitive, but *display* must not be lowercased:
    /// showing an admin `entryuuid` and `objectclass` when their directory says
    /// `entryUUID` and `objectClass` makes the attribute list look like it came
    /// from somewhere other than their directory, which is the one thing this
    /// list exists to prove.
    labels: HashMap<String, String>,
}

impl RawEntry {
    pub fn new(entry: SearchEntry) -> Self {
        Self::from_parts(
            entry.dn,
            entry.attrs.into_iter().collect(),
            entry.bin_attrs.into_iter().collect(),
        )
    }

    /// Builds an entry from already-separated text and binary attributes.
    ///
    /// Shared by the live search path and the LDIF parser so both normalize keys
    /// (and pick the first binary value) identically — the preview must not
    /// disagree with a sync about what an entry contains.
    pub fn from_parts(
        dn: String,
        text: Vec<(String, Vec<String>)>,
        binary: Vec<(String, Vec<Vec<u8>>)>,
    ) -> Self {
        let mut labels: HashMap<String, String> = HashMap::new();
        let mut remember = |key: &str| {
            labels
                .entry(key.to_lowercase())
                .or_insert_with(|| key.to_string());
        };
        let text = text
            .into_iter()
            .map(|(k, v)| {
                remember(&k);
                (k.to_lowercase(), v)
            })
            .collect();
        let binary = binary
            .into_iter()
            .filter_map(|(k, v)| {
                remember(&k);
                v.into_iter().next().map(|first| (k.to_lowercase(), first))
            })
            .collect();
        Self {
            dn,
            text,
            binary,
            labels,
        }
    }

    /// First non-empty text value of `attr`.
    pub fn text(&self, attr: &str) -> Option<String> {
        self.all_text(attr).into_iter().next()
    }

    /// All non-empty text values of `attr`, trimmed.
    pub fn all_text(&self, attr: &str) -> Vec<String> {
        self.text
            .get(&attr.to_lowercase())
            .map(|values| {
                values
                    .iter()
                    .map(|v| v.trim())
                    .filter(|v| !v.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The stable identifier for an entry, whatever shape the directory returns
    /// it in: a text UUID (`entryUUID`, `ipaUniqueID`) or the 16-byte binary AD
    /// `objectGUID`.
    pub fn external_id(&self, attr: &str) -> Option<String> {
        if let Some(value) = self.text(attr) {
            return Some(value);
        }
        let bytes = self.binary.get(&attr.to_lowercase())?;
        // Not a 16-byte GUID: hex is the only lossless rendering available.
        Some(format_guid(bytes).unwrap_or_else(|| data_encoding::HEXLOWER.encode(bytes)))
    }

    /// Attribute names present on the entry, for diagnostics only.
    ///
    /// Spelled the way the entry did: an error about a missing
    /// `external_id_attribute` is only actionable if the names listed next to it
    /// match what the directory (or the paste) actually contains.
    pub fn available_attributes(&self) -> String {
        let mut names: Vec<&str> = self
            .text
            .keys()
            .chain(self.binary.keys())
            .map(|key| self.label(key))
            .collect();
        names.sort_unstable();
        names.dedup();
        names.join(", ")
    }

    /// Every attribute name with how many values it carries, sorted.
    ///
    /// This is what the mapping preview renders as the clickable list of
    /// attribute targets, so it reports counts rather than values: `memberOf`
    /// with 7 values is a different thing from one with a single value, and the
    /// admin needs to see which.
    pub fn attribute_summary(&self) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = Vec::new();
        for (key, values) in &self.text {
            let non_empty = values.iter().filter(|v| !v.trim().is_empty()).count();
            if non_empty > 0 {
                out.push((self.label(key).to_string(), non_empty));
            }
        }
        for key in self.binary.keys() {
            out.push((self.label(key).to_string(), 1));
        }
        out.sort();
        out
    }

    /// The original spelling of a lowercased attribute key.
    ///
    /// Every key in `text` and `binary` passed through the same normalization, so
    /// the fallback is unreachable; it exists only because the lookup must return
    /// *something* borrowed from `self`, which is why both references share a
    /// lifetime.
    fn label<'a>(&'a self, key: &'a str) -> &'a str {
        self.labels.get(key).map(String::as_str).unwrap_or(key)
    }
}

/// Builds the normalized upstream user for one entry.
///
/// The single place an LDAP entry is converted into the fields the sync manages.
/// `fetch_users` and the mapping preview both call it, so a preview cannot
/// promise something the sync would not do (§13).
pub fn upstream_from_entry(
    cfg: &LdapConfig,
    entry: &RawEntry,
    membership: &HashMap<String, Vec<String>>,
) -> AppResult<UpstreamUser> {
    let Some(external_id) = entry.external_id(&cfg.external_id_attribute) else {
        // A wrong `external_id_attribute` would otherwise produce a run that
        // silently creates nobody, so abort with the attribute names that *are*
        // present. The search is drained before any write, so this leaves the
        // local database untouched.
        return Err(AppError::upstream(format!(
            "entry `{}` has no value for external_id_attribute `{}`; \
             attributes present: {}",
            entry.dn,
            cfg.external_id_attribute,
            entry.available_attributes()
        )));
    };

    Ok(UpstreamUser {
        external_id,
        external_dn: Some(entry.dn.clone()),
        email: entry.text(&cfg.email_attribute).unwrap_or_default(),
        username: entry.text(&cfg.username_attribute),
        display_name: cfg
            .display_name_attribute
            .as_deref()
            .and_then(|attr| entry.text(attr)),
        // Only read when the scope predicate asks for it; keeping it on the
        // normalized entry rather than inside the planner is what lets the
        // mapping preview evaluate the same predicate against a sample (§13).
        department: cfg
            .department_attribute
            .as_deref()
            .and_then(|attr| entry.text(attr)),
        groups: membership
            .get(&entry.dn.to_lowercase())
            .cloned()
            .unwrap_or_default(),
    })
}

/// A connected, bound LDAP session.
pub struct LdapConnector {
    ldap: Ldap,
    cfg: LdapConfig,
}

impl LdapConnector {
    /// Connects over LDAPS and binds as the service account.
    ///
    /// `password` is used for this bind only: never stored, never logged, never
    /// cached (§12).
    pub async fn connect(
        cfg: &LdapConfig,
        password: Option<&str>,
        ca_pem: Option<&str>,
    ) -> AppResult<Self> {
        let tls = build_client_config(ca_pem).map_err(AppError::bad_request)?;
        let settings = LdapConnSettings::new()
            .set_conn_timeout(CONNECT_TIMEOUT)
            .set_config(tls);

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &cfg.url)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, url = %cfg.url, "ldap connection failed");
                AppError::upstream(format!("cannot connect to {}: {e}", cfg.url))
            })?;
        ldap3::drive!(conn);
        ldap.with_timeout(OP_TIMEOUT);

        // Refused rather than defaulted to an empty string: `simple_bind(dn, "")`
        // is an unauthenticated bind (RFC 4513 §5.1.2), and `requires_credential`
        // keeps an LDAP source from being saved without one precisely because a
        // server that accepts it answers with success while quietly returning a
        // reduced view of the directory. Reaching here with nothing to send means
        // the stored credential is missing or empty, which is a broken source and
        // must not become an anonymous search.
        let Some(password) = password.filter(|p| !p.is_empty()) else {
            return Err(AppError::bad_request(
                "this ldap source has no service-account credential; refusing an \
                 anonymous bind",
            ));
        };

        ldap.simple_bind(&cfg.bind_dn, password)
            .await
            .map_err(|e| upstream_error("ldap bind", e))?
            .success()
            .map_err(|e| upstream_error("ldap bind rejected", e))?;

        tracing::debug!(url = %cfg.url, "ldap bound");
        Ok(Self {
            ldap,
            cfg: cfg.clone(),
        })
    }

    /// Reads the full user set, resolving group membership when configured.
    ///
    /// The whole set is materialized before returning: the engine plans against a
    /// complete snapshot, so a failure partway through the search must not leave
    /// a partially applied sync behind.
    pub async fn fetch_users(&mut self, limit: Option<usize>) -> AppResult<Vec<UpstreamUser>> {
        let cfg = self.cfg.clone();
        // Groups are read first: the search borrows the connection, and the
        // DN→groups map is needed while walking the user entries.
        let membership = match cfg.group_base_dn.as_deref() {
            Some(_) => self.fetch_group_membership().await?,
            None => HashMap::new(),
        };

        let mut attrs: Vec<String> = vec![
            cfg.username_attribute.clone(),
            cfg.email_attribute.clone(),
            cfg.external_id_attribute.clone(),
        ];
        if let Some(attr) = &cfg.display_name_attribute {
            attrs.push(attr.clone());
        }
        let attr_refs: Vec<&str> = attrs.iter().map(String::as_str).collect();

        let mut out = Vec::new();
        let mut stream = self
            .ldap
            .streaming_search_with(
                PagedResults::new(cfg.page_size),
                &cfg.base_dn,
                Scope::Subtree,
                &cfg.user_filter,
                attr_refs,
            )
            .await
            .map_err(|e| upstream_error("ldap user search", e))?;

        while let Some(entry) = stream
            .next()
            .await
            .map_err(|e| upstream_error("ldap user search", e))?
        {
            if entry.is_ref() {
                continue;
            }
            let entry = RawEntry::new(SearchEntry::construct(entry));
            out.push(upstream_from_entry(&cfg, &entry, &membership)?);

            if limit.is_some_and(|max| out.len() >= max) {
                break;
            }
        }

        // A truncated search stream means the result set is incomplete, which for
        // a reconciliation pass would look like "these users were deleted".
        stream
            .finish()
            .await
            .success()
            .map_err(|e| upstream_error("ldap user search", e))?;

        if limit.is_some_and(|max| out.len() >= max) {
            tracing::warn!(
                limit = limit.unwrap_or_default(),
                "ldap user search stopped at the configured limit"
            );
        }

        tracing::debug!(count = out.len(), "ldap users fetched");
        Ok(out)
    }

    /// Maps a group member DN (lowercased) to the names of the groups listing it.
    ///
    /// v1 always resolves membership from the group side (`member`,
    /// `uniqueMember`, …) rather than reading `memberOf` from the user entry.
    /// `memberOf` yields *DNs*, so it would need this same group search to
    /// produce the group *names* the OIDC `groups` claim carries — doing it once
    /// from the group side is both uniform for AD and OpenLDAP and consistent
    /// with what gets written to `users.directory_groups`.
    async fn fetch_group_membership(&mut self) -> AppResult<HashMap<String, Vec<String>>> {
        let cfg = self.cfg.clone();
        let base_dn = cfg
            .group_base_dn
            .clone()
            .expect("caller checked group_base_dn");
        let attrs = [
            cfg.group_name_attribute.as_str(),
            cfg.group_member_attribute.as_str(),
        ];

        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        let mut stream = self
            .ldap
            .streaming_search_with(
                PagedResults::new(cfg.page_size),
                &base_dn,
                Scope::Subtree,
                &cfg.group_filter,
                attrs,
            )
            .await
            .map_err(|e| upstream_error("ldap group search", e))?;

        let mut groups_seen = 0usize;
        while let Some(entry) = stream
            .next()
            .await
            .map_err(|e| upstream_error("ldap group search", e))?
        {
            if entry.is_ref() {
                continue;
            }
            let entry = RawEntry::new(SearchEntry::construct(entry));
            let Some(name) = entry.text(&cfg.group_name_attribute) else {
                continue;
            };
            groups_seen += 1;
            for member in entry.all_text(&cfg.group_member_attribute) {
                map.entry(member.to_lowercase())
                    .or_default()
                    .push(name.clone());
            }
        }
        stream
            .finish()
            .await
            .success()
            .map_err(|e| upstream_error("ldap group search", e))?;

        tracing::debug!(
            groups = groups_seen,
            members = map.len(),
            "ldap groups fetched"
        );
        Ok(map)
    }

    /// Closes the connection. Failures are logged, not propagated: the sync has
    /// already finished by the time this runs.
    pub async fn unbind(mut self) {
        if let Err(e) = self.ldap.unbind().await {
            tracing::debug!(error = %e, "ldap unbind failed");
        }
    }
}
