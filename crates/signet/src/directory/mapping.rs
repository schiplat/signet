//! The mapping preview (§13): what would this mapping read, and what would be
//! written?
//!
//! Configuring a source means answering the same six questions for either kind —
//! which entries are users, and where the external id, email, username, display
//! name and groups live. The dashboard renders those six rows from one shared
//! table, so this module reports its verdict in kind-neutral row ids
//! ([`ROW_EXTERNAL_ID`] and friends) and lets each connector do the talking.
//!
//! Everything here is **pure**: no database, no network. That is what makes the
//! preview trustworthy — [`preview`] takes a sample the admin pasted, runs it
//! through the *same* extraction and normalization the sync uses
//! ([`ldap::upstream_from_entry`], [`http_json::to_upstream`],
//! [`plan::ManagedFields::from_upstream`]), and can therefore not disagree with a
//! run. A preview that reimplemented the mapping would be worse than no preview:
//! it would be believed.

use crate::directory::http_json::{self};
use crate::directory::ldap::{self, RawEntry};
use crate::directory::ldif;
use crate::directory::plan::{self, ScopeFilter, UpstreamUser};
use crate::directory::source::{HttpJsonConfig, LdapConfig};
use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Row ids shared with the dashboard's mapping table. Changing one of these
/// breaks the per-row error display, so they are constants rather than inline
/// strings on both sides.
pub const ROW_SCOPE: &str = "scope";
pub const ROW_EXTERNAL_ID: &str = "external_id";
pub const ROW_EMAIL: &str = "email";
pub const ROW_USERNAME: &str = "username";
pub const ROW_DISPLAY_NAME: &str = "display_name";
pub const ROW_GROUPS: &str = "groups";

// The sample is analysed *in full* and displayed *one page at a time*, and the
// two are kept strictly apart.
//
// They used to be the same number, which made the verdicts lie. The counters
// stopped at the first 50 entries while `entry_count` reported all of them, so a
// 120-entry sample rendered "120 entries" in the header and "10/50 entries" on
// the display_name row — two denominators in one panel, and the smaller one was
// wrong in the reassuring direction: an attribute in 8% of the directory read as
// 20%. Since the whole point of the count is to talk an admin out of picking a
// patchy attribute, understating the patchiness defeats the feature.
//
// Analysis is cheap (one pass, no I/O) and `MAX_SAMPLE_BYTES` bounds it, so the
// cost of being complete is negligible next to the cost of being wrong.

/// How many normalized rows one page of the response carries.
const PREVIEW_PAGE: usize = 25;
/// Cap on a pasted sample, enforced before parsing.
pub const MAX_SAMPLE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewRequest {
    pub kind: String,
    pub config: Value,
    /// Pasted sample: a JSON document (`http_json`) or LDIF text (`ldap`).
    pub sample: Option<String>,
    /// The source's toggle, when known. Only used to warn about a group path
    /// that no run would ever write.
    #[serde(default)]
    pub sync_groups: Option<bool>,
    /// Which page of normalized rows to return, counted in source entries.
    ///
    /// Paging exists so a large paste does not have to be returned in one
    /// response, not to bound the analysis: every entry is examined whatever this
    /// is set to, which is what keeps the per-row counters true.
    #[serde(default)]
    pub offset: Option<usize>,
}

// ─── The mapping-relevant slice of a config ───────────────────────────────
//
// The preview reads *only* the keys that say where each field comes from. It
// never fetches anything (that is the whole point — see the module docs), so the
// connection settings (`url`, `bind_dn`, the credential, timeouts, pagination)
// are irrelevant to it and are deliberately not required.
//
// This matters for more than tidiness. Requiring the full config meant the
// preview refused to run while the admin was still filling the form in, so the
// attribute list for a pasted LDIF — which depends on nothing but the paste —
// stayed hidden until the connection was complete, which is exactly backwards
// for the one panel whose job is to help fill the form in. Unknown keys are
// therefore ignored rather than refused, and *saving* remains the place where
// the whole config is validated strictly (`SourceConfig::parse`).

/// The `ldap` keys the mapping reads. `None` means "not filled in yet".
#[derive(Debug, Default, Deserialize)]
struct LdapMapping {
    base_dn: Option<String>,
    user_filter: Option<String>,
    username_attribute: Option<String>,
    email_attribute: Option<String>,
    display_name_attribute: Option<String>,
    external_id_attribute: Option<String>,
    group_base_dn: Option<String>,
    group_member_attribute: Option<String>,
    group_name_attribute: Option<String>,
    /// §7 scope. Read so the preview can evaluate the predicate against the
    /// paste; left empty it constrains nothing, exactly as in a sync.
    #[serde(default)]
    email_domains: Vec<String>,
    #[serde(default)]
    department_attribute: Option<String>,
    #[serde(default)]
    department_values: Vec<String>,
}

/// The `http_json` keys the mapping reads.
#[derive(Debug, Default, Deserialize)]
struct HttpJsonMapping {
    users_path: Option<String>,
    external_id_path: Option<String>,
    email_path: Option<String>,
    username_path: Option<String>,
    display_name_path: Option<String>,
    groups_path: Option<String>,
    /// §7 scope, the JSON counterpart of the LDAP fields above.
    #[serde(default)]
    email_domains: Vec<String>,
    #[serde(default)]
    department_path: Option<String>,
    #[serde(default)]
    department_values: Vec<String>,
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Trims a list of form values and drops blanks.
///
/// A scope entry is compared exactly, so a stray space would make it match
/// nobody — turning a typo into a source that owns no one, which is the failure
/// the scope row exists to surface rather than to spring on the admin.
fn trimmed_all(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

impl LdapMapping {
    /// The connector config these values describe, with the documented defaults
    /// for anything left blank.
    ///
    /// Built rather than read so the preview can hand the result to
    /// [`ldap::upstream_from_entry`] — the same function a sync uses — instead of
    /// reimplementing attribute lookup, which is what keeps the preview from
    /// drifting away from the run it is predicting.
    fn config(&self) -> LdapConfig {
        use crate::directory::source::{
            default_email_attribute, default_group_member_attribute, default_group_name_attribute,
            default_page_size, default_user_filter,
        };
        LdapConfig {
            // Never used by the preview: it resolves nothing over the network.
            url: String::new(),
            bind_dn: String::new(),
            base_dn: self.base_dn.clone().unwrap_or_default(),
            user_filter: non_empty(&self.user_filter)
                .map(str::to_string)
                .unwrap_or_else(default_user_filter),
            username_attribute: self.username_attribute.clone().unwrap_or_default(),
            email_attribute: non_empty(&self.email_attribute)
                .map(str::to_string)
                .unwrap_or_else(default_email_attribute),
            display_name_attribute: non_empty(&self.display_name_attribute).map(str::to_string),
            external_id_attribute: self.external_id_attribute.clone().unwrap_or_default(),
            group_base_dn: non_empty(&self.group_base_dn).map(str::to_string),
            group_filter: String::new(), // unused: no server-side group search offline
            group_member_attribute: non_empty(&self.group_member_attribute)
                .map(str::to_string)
                .unwrap_or_else(default_group_member_attribute),
            group_name_attribute: non_empty(&self.group_name_attribute)
                .map(str::to_string)
                .unwrap_or_else(default_group_name_attribute),
            page_size: default_page_size(),
            // Trimmed like the rest: a stray space in a pasted domain list would
            // otherwise produce a filter that matches nobody, which is the one
            // outcome the scope row exists to catch.
            email_domains: trimmed_all(&self.email_domains),
            department_attribute: non_empty(&self.department_attribute).map(str::to_string),
            department_values: trimmed_all(&self.department_values),
        }
    }

    /// Rows that cannot be evaluated at all, as `(row, config key)`.
    ///
    /// Reported as "not set yet" rather than as the row's own "resolved for none
    /// of the entries" message: an empty input is not a mapping that failed, and
    /// telling an admin their attribute "has no value in any entry" when they
    /// simply have not typed it yet sends them looking in the wrong place.
    fn unset(&self) -> Vec<(&'static str, &'static str)> {
        let mut out = Vec::new();
        if non_empty(&self.base_dn).is_none() {
            out.push((ROW_SCOPE, "base_dn"));
        }
        if non_empty(&self.external_id_attribute).is_none() {
            out.push((ROW_EXTERNAL_ID, "external_id_attribute"));
        }
        if non_empty(&self.email_attribute).is_none() {
            out.push((ROW_EMAIL, "email_attribute"));
        }
        // Username is required by the connector, but its absence does not stop
        // the other rows from being read.
        if non_empty(&self.username_attribute).is_none() {
            out.push((ROW_USERNAME, "username_attribute"));
        }
        out
    }
}

impl HttpJsonMapping {
    fn config(&self) -> HttpJsonConfig {
        use crate::directory::source::default_http_method;
        HttpJsonConfig {
            // Never used by the preview: it resolves nothing over the network.
            url: String::new(),
            method: default_http_method(),
            auth: Default::default(),
            users_path: self.users_path.clone().unwrap_or_default(),
            external_id_path: self.external_id_path.clone().unwrap_or_default(),
            email_path: self.email_path.clone().unwrap_or_default(),
            username_path: non_empty(&self.username_path).map(str::to_string),
            display_name_path: non_empty(&self.display_name_path).map(str::to_string),
            groups_path: non_empty(&self.groups_path).map(str::to_string),
            pagination: Default::default(),
            email_domains: trimmed_all(&self.email_domains),
            department_path: non_empty(&self.department_path).map(str::to_string),
            department_values: trimmed_all(&self.department_values),
        }
    }

    fn unset(&self) -> Vec<(&'static str, &'static str)> {
        let mut out = Vec::new();
        if non_empty(&self.users_path).is_none() {
            out.push((ROW_SCOPE, "users_path"));
        }
        if non_empty(&self.external_id_path).is_none() {
            out.push((ROW_EXTERNAL_ID, "external_id_path"));
        }
        if non_empty(&self.email_path).is_none() {
            out.push((ROW_EMAIL, "email_path"));
        }
        out
    }
}

/// Builds the preview for a source configuration, optionally against a sample.
///
/// Only the mapping-shaped kinds are accepted. `scim` is a push source whose
/// schema is fixed (§3), so it has no configurable mapping and says so instead of
/// returning an empty success that would look like a passing check.
pub fn preview(req: &PreviewRequest) -> AppResult<MappingPreview> {
    if let Some(sample) = &req.sample {
        if sample.len() > MAX_SAMPLE_BYTES {
            return Err(AppError::bad_request(format!(
                "sample is {} bytes; the limit is {MAX_SAMPLE_BYTES}",
                sample.len()
            )));
        }
    }
    let sample = req.sample.as_deref();
    let sync_groups = req.sync_groups.unwrap_or(true);
    let offset = req.offset.unwrap_or(0);

    match req.kind.as_str() {
        "ldap" => {
            let mapping: LdapMapping = parse_mapping(&req.kind, &req.config)?;
            // A scope that is not set cannot be evaluated, but everything else
            // can: the paste alone tells us what attributes exist, and that list
            // is what the admin needs in order to fill the scope in.
            let mut preview = preview_ldap(&mapping.config(), sample, sync_groups, offset)?;
            mark_unset(&mut preview, &mapping.unset());
            Ok(preview)
        }
        "http_json" => {
            let mapping: HttpJsonMapping = parse_mapping(&req.kind, &req.config)?;
            if non_empty(&mapping.users_path).is_none() {
                // Without the users path there is no entry to read, so the
                // per-entry rows genuinely cannot be checked. Everything is
                // reported as unset rather than as a failure.
                let mut preview = empty_preview(vec![
                    "No sample was read: `users_path` is not set yet.".into(),
                ]);
                preview.fields = vec![field_with_error(
                    ROW_SCOPE,
                    "`users_path` is not set yet".to_string(),
                )];
                return Ok(preview);
            }
            let mut preview = preview_http_json(&mapping.config(), sample, sync_groups, offset)?;
            mark_unset(&mut preview, &mapping.unset());
            Ok(preview)
        }
        other => Err(AppError::bad_request(format!(
            "kind `{other}` has no configurable field mapping"
        ))),
    }
}

fn parse_mapping<T: serde::de::DeserializeOwned + Default>(
    kind: &str,
    value: &Value,
) -> AppResult<T> {
    // A non-object config means the form is in a shape we cannot read, which is a
    // programming error rather than an admin one, so it stays loud.
    if !value.is_object() {
        return Err(AppError::bad_request(format!(
            "{kind} config must be an object"
        )));
    }
    serde_json::from_value(value.clone())
        .map_err(|e| AppError::bad_request(format!("cannot read the {kind} mapping: {e}")))
}

/// Replaces a row's verdict with "not set yet" for keys that are still blank.
fn mark_unset(preview: &mut MappingPreview, unset: &[(&'static str, &'static str)]) {
    for (row, key) in unset {
        if let Some(field) = preview.fields.iter_mut().find(|f| f.row == *row) {
            field.ok = false;
            field.error = Some(format!("`{key}` is not set yet"));
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct PreviewField {
    /// One of the `ROW_*` constants.
    pub row: &'static str,
    /// False when the mapping cannot work as configured against this sample.
    pub ok: bool,
    /// Human-readable explanation, present iff `ok` is false.
    pub error: Option<String>,
    /// How many sampled entries this row resolved for, when that is meaningful.
    /// `None` for rows that are not per-entry (the scope row).
    pub resolved: Option<usize>,
    /// How many entries were examined for `resolved`.
    pub total: Option<usize>,
    /// True for a row that is deliberately not configurable per kind.
    pub fixed: bool,
}

#[derive(Debug, Serialize)]
pub struct PreviewTarget {
    /// Attribute name (LDAP), spelled the way the directory spells it. JSON
    /// targets are resolved from the document client-side, because nesting is the
    /// part that matters there.
    pub key: String,
    /// Highest number of values seen for this attribute in one entry.
    pub count: usize,
    pub multi: bool,
    /// Which entries carry it: `user`, `group` or `both`.
    pub source: &'static str,
    /// One real value, so the list can be read by recognition instead of by
    /// guessing which attribute name is the right one.
    pub sample_value: Option<String>,
    /// How many *user* entries carry it; the denominator is the preview's
    /// `entry_count`.
    ///
    /// This is what makes a patchy attribute visible while choosing one: `mail`
    /// present in every entry and `displayName` in two thirds look identical in a
    /// bare attribute list, and picking the patchy one is how a mapping ends up
    /// silently falling back for a third of the directory.
    pub user_entries: usize,
    /// How many *group* entries carry it. Group membership is reconstructed from
    /// the paste, so this has no denominator in the preview itself.
    pub group_entries: usize,
}

/// One normalized user, as it would be written.
#[derive(Debug, Serialize)]
pub struct PreviewRow {
    pub external_id: String,
    pub external_dn: Option<String>,
    pub email: String,
    pub username: Option<String>,
    pub display_name: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MappingPreview {
    pub fields: Vec<PreviewField>,
    pub targets: Vec<PreviewTarget>,
    pub rows: Vec<PreviewRow>,
    pub warnings: Vec<String>,
    /// Every entry the sample yielded after applying the scope — the denominator
    /// behind `fields` *and* the total the `rows` window is taken from. Always the
    /// full count, never the page size.
    pub entry_count: usize,
    /// Index of the first returned row, counted in source entries. Echoed back so
    /// the caller can render "26–50 of 120" without tracking it separately.
    pub offset: usize,
    /// How many entries one page spans — the page *capacity*, constant across
    /// pages, and the step a caller should move by.
    ///
    /// Deliberately not `rows.len()`: a page returns fewer rows than it spans
    /// whenever an entry yields none (missing external id, unusable DN), and it
    /// returns fewer entries on the last page. Stepping by the row count would
    /// then produce overlapping or skipped windows — 100 − 20 = 80 after a short
    /// final page, overlapping the 75–99 page. Reporting a fixed step keeps
    /// forward and backward paging aligned.
    pub page_size: usize,
    /// True when rows exist beyond this page.
    pub truncated: bool,
}

// ─── HTTP JSON ────────────────────────────────────────────────────────────

/// The window of source entries a response returns rows for.
///
/// Clamped so a stale `offset` still lands on a page that exists: between two
/// debounced runs the admin can shrink the paste, and the offsets the dashboard
/// was holding then point past the end. Without the clamp that renders as an
/// empty table, which reads as "this source yields no users" rather than "your
/// page number is stale" — a much worse failure than repeating the last page.
fn page_window(offset: usize, entry_count: usize) -> std::ops::Range<usize> {
    if entry_count == 0 {
        return 0..0;
    }
    let last_page = (entry_count - 1) / PREVIEW_PAGE * PREVIEW_PAGE;
    let start = offset.min(last_page);
    start..(start + PREVIEW_PAGE).min(entry_count)
}

fn preview_http_json(
    cfg: &HttpJsonConfig,
    sample: Option<&str>,
    sync_groups: bool,
    offset: usize,
) -> AppResult<MappingPreview> {
    let mut warnings = Vec::new();
    let sample = match sample.map(str::trim).filter(|s| !s.is_empty()) {
        Some(sample) => sample,
        None => {
            // Without a document there is nothing per-entry to check, so the
            // response says so instead of implying the mapping is verified.
            warnings.push(
                "No sample provided: only the configuration structure was checked, not whether \
                 the paths resolve."
                    .to_string(),
            );
            return Ok(empty_preview(warnings));
        }
    };

    let doc: Value = serde_json::from_str(sample)
        .map_err(|e| AppError::bad_request(format!("sample is not valid JSON: {e}")))?;
    // A `users_path` that does not resolve to an array is the most destructive
    // misconfiguration there is (an empty listing disables everyone the source
    // manages), so it aborts the preview rather than being downgraded to a
    // warning.
    let entries = http_json::entries_at(&doc, &cfg.users_path)?;
    // The denominator is every entry in the paste, and the loop below visits all
    // of them. Only `rows` is windowed.
    let total = entries.len();
    let window = page_window(offset, total);

    let mut rows = Vec::new();
    let mut id_resolved = 0usize;
    let mut email_resolved = 0usize;
    let mut username_resolved = 0usize;
    let mut display_name_resolved = 0usize;
    let mut groups_resolved = 0usize;
    // §7: the scope predicate is one of the few config checks a paste can settle,
    // so it is evaluated over every entry rather than over the displayed page.
    let scope = cfg.scope();
    let mut scope_matched = 0usize;

    for (index, entry) in entries.iter().enumerate() {
        // `to_upstream` returns `None` only for a missing or blank external id,
        // so a `None` here is precisely the external_id row failing.
        if let Some(user) = http_json::to_upstream(cfg, entry) {
            id_resolved += 1;
            if !user.email.trim().is_empty() {
                email_resolved += 1;
            }
            if scope.allows(&user) {
                scope_matched += 1;
            }
            if window.contains(&index) {
                rows.push(row_from_upstream(&user));
            }
        }
        if path_resolves(entry, cfg.username_path.as_deref()) {
            username_resolved += 1;
        }
        if path_resolves(entry, cfg.display_name_path.as_deref()) {
            display_name_resolved += 1;
        }
        if cfg
            .groups_path
            .as_deref()
            .is_some_and(|p| !http_json::strings_at_path(entry, p).is_empty())
        {
            groups_resolved += 1;
        }
    }

    // With nothing configured there is nothing to check, so the row keeps
    // reporting the sample size the way it did before scoping existed. With a
    // scope configured it reports how many entries the scope admits, which is the
    // number that decides whether the next run creates anyone at all.
    let (scope_resolved, scope_error) = if scope.is_empty() {
        (total, None)
    } else {
        (
            scope_matched,
            scope_mismatch_error(&scope, id_resolved, scope_matched),
        )
    };

    let fields = vec![
        scope_field(scope_resolved, total, scope_error),
        per_entry_field(
            ROW_EXTERNAL_ID,
            (total > 0 && id_resolved == 0).then(|| {
                format!(
                    "`{}` does not resolve to a non-empty value in any of the {total} sampled \
                     entries",
                    cfg.external_id_path
                )
            }),
            id_resolved,
            total,
            false,
        ),
        per_entry_field(
            ROW_EMAIL,
            empty_email_error(cfg, email_resolved, total),
            email_resolved,
            total,
            false,
        ),
        per_entry_field(
            ROW_USERNAME,
            optional_path_error(
                "username_path",
                cfg.username_path.as_deref(),
                username_resolved,
                total,
            ),
            username_resolved,
            total,
            false,
        ),
        per_entry_field(
            ROW_DISPLAY_NAME,
            optional_path_error(
                "display_name_path",
                cfg.display_name_path.as_deref(),
                display_name_resolved,
                total,
            ),
            display_name_resolved,
            total,
            false,
        ),
        per_entry_field(
            ROW_GROUPS,
            optional_path_error(
                "groups_path",
                cfg.groups_path.as_deref(),
                groups_resolved,
                total,
            ),
            groups_resolved,
            total,
            false,
        ),
    ];

    if cfg
        .groups_path
        .as_deref()
        .is_none_or(|p| p.trim().is_empty())
    {
        warnings.push(
            "No groups_path is configured, so group membership from this source is not synced."
                .to_string(),
        );
    } else if !sync_groups {
        warnings.push(
            "A groups_path is configured but Sync group membership is off, so groups will not \
             be written."
                .to_string(),
        );
    }
    Ok(MappingPreview {
        fields,
        targets: Vec::new(),
        truncated: window.end < total,
        rows,
        warnings,
        entry_count: total,
        offset: window.start,
        page_size: PREVIEW_PAGE,
    })
}

fn path_resolves(entry: &Value, path: Option<&str>) -> bool {
    path.is_some_and(|p| http_json::lookup(entry, p).is_some_and(|v| !v.is_null()))
}

fn empty_email_error(cfg: &HttpJsonConfig, resolved: usize, total: usize) -> Option<String> {
    (total > 0 && resolved == 0).then(|| {
        format!(
            "`{}` resolved for none of the {total} sampled entries; a user without an email \
             address is skipped by the sync",
            cfg.email_path
        )
    })
}

fn optional_path_error(
    name: &str,
    path: Option<&str>,
    resolved: usize,
    total: usize,
) -> Option<String> {
    match path {
        // Not configured is a valid choice, not a problem.
        None => None,
        Some(_) if resolved == 0 && total > 0 => Some(format!(
            "`{name}` resolved for none of the {total} sampled entries; it would be left empty \
             for every user"
        )),
        Some(_) => None,
    }
}

// ─── LDAP ─────────────────────────────────────────────────────────────────

fn preview_ldap(
    cfg: &LdapConfig,
    sample: Option<&str>,
    sync_groups: bool,
    offset: usize,
) -> AppResult<MappingPreview> {
    let mut warnings = Vec::new();
    let sample = match sample.map(str::trim).filter(|s| !s.is_empty()) {
        Some(sample) => sample,
        None => {
            warnings.push(
                "No sample provided: only the configuration structure was checked, not whether \
                 the attributes exist."
                    .to_string(),
            );
            return Ok(empty_preview(warnings));
        }
    };

    let entries = ldif::parse(sample)?;
    if entries.is_empty() {
        return Err(AppError::bad_request(
            "the LDIF sample contains no entries (a `dn:` line is required to start one)",
        ));
    }

    // Group entries are identified the same way the membership map identifies
    // them, and are excluded from the user rows: a group entry has no email, so
    // counting it as a user would report a mapping failure that is not one.
    let membership = ldif::membership_map(
        &entries,
        cfg.group_base_dn.as_deref().unwrap_or_default(),
        &cfg.group_member_attribute,
        &cfg.group_name_attribute,
    );
    let (groups, users): (Vec<&RawEntry>, Vec<&RawEntry>) =
        entries.iter().partition(|entry| is_group_entry(cfg, entry));

    if users.is_empty() {
        warnings.push(
            "Every pasted entry looks like a group entry (its DN is under the group base DN and \
             it carries the group member attribute), so no user could be previewed."
                .to_string(),
        );
    }

    let total = users.len();
    let window = page_window(offset, total);
    let mut rows = Vec::new();
    let mut id_error: Option<String> = None;
    let mut id_resolved = 0usize;
    let mut email_resolved = 0usize;
    let mut username_resolved = 0usize;
    let mut display_name_resolved = 0usize;
    let mut under_base_dn = 0usize;
    // The scope predicate is checkable from a paste, unlike `user_filter` (§7).
    // Candidates are the entries a real search would have returned — under
    // `base_dn` and extractable — so the ratio means "of the entries this source
    // could own, how many does the scope actually admit".
    let scope = cfg.scope();
    let mut scope_candidates = 0usize;
    let mut scope_matched = 0usize;

    let base = cfg.base_dn.trim().to_lowercase();
    for (index, entry) in users.iter().enumerate() {
        let under = base.is_empty() || entry.dn.to_lowercase().ends_with(&base);
        if under {
            under_base_dn += 1;
        }
        // The shared extraction: an error here is exactly the error a sync would
        // raise, message included.
        match ldap::upstream_from_entry(cfg, entry, &membership) {
            Ok(user) => {
                id_resolved += 1;
                if under {
                    scope_candidates += 1;
                    if scope.allows(&user) {
                        scope_matched += 1;
                    }
                }
                if !user.email.trim().is_empty() {
                    email_resolved += 1;
                }
                if entry.text(&cfg.username_attribute).is_some() {
                    username_resolved += 1;
                }
                if cfg
                    .display_name_attribute
                    .as_deref()
                    .and_then(|attr| entry.text(attr))
                    .is_some()
                {
                    display_name_resolved += 1;
                }
                if window.contains(&index) {
                    rows.push(row_from_upstream(&user));
                }
            }
            Err(e) => {
                if id_error.is_none() {
                    id_error = Some(e.to_string());
                }
            }
        }
    }

    // Full pass, like the rest of the counters: `groups_resolved` is the
    // denominator that tells an admin whether the group attributes are populated
    // widely enough to be worth mapping.
    let groups_resolved = users
        .iter()
        .filter(|entry| {
            !membership
                .get(&entry.dn.to_lowercase())
                .is_none_or(Vec::is_empty)
        })
        .count();

    let fields = vec![
        // The server-side half of the scope cannot be evaluated offline:
        // `user_filter` is applied by the server. What *is* checkable is whether
        // the pasted DNs sit under the configured base DN — the part admins
        // actually get wrong — and, since §7, whether the configured scope
        // predicate admits any of them at all.
        PreviewField {
            row: ROW_SCOPE,
            ok: total == 0 || scope_matched > 0,
            error: if total == 0 {
                None
            } else if under_base_dn == 0 {
                Some(format!(
                    "none of the {total} sampled entries sit under base_dn `{}`; check the base \
                     DN, and note that user_filter is applied by the server and cannot be \
                     checked here",
                    cfg.base_dn
                ))
            } else {
                scope_mismatch_error(&scope, scope_candidates, scope_matched)
            },
            resolved: Some(scope_matched),
            total: Some(total),
            fixed: false,
        },
        per_entry_field(ROW_EXTERNAL_ID, id_error, id_resolved, total, false),
        per_entry_field(
            ROW_EMAIL,
            (total > 0 && email_resolved == 0).then(|| {
                format!(
                    "`{}` had no value in any of the {total} sampled entries",
                    cfg.email_attribute
                )
            }),
            email_resolved,
            total,
            false,
        ),
        per_entry_field(
            ROW_USERNAME,
            (total > 0 && username_resolved == 0).then(|| {
                format!(
                    "`{}` had no value in any of the {total} sampled entries",
                    cfg.username_attribute
                )
            }),
            username_resolved,
            total,
            false,
        ),
        per_entry_field(
            ROW_DISPLAY_NAME,
            match cfg.display_name_attribute.as_deref() {
                None => None,
                Some(attr) if total > 0 && display_name_resolved == 0 => Some(format!(
                    "`{attr}` had no value in any of the {total} sampled entries; the email local \
                     part would be used instead"
                )),
                Some(_) => None,
            },
            display_name_resolved,
            total,
            false,
        ),
        per_entry_field(ROW_GROUPS, None, groups_resolved, total, false),
    ];

    append_group_warnings(cfg, &groups, sync_groups, total, &mut warnings);

    Ok(MappingPreview {
        fields,
        targets: targets_from(&users, &groups),
        truncated: window.end < total,
        rows,
        warnings,
        entry_count: total,
        offset: window.start,
        page_size: PREVIEW_PAGE,
    })
}

/// Whether an entry is a group rather than a user, by the same rule the
/// membership map uses: under the group base DN and carrying the member
/// attribute. With no `group_base_dn` configured there are no groups, so every
/// entry is a user.
fn is_group_entry(cfg: &LdapConfig, entry: &RawEntry) -> bool {
    let Some(base) = cfg
        .group_base_dn
        .as_deref()
        .map(str::trim)
        .filter(|b| !b.is_empty())
    else {
        return false;
    };
    entry.dn.to_lowercase().ends_with(&base.to_lowercase())
        && !entry.all_text(&cfg.group_member_attribute).is_empty()
}

fn append_group_warnings(
    cfg: &LdapConfig,
    group_entries: &[&RawEntry],
    sync_groups: bool,
    total_users: usize,
    warnings: &mut Vec<String>,
) {
    if cfg.group_base_dn.is_none() {
        warnings.push(
            "No group base DN is configured, so group membership from this directory is not \
             synced."
                .to_string(),
        );
        return;
    }
    if !sync_groups {
        warnings.push(
            "A group base DN is configured but Sync group membership is off, so groups will not \
             be written."
                .to_string(),
        );
    }
    if group_entries.is_empty() {
        warnings.push(
            "The sample contains no group entries, so the groups column could not be checked. \
             Paste the output of a group search (under the group base DN) to verify it."
                .to_string(),
        );
        return;
    }
    if total_users > 0 {
        // Worth stating plainly: this column is reconstructed from the paste,
        // while a real sync asks the server with `group_filter` on
        // `group_base_dn`. The two can differ, and only the live probe is exact.
        warnings.push(
            "The groups column is a best-effort reconstruction from the pasted group entries: a \
             real sync resolves membership with a server-side group filter, so the two can \
             differ."
                .to_string(),
        );
    }
}

/// What the paste says about one attribute, accumulated across entries.
#[derive(Default)]
struct TargetAccum {
    /// Most values seen for it in a single entry (multi-valued attributes).
    max_values: usize,
    user_entries: usize,
    group_entries: usize,
    /// One real value, for recognition.
    sample: Option<String>,
}

/// Merges attribute names across user and group entries, with provenance.
///
/// Each target carries one real value because the list is read by a human with
/// their `ldapsearch` output next to it: `uid — "ada"` is recognisable at a
/// glance in a way that the bare name `uid` is not, and recognition is what the
/// list is for.
fn targets_from(users: &[&RawEntry], groups: &[&RawEntry]) -> Vec<PreviewTarget> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut merged: BTreeMap<String, TargetAccum> = BTreeMap::new();
    let mut absorb = |entries: &[&RawEntry], is_user: bool| {
        for entry in entries {
            // A key can appear once per entry, but counting it per *summary item*
            // would still double-count an attribute present in both the text and
            // binary maps; dedupe so the numbers mean "entries carrying it".
            let mut seen: BTreeSet<String> = BTreeSet::new();
            for (key, count) in entry.attribute_summary() {
                let slot = merged.entry(key.clone()).or_default();
                slot.max_values = slot.max_values.max(count);
                if seen.insert(key.clone()) {
                    if is_user {
                        slot.user_entries += 1;
                    } else {
                        slot.group_entries += 1;
                    }
                }
                if slot.sample.is_none() {
                    // `external_id` reads text and binary alike, so an AD
                    // `objectGUID` shows as a GUID here too.
                    slot.sample = entry.external_id(&key).map(|v| truncate(&v, 60));
                }
            }
        }
    };
    absorb(users, true);
    absorb(groups, false);
    merged
        .into_iter()
        .map(|(key, accum)| PreviewTarget {
            key,
            count: accum.max_values,
            multi: accum.max_values > 1,
            source: match (accum.user_entries > 0, accum.group_entries > 0) {
                (true, true) => "both",
                (false, true) => "group",
                _ => "user",
            },
            sample_value: accum.sample,
            user_entries: accum.user_entries,
            group_entries: accum.group_entries,
        })
        .collect()
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max).collect();
    out.push('…');
    out
}

// ─── Shared shaping ───────────────────────────────────────────────────────

/// Turns an extracted upstream user into the values a sync would write.
///
/// The normalization is the planner's, not a copy of it: lowercase email, the
/// display-name fallback to the email local part, normalized username, and
/// trimmed/deduplicated/sorted groups. Showing raw upstream values here would
/// hide precisely the surprises an admin needs to see before the first run.
fn row_from_upstream(user: &UpstreamUser) -> PreviewRow {
    let fields = plan::ManagedFields::from_upstream(user);
    PreviewRow {
        external_id: user.external_id.clone(),
        external_dn: user.external_dn.clone(),
        email: fields.email,
        username: fields.username,
        display_name: fields.display_name,
        groups: plan::normalize_groups(&user.groups),
    }
}

fn scope_field(resolved: usize, total: usize, error: Option<String>) -> PreviewField {
    PreviewField {
        row: ROW_SCOPE,
        ok: error.is_none(),
        error,
        resolved: Some(resolved),
        total: Some(total),
        fixed: false,
    }
}

/// Why the scope row fails, when a configured [`ScopeFilter`] matched nothing.
///
/// This is a failing row rather than a passing zero because the two are only
/// distinguishable here: at run time a scope that matches nobody disables every
/// user the source already manages, so a typo in a domain would present itself as
/// a mass deprovisioning rather than as a config error. The check is only possible
/// because the predicate is evaluated locally — the server-side `user_filter`
/// still cannot be verified (§7).
fn scope_mismatch_error(scope: &ScopeFilter, candidates: usize, matched: usize) -> Option<String> {
    if scope.is_empty() || candidates == 0 || matched > 0 {
        return None;
    }
    Some(format!(
        "the configured scope ({}) matched none of the {candidates} sampled entries it could be \
         checked against; at run time an empty scope disables every user this source already \
         manages",
        scope.describe()
    ))
}

/// A row that could not be evaluated at all, with the reason.
fn field_with_error(row: &'static str, error: String) -> PreviewField {
    PreviewField {
        row,
        ok: false,
        error: Some(error),
        resolved: None,
        total: None,
        fixed: false,
    }
}

fn per_entry_field(
    row: &'static str,
    error: Option<String>,
    resolved: usize,
    total: usize,
    fixed: bool,
) -> PreviewField {
    PreviewField {
        ok: error.is_none(),
        error,
        row,
        // A row with no upstream source to point at cannot report a resolution
        // rate; `total` is still reported so the UI can say "0 of N".
        resolved: Some(resolved),
        total: Some(total),
        fixed,
    }
}

fn empty_preview(warnings: Vec<String>) -> MappingPreview {
    MappingPreview {
        fields: Vec::new(),
        targets: Vec::new(),
        rows: Vec::new(),
        warnings,
        entry_count: 0,
        offset: 0,
        page_size: 0,
        truncated: false,
    }
}
