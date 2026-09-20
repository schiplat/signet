//! The sync decision, as a pure function of two snapshots (§6.2–§6.4).
//!
//! Everything the engine does is chosen here, from
//! (upstream entries, local state) alone. Nothing in this module touches a
//! database, so `--dry-run` and a real run derive the same plan and differ only
//! in whether it is applied — which is what makes the dry-run guarantee in §16
//! structural instead of aspirational.
//!
//! The plan also decides *which* users to disable (rather than leaving that to a
//! blanket SQL statement at apply time), so the counters a dry-run prints are
//! exactly the counters a real run reports.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// One upstream entry, normalized to the fields the sync manages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamUser {
    /// Stable identifier in the source (`entryUUID`, `objectGUID`, SCIM `id`).
    pub external_id: String,
    /// Distinguishing name; persisted for LDAP bind-through auth (§8).
    pub external_dn: Option<String>,
    pub email: String,
    pub username: Option<String>,
    /// `None` when the attribute is missing; the email local part is used.
    pub display_name: Option<String>,
    /// Value of the configured department attribute (LDAP) or path (`http_json`),
    /// when the source has one. Read only by the scope predicate in
    /// [`ScopeFilter`] — it is never stored, so a source that filters on the
    /// department does not also record it (§7).
    pub department: Option<String>,
    /// Group names this entry belongs to, as resolved by the connector.
    pub groups: Vec<String>,
}

/// Existing link between an upstream entry and a local user, for one source.
#[derive(Debug, Clone)]
pub struct LinkSnapshot {
    pub external_id: String,
    pub user_id: Uuid,
    pub source_hash: Option<String>,
}

/// The directory-managed attributes of a linked local user.
#[derive(Debug, Clone)]
pub struct UserSnapshot {
    pub id: Uuid,
    pub email: String,
    pub username: Option<String>,
    pub display_name: String,
    pub status: String,
    pub directory_groups: Vec<String>,
}

/// Minimal identity of a local user, for collision detection. Loaded for every
/// user, not just linked ones, because a new directory entry can collide with
/// any account.
#[derive(Debug, Clone)]
pub struct UserIndexEntry {
    pub id: Uuid,
    pub email: String,
    pub username: Option<String>,
}

/// Everything the planner needs to know about the local side.
#[derive(Debug, Clone, Default)]
pub struct LocalState {
    /// Code of the source being synced.
    pub source_code: String,
    /// Links owned by the source being synced.
    pub links: Vec<LinkSnapshot>,
    /// Full snapshots of the users in `links`.
    pub linked_users: Vec<UserSnapshot>,
    /// Identity of every local user (any source).
    pub index: Vec<UserIndexEntry>,
    /// `user_id` → code of the highest-precedence source linking it, across all
    /// sources. Decides who may disable a user (§4.1 multi-source).
    pub managing: HashMap<Uuid, String>,
}

/// Attributes the directory owns (the §5 table, minus groups which are handled
/// separately so a run can decline to own them).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedFields {
    pub username: Option<String>,
    pub email: String,
    pub display_name: String,
}

impl ManagedFields {
    /// Builds the target managed values for an upstream entry, applying the same
    /// normalizations the database enforces, so the fingerprint always describes
    /// what would actually be stored.
    pub fn from_upstream(user: &UpstreamUser) -> Self {
        let email = user.email.trim().to_lowercase();
        let display_name = user
            .display_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            // §6.2: mirror the JIT-provisioning fallback used by federation.
            .unwrap_or_else(|| email_local_part(&email));
        Self {
            username: crate::models::normalize_username(user.username.as_deref()),
            email,
            display_name,
        }
    }
}

fn email_local_part(email: &str) -> String {
    email
        .split_once('@')
        .map(|(local, _)| local)
        .unwrap_or(email)
        .to_string()
}

/// What the sync will do with one upstream entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Create a new local user and link it.
    Create,
    /// Managed values changed; update in place.
    Update,
    /// Already identical to the directory; only `last_seen_at` is refreshed.
    Unchanged,
    /// Deliberately ignored — benign, e.g. an entry with no email address.
    Skip,
    /// Would take over an existing local account; needs an admin decision.
    Conflict,
    /// Absent upstream: disable locally (never delete, D3).
    Disable,
    /// The entry could not be interpreted — bad config or a dangling link.
    Error,
}

impl Outcome {
    /// Short lowercase label for CLI and log output.
    pub fn label(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Unchanged => "unchanged",
            Self::Skip => "skip",
            Self::Conflict => "conflict",
            Self::Disable => "disable",
            Self::Error => "error",
        }
    }

    /// True for outcomes an operator needs to look at, as opposed to the
    /// high-volume "nothing to do" results.
    pub fn is_noteworthy(self) -> bool {
        !matches!(self, Self::Unchanged | Self::Skip)
    }
}

/// One planned action.
#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub outcome: Outcome,
    pub external_id: String,
    pub external_dn: Option<String>,
    /// Set for Update/Unchanged/Disable/Error; `None` for Create.
    pub user_id: Option<Uuid>,
    /// Set for Create/Update.
    pub fields: Option<ManagedFields>,
    /// `Some` when this run owns group membership for the entry.
    pub groups: Option<Vec<String>>,
    /// Why, for Skip/Conflict/Error. Empty otherwise.
    pub reason: String,
}

/// Totals, shaped to match the `directory_sync_runs` counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub created: i64,
    pub updated: i64,
    pub disabled: i64,
    pub skipped: i64,
    pub conflicts: i64,
    pub errors: i64,
}

#[derive(Debug, Clone, Default)]
pub struct SyncPlan {
    pub changes: Vec<Change>,
    /// Entries read from the source.
    pub scanned: i64,
    /// False when the run intentionally skipped the "absent upstream" pass, so
    /// the report can say so instead of implying nothing was missing.
    pub reconciled: bool,
}

impl SyncPlan {
    pub fn counts(&self) -> Counts {
        let mut c = Counts::default();
        for change in &self.changes {
            match change.outcome {
                Outcome::Create => c.created += 1,
                Outcome::Update => c.updated += 1,
                Outcome::Unchanged | Outcome::Skip => c.skipped += 1,
                Outcome::Conflict => c.conflicts += 1,
                Outcome::Disable => c.disabled += 1,
                Outcome::Error => c.errors += 1,
            }
        }
        c
    }

    /// Actions that write to the database, in a stable order. Create first so a
    /// subsequent Update for the same user cannot be planned against a row that
    /// does not exist yet — ordering within one run still matters because the
    /// snapshot was taken before any write.
    pub fn writes(&self) -> impl Iterator<Item = &Change> {
        self.changes
            .iter()
            .filter(|c| matches!(c.outcome, Outcome::Create | Outcome::Update))
    }
}

/// Fingerprint of the values the sync owns, stored in
/// `directory_entries.source_hash` to make a no-op run cheap.
///
/// Every field is length-prefixed so `("ab", "c")` cannot collide with
/// `("a", "bc")`, and each optional field carries a presence tag so `None` is
/// distinguishable from `Some("")`.
///
/// `groups` participates only when the run owns group membership: flipping
/// `sync_groups` therefore invalidates every fingerprint and produces one full
/// update pass, which is required — the column would otherwise keep a stale
/// value with a "matching" hash.
pub fn fingerprint(fields: &ManagedFields, groups: Option<&[String]>) -> String {
    let mut buf = Vec::with_capacity(128);
    push_opt(&mut buf, fields.username.as_deref());
    push_opt(&mut buf, Some(&fields.email));
    push_opt(&mut buf, Some(&fields.display_name));
    match groups {
        None => buf.push(0),
        Some(groups) => {
            buf.push(1);
            buf.extend_from_slice(&(groups.len() as u64).to_le_bytes());
            for group in groups {
                push_opt(&mut buf, Some(group));
            }
        }
    }
    let digest = Sha256::digest(&buf);
    data_encoding::HEXLOWER.encode(&digest)
}

fn push_opt(buf: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => buf.push(0),
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
            buf.extend_from_slice(v.as_bytes());
        }
    }
}

/// Normalizes a group list: trimmed, deduplicated, sorted. Sorting keeps the
/// fingerprint (and the OIDC `groups` claim) stable across runs regardless of
/// the order the directory returned membership in.
pub fn normalize_groups(groups: &[String]) -> Vec<String> {
    let mut out: Vec<String> = groups
        .iter()
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Which upstream entries a source is allowed to *own* (§7).
///
/// This is a scope, not a query, and the difference is the whole design. An entry
/// that fails it is not merely left out: a user already linked to this source who
/// stops passing is disabled, exactly as if the directory had deleted them. That
/// is why the planner labels the two cases differently —
/// [`REASON_OUT_OF_SCOPE`] versus [`REASON_ABSENT_UPSTREAM`] — so a department
/// transfer can be told apart from a departure in the run history and audit.
///
/// Both lists are empty when unconfigured, and an empty list constrains nothing,
/// so a source saved before this existed behaves identically.
///
/// Matching is deliberately narrow: whole-label domain comparison and exact
/// department values, case-insensitively. Nothing here is a pattern language —
/// a glob or a regex would be unverifiable in the preview and would let one typo
/// silently widen or empty a source's ownership.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeFilter {
    /// Domains the entry's email may belong to, e.g. `corp.example`.
    pub email_domains: Vec<String>,
    /// Department values that are in scope, matched against
    /// `UpstreamUser.department`.
    pub department_values: Vec<String>,
}

/// Reason recorded when an entry was present upstream but outside the source's
/// scope, as opposed to genuinely missing.
pub const REASON_OUT_OF_SCOPE: &str = "out_of_scope";
/// Reason recorded when the directory no longer lists an entry at all.
pub const REASON_ABSENT_UPSTREAM: &str = "absent_upstream";

impl ScopeFilter {
    /// True when nothing is configured, i.e. the source owns everything it lists.
    pub fn is_empty(&self) -> bool {
        self.email_domains.is_empty() && self.department_values.is_empty()
    }

    /// Whether an entry is inside the source's scope.
    pub fn allows(&self, user: &UpstreamUser) -> bool {
        self.allows_email(&user.email) && self.allows_department(user.department.as_deref())
    }

    /// Whether the email's domain is one of the allowed domains.
    ///
    /// A configured domain list and an entry with no parseable email means "no",
    /// not "unknown": the entry cannot be shown to belong to an allowed domain,
    /// and treating an unparseable address as belonging would quietly admit
    /// entries the admin meant to exclude.
    fn allows_email(&self, email: &str) -> bool {
        if self.email_domains.is_empty() {
            return true;
        }
        let normalized = email.trim().to_lowercase();
        let Some((_, domain)) = normalized.rsplit_once('@') else {
            return false;
        };
        self.email_domains
            .iter()
            .any(|allowed| domain_matches(domain, allowed))
    }

    fn allows_department(&self, department: Option<&str>) -> bool {
        if self.department_values.is_empty() {
            return true;
        }
        let Some(value) = department.map(str::trim).filter(|v| !v.is_empty()) else {
            return false;
        };
        self.department_values
            .iter()
            .any(|allowed| value.eq_ignore_ascii_case(allowed.trim()))
    }

    /// One-line summary for operator-facing messages, e.g.
    /// `domains corp.example; departments Engineering, Platform`.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.email_domains.is_empty() {
            parts.push(format!("domains {}", self.email_domains.join(", ")));
        }
        if !self.department_values.is_empty() {
            parts.push(format!("departments {}", self.department_values.join(", ")));
        }
        if parts.is_empty() {
            return "nothing configured".into();
        }
        parts.join("; ")
    }
}

/// Whether `domain` is `allowed` or a subdomain of it.
///
/// A plain suffix test would accept `evilcorp.example` for `corp.example`, which
/// is the mistake that turns a domain filter into a security hole. Comparing on
/// label boundaries means a subdomain has to be a real one: `mail.corp.example`
/// passes, `notcorp.example` does not.
fn domain_matches(domain: &str, allowed: &str) -> bool {
    let allowed = allowed.trim().trim_start_matches('.').to_lowercase();
    if allowed.is_empty() {
        return false;
    }
    domain == allowed || domain.ends_with(&format!(".{allowed}"))
}

/// Knobs that change what a run is allowed to own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanOptions {
    /// Whether this run owns `users.directory_groups`.
    pub sync_groups: bool,
    /// Whether absent entries may be disabled.
    ///
    /// Must be false for a trial run (`--limit`): the snapshot is then partial,
    /// so "absent" would mean "not among the first N" and a single trial run
    /// would disable every user beyond the limit.
    pub reconcile: bool,
    /// Which entries this source may own (§7).
    ///
    /// Empty by default, and an empty filter constrains nothing — a source saved
    /// before scoping existed keeps owning exactly what it owned.
    pub scope: ScopeFilter,
}

/// Builds the plan for one full reconciliation pass.
pub fn plan(upstream: &[UpstreamUser], local: &LocalState, opts: PlanOptions) -> SyncPlan {
    let sync_groups = opts.sync_groups;
    let users_by_id: HashMap<Uuid, &UserSnapshot> =
        local.linked_users.iter().map(|u| (u.id, u)).collect();
    let links_by_external: HashMap<&str, &LinkSnapshot> = local
        .links
        .iter()
        .map(|l| (l.external_id.as_str(), l))
        .collect();

    // Collision indices. Email and username are both unique in `users`, so the
    // first writer wins if the table somehow contains a duplicate.
    let mut by_email: HashMap<String, Uuid> = HashMap::new();
    let mut by_username: HashMap<String, Uuid> = HashMap::new();
    for entry in &local.index {
        by_email
            .entry(entry.email.trim().to_lowercase())
            .or_insert(entry.id);
        if let Some(username) = entry.username.as_deref() {
            by_username
                .entry(username.trim().to_lowercase())
                .or_insert(entry.id);
        }
    }

    let mut changes = Vec::with_capacity(upstream.len());
    let mut seen_external: HashSet<&str> = HashSet::new();
    // External ids that were listed upstream but fell outside the scope. Kept
    // separate from `seen_external` on purpose: these entries must *not* be
    // treated as seen (a linked user who left the scope has to reach the absent
    // pass and be disabled), but the pass needs to know their absence was a
    // scoping decision rather than a deletion.
    let mut out_of_scope: HashSet<&str> = HashSet::new();
    // Email → external id of the first entry that claimed it *in this run*, so a
    // directory with the same address on two entries does not create two
    // accounts and does not silently drop the second one either (§6.4).
    let mut claimed_email: HashMap<String, String> = HashMap::new();
    let mut claimed_username: HashMap<String, String> = HashMap::new();

    for user in upstream {
        let fields = ManagedFields::from_upstream(user);
        let groups = sync_groups.then(|| normalize_groups(&user.groups));

        // ── Entries we cannot act on ────────────────────────────────────
        if fields.email.is_empty() || !fields.email.contains('@') {
            changes.push(Change {
                outcome: Outcome::Skip,
                external_id: user.external_id.clone(),
                external_dn: user.external_dn.clone(),
                user_id: links_by_external
                    .get(user.external_id.as_str())
                    .map(|l| l.user_id),
                fields: None,
                groups: None,
                reason: format!("entry has no usable email address ({:?})", user.email),
            });
            continue;
        }
        // ── Out of scope ────────────────────────────────────────────────
        // Checked after the email test so a malformed entry still gets the more
        // specific reason (an unparseable address tells the operator far more
        // than "not in scope"), and before the duplicate check so an id this run
        // declines to own is not also reported as a duplicate.
        if !opts.scope.allows(user) {
            out_of_scope.insert(user.external_id.as_str());
            changes.push(Change {
                outcome: Outcome::Skip,
                external_id: user.external_id.clone(),
                external_dn: user.external_dn.clone(),
                user_id: links_by_external
                    .get(user.external_id.as_str())
                    .map(|l| l.user_id),
                fields: None,
                groups: None,
                reason: REASON_OUT_OF_SCOPE.into(),
            });
            continue;
        }
        if !seen_external.insert(user.external_id.as_str()) {
            changes.push(Change {
                outcome: Outcome::Error,
                external_id: user.external_id.clone(),
                external_dn: user.external_dn.clone(),
                user_id: None,
                fields: None,
                groups: None,
                reason: "the source returned this external id twice".into(),
            });
            continue;
        }

        match links_by_external.get(user.external_id.as_str()) {
            // ── Already linked: diff the managed values ─────────────────
            Some(link) => {
                // §4.1: when several sources link the same user, the
                // lowest-priority value owns the attributes. A source that does
                // not own them must not overwrite them.
                if let Some(other) = outranking(local, link.user_id) {
                    changes.push(Change {
                        outcome: Outcome::Skip,
                        external_id: user.external_id.clone(),
                        external_dn: user.external_dn.clone(),
                        user_id: Some(link.user_id),
                        fields: None,
                        groups: None,
                        reason: outranked_reason(&other),
                    });
                    continue;
                }

                let Some(current) = users_by_id.get(&link.user_id) else {
                    changes.push(Change {
                        outcome: Outcome::Error,
                        external_id: user.external_id.clone(),
                        external_dn: user.external_dn.clone(),
                        user_id: Some(link.user_id),
                        fields: None,
                        groups: None,
                        reason: format!(
                            "link points at user {} which does not exist",
                            link.user_id
                        ),
                    });
                    continue;
                };

                // §6.4: an email change that would land on someone else's
                // account is refused rather than merged.
                if let Some(owner) = by_email.get(&fields.email) {
                    if *owner != link.user_id {
                        changes.push(Change {
                            outcome: Outcome::Conflict,
                            external_id: user.external_id.clone(),
                            external_dn: user.external_dn.clone(),
                            user_id: Some(link.user_id),
                            fields: None,
                            groups: None,
                            reason: format!(
                                "email {} already belongs to user {owner}; refusing to merge",
                                fields.email
                            ),
                        });
                        continue;
                    }
                }
                if let Some(username) = fields.username.as_deref() {
                    if let Some(owner) = by_username.get(username) {
                        if *owner != link.user_id {
                            changes.push(Change {
                                outcome: Outcome::Conflict,
                                external_id: user.external_id.clone(),
                                external_dn: user.external_dn.clone(),
                                user_id: Some(link.user_id),
                                fields: None,
                                groups: None,
                                reason: format!(
                                    "username {username} already belongs to user {owner}; \
                                     refusing to merge"
                                ),
                            });
                            continue;
                        }
                    }
                }

                // The hash is the fast path. The group check is a safety net for
                // when `directory_groups` was changed by something other than
                // this source (a second source, or an older hash written under
                // different `sync_groups` semantics): re-writing is idempotent
                // and keeps the stored values from drifting away from the hash
                // that claims they are current.
                let target = fingerprint(&fields, groups.as_deref());
                let hash_matches = link.source_hash.as_deref() == Some(target.as_str());
                let groups_match = groups
                    .as_ref()
                    .is_none_or(|g| *g == normalize_groups(&current.directory_groups));
                changes.push(Change {
                    outcome: if hash_matches && groups_match {
                        Outcome::Unchanged
                    } else {
                        Outcome::Update
                    },
                    external_id: user.external_id.clone(),
                    external_dn: user.external_dn.clone(),
                    user_id: Some(link.user_id),
                    fields: Some(fields),
                    groups: groups.clone(),
                    reason: String::new(),
                });
            }
            // ── New entry: look for an account it must not take over ────
            None => {
                if let Some(previous) = claimed_email.get(&fields.email) {
                    changes.push(Change {
                        outcome: Outcome::Conflict,
                        external_id: user.external_id.clone(),
                        external_dn: user.external_dn.clone(),
                        user_id: None,
                        fields: None,
                        groups: None,
                        reason: format!(
                            "another entry in this run ({previous}) already uses email {}",
                            fields.email
                        ),
                    });
                    continue;
                }
                if let Some(username) = fields.username.as_deref() {
                    if let Some(previous) = claimed_username.get(username) {
                        changes.push(Change {
                            outcome: Outcome::Conflict,
                            external_id: user.external_id.clone(),
                            external_dn: user.external_dn.clone(),
                            user_id: None,
                            fields: None,
                            groups: None,
                            reason: format!(
                                "another entry in this run ({previous}) already uses \
                                 username {username}"
                            ),
                        });
                        continue;
                    }
                }

                // v1 never claims an existing account by email (§6.4): a
                // misconfigured directory entry carrying `admin@corp` must not
                // be able to take over the local administrator. A user another
                // source already provisioned is not a takeover, though — the
                // higher-priority source simply owns them.
                if let Some(owner) = by_email.get(&fields.email) {
                    changes.push(collision_change(
                        user,
                        *owner,
                        &fields.email,
                        "email",
                        local,
                    ));
                    continue;
                }
                if let Some(username) = fields.username.as_deref() {
                    if let Some(owner) = by_username.get(username) {
                        changes.push(collision_change(user, *owner, username, "username", local));
                        continue;
                    }
                    claimed_username.insert(username.to_string(), user.external_id.clone());
                }

                claimed_email.insert(fields.email.clone(), user.external_id.clone());
                changes.push(Change {
                    outcome: Outcome::Create,
                    external_id: user.external_id.clone(),
                    external_dn: user.external_dn.clone(),
                    user_id: None,
                    fields: Some(fields),
                    groups,
                    reason: String::new(),
                });
            }
        }
    }

    // ── Reconciliation: links the source no longer returns (§6.3) ───────
    //
    // Computed from the fetched snapshot rather than from a `last_seen_at`
    // timestamp comparison. Timestamps would make the outcome depend on clock
    // values that the plan cannot see, so the counters a dry-run prints could
    // differ from what a real run applies; here the list of users to disable is
    // part of the plan and is applied verbatim.
    for link in &local.links {
        if !opts.reconcile || seen_external.contains(link.external_id.as_str()) {
            continue;
        }
        let Some(current) = users_by_id.get(&link.user_id) else {
            changes.push(Change {
                outcome: Outcome::Error,
                external_id: link.external_id.clone(),
                external_dn: None,
                user_id: Some(link.user_id),
                fields: None,
                groups: None,
                reason: format!("link points at user {} which does not exist", link.user_id),
            });
            continue;
        };
        if current.status == "disabled" {
            changes.push(Change {
                outcome: Outcome::Unchanged,
                external_id: link.external_id.clone(),
                external_dn: None,
                user_id: Some(link.user_id),
                fields: None,
                groups: None,
                reason: String::new(),
            });
            continue;
        }
        // Another source outranks this one for the user, so this source losing
        // sight of them must not disable an account that source still manages
        // (§4.1). Surface it as a skip with a reason: "no change" and "declined
        // on purpose" are different things to whoever reads the run report.
        if let Some(other) = outranking(local, link.user_id) {
            changes.push(Change {
                outcome: Outcome::Skip,
                external_id: link.external_id.clone(),
                external_dn: None,
                user_id: Some(link.user_id),
                fields: None,
                groups: None,
                reason: outranked_reason(&other),
            });
            continue;
        }
        changes.push(Change {
            outcome: Outcome::Disable,
            external_id: link.external_id.clone(),
            external_dn: None,
            user_id: Some(link.user_id),
            fields: None,
            groups: None,
            // The directory still lists them; we just no longer own them. Saying
            // so is the difference between an operator reading "offboarded" and
            // "changed department" at 3am.
            reason: if out_of_scope.contains(link.external_id.as_str()) {
                REASON_OUT_OF_SCOPE.into()
            } else {
                REASON_ABSENT_UPSTREAM.into()
            },
        });
    }

    SyncPlan {
        changes,
        scanned: upstream.len() as i64,
        reconciled: opts.reconcile,
    }
}

/// The code of a *different* source that outranks this one for `user_id`.
///
/// Sources link the same user only when both directories list them; §4.1
/// resolves that by `priority` (lower wins) and breaks ties on `code`, which is
/// the same comparison the `managing_source` view performs. The view already
/// filtered to enabled sources, so this only has to look for someone else.
fn outranking(local: &LocalState, user_id: Uuid) -> Option<String> {
    local
        .managing
        .get(&user_id)
        .filter(|code| code.as_str() != local.source_code)
        .cloned()
}

fn outranked_reason(other: &str) -> String {
    format!("attributes are owned by higher-priority directory source `{other}`")
}

/// An upstream entry whose email/username already belongs to an existing
/// account that this run must not adopt.
///
/// A user another source provisioned is a skip, not a conflict: the higher
/// priority source owns them and this run has nothing to decide. An unmanaged
/// local account *is* a conflict — it is the account-takeover case, and it
/// needs a human.
fn collision_change(
    user: &UpstreamUser,
    owner: Uuid,
    value: &str,
    kind: &str,
    local: &LocalState,
) -> Change {
    let mut change = Change {
        outcome: Outcome::Conflict,
        external_id: user.external_id.clone(),
        external_dn: user.external_dn.clone(),
        user_id: None,
        fields: None,
        groups: None,
        reason: format!(
            "{kind} {value} belongs to local user {owner}, which is not linked to this \
             source; link it explicitly or change the directory entry (v1 does not \
             auto-claim existing accounts)"
        ),
    };
    if let Some(other) = outranking(local, owner) {
        change.outcome = Outcome::Skip;
        change.reason = outranked_reason(&other);
    }
    change
}
