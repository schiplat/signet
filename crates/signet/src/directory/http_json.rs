//! Generic HTTP JSON directory connector (§13).
//!
//! The upstream contract is a JSON document containing an array of user
//! objects, with every field addressed by an explicit dotted path. That is
//! deliberately the whole contract: it covers the shape most internal
//! "list employees" endpoints expose, and anything richer (SCIM semantics,
//! nested group expansion) belongs in a dedicated connector rather than in a
//! mapping language this module would then have to implement and test.
//!
//! Two properties are enforced here rather than left to the caller:
//!
//! * **Every request goes through [`crate::outbound`].** The URL is re-validated
//!   per request — DNS rebinding means the check made when the source was saved
//!   is worthless at fetch time — redirects are disabled, and the body is read
//!   under a size cap.
//! * **Every path is bounded.** Pagination stops at `max_pages`, and a path that
//!   resolves to the wrong JSON type is an error naming the path, not a silent
//!   empty result that would look like an empty directory and disable everyone.

use crate::directory::plan::UpstreamUser;
use crate::directory::source::{HttpAuth, HttpJsonConfig, Pagination};
use crate::error::{AppError, AppResult};
use serde_json::Value;

/// Reads the whole listing and normalizes it into [`UpstreamUser`]s.
///
/// `limit` caps how many entries are returned, matching the LDAP connector: it
/// exists for trial runs, and the caller turns off reconciliation accordingly.
pub async fn fetch_users(
    cfg: &HttpJsonConfig,
    credential: Option<&str>,
    allow_private: bool,
    limit: Option<usize>,
) -> AppResult<Vec<UpstreamUser>> {
    let mut out: Vec<UpstreamUser> = Vec::new();
    let mut pages = 0u32;
    let mut cursor: Option<String> = None;
    let mut page_number: u32 = match &cfg.pagination {
        Pagination::Page { start, .. } => *start,
        _ => 1,
    };

    loop {
        let url = page_url(cfg, &cursor, page_number)?;
        let body = get_json(&url, cfg, credential, allow_private).await?;
        pages += 1;

        for entry in entries_at(&body, &cfg.users_path)? {
            // A single malformed entry is skipped rather than failing the run:
            // an upstream that adds one odd record should not stop 100k users
            // from syncing. An entry with no email is still reported, as a
            // `skip` in the run report, by the planner.
            if let Some(user) = to_upstream(cfg, entry) {
                out.push(user);
                if limit.is_some_and(|limit| out.len() >= limit) {
                    return Ok(out);
                }
            }
        }

        // Paging advance. All three arms fall through to `break` when there is
        // nothing left to fetch or the configured bound is reached.
        match &cfg.pagination {
            Pagination::None => break,
            Pagination::Cursor {
                next_path,
                max_pages,
                ..
            } => {
                cursor = string_at(&body, next_path).filter(|s| !s.trim().is_empty());
                if cursor.is_none() || pages >= *max_pages {
                    break;
                }
            }
            Pagination::Page { max_pages, .. } => {
                if pages >= *max_pages {
                    break;
                }
                page_number += 1;
            }
        }
    }

    Ok(out)
}

/// Builds the URL for one page, adding the paging parameter the config asks for.
///
/// The page number and cursor are appended as query parameters on top of
/// whatever the configured URL already carries: many endpoints are a fixed path
/// with an embedded filter, and dropping it would silently return a different
/// set on page 2.
fn page_url(
    cfg: &HttpJsonConfig,
    cursor: &Option<String>,
    page_number: u32,
) -> AppResult<reqwest::Url> {
    let mut url = reqwest::Url::parse(cfg.url.trim())
        .map_err(|_| AppError::bad_request("http_json url is not a valid URL"))?;
    match &cfg.pagination {
        Pagination::None => {}
        Pagination::Page {
            param,
            size_param,
            size,
            ..
        } => {
            url.query_pairs_mut()
                .append_pair(param, &page_number.to_string())
                .append_pair(size_param, &size.to_string());
        }
        Pagination::Cursor { param, .. } => {
            if let Some(cursor) = cursor {
                url.query_pairs_mut().append_pair(param, cursor);
            }
        }
    }
    Ok(url)
}

/// Performs one GET and parses the body as JSON, with the outbound policy
/// applied on this attempt.
async fn get_json(
    url: &reqwest::Url,
    cfg: &HttpJsonConfig,
    credential: Option<&str>,
    allow_private: bool,
) -> AppResult<Value> {
    // Re-validated per request, and deliberately on the *rendered* URL: the
    // cursor/paging values end up in the query string, and a URL assembled here
    // must pass the same guard the stored one did.
    let url = crate::outbound::ensure_allowed(url.as_str(), allow_private).await?;

    let mut request = crate::outbound::client().get(url.clone());
    if let Some(header) = authorization(cfg, credential) {
        request = request.header(reqwest::header::AUTHORIZATION, header);
    }

    let started = std::time::Instant::now();
    let resp = request
        .send()
        .await
        .map_err(|e| AppError::upstream(format!("http_json source request failed: {e}")))?;
    let status = resp.status();
    let body = crate::outbound::read_body_capped(resp)
        .await
        .map_err(|e| AppError::upstream(format!("http_json source body could not be read: {e}")))?;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    // The URL is logged without its query string: a cursor can be a bearer-like
    // secret on some APIs, and the path is what an operator needs to debug.
    let logged = format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.path()
    );
    if !status.is_success() {
        // The upstream body can be an HTML error page; only the status is
        // reported so a misconfigured source does not dump a page into logs.
        return Err(AppError::upstream(format!(
            "http_json source returned {status} for {logged}"
        )));
    }
    tracing::debug!(
        url = %logged,
        status = status.as_u16(),
        bytes = body.len(),
        elapsed_ms,
        "http_json source page fetched"
    );
    serde_json::from_slice(&body).map_err(|e| {
        AppError::upstream(format!(
            "http_json source did not return JSON ({e}); body was {} bytes",
            body.len()
        ))
    })
}

/// The `Authorization` header for the configured scheme, if any.
fn authorization(cfg: &HttpJsonConfig, credential: Option<&str>) -> Option<String> {
    match &cfg.auth {
        HttpAuth::None => None,
        HttpAuth::Bearer => credential.map(|token| format!("Bearer {token}")),
        HttpAuth::Basic { username } => credential.map(|password| {
            // base64 of `user:pass`, as RFC 7617 requires. Reusing `base64`
            // rather than hand-rolling keeps the padding rules correct.
            use base64::Engine;
            let raw = format!("{username}:{password}");
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(raw)
            )
        }),
    }
}

/// Resolves one entry into the fields the sync manages.
///
/// `None` when the entry has no usable external id or email: the planner would
/// classify it as `skip` anyway, and doing it here keeps the counters honest
/// about what the source actually returned.
///
/// Public because the mapping preview calls it — the preview must show what a
/// sync would read, not a second implementation's opinion.
pub fn to_upstream(cfg: &HttpJsonConfig, entry: &Value) -> Option<UpstreamUser> {
    let external_id = string_at(entry, &cfg.external_id_path)?;
    if external_id.trim().is_empty() {
        return None;
    }
    let email = string_at(entry, &cfg.email_path).unwrap_or_default();
    Some(UpstreamUser {
        external_id: external_id.trim().to_string(),
        // HTTP JSON has no DN, so there is no bind-through target for it; the
        // login path only consults `kind = 'ldap'` links (§8).
        external_dn: None,
        email,
        username: cfg
            .username_path
            .as_deref()
            .and_then(|p| string_at(entry, p)),
        display_name: cfg
            .display_name_path
            .as_deref()
            .and_then(|p| string_at(entry, p)),
        // The JSON counterpart of the LDAP department attribute (§7). Read only
        // by the scope predicate, never stored.
        department: cfg
            .department_path
            .as_deref()
            .and_then(|p| string_at(entry, p)),
        groups: cfg
            .groups_path
            .as_deref()
            .map(|p| strings_at_path(entry, p))
            .unwrap_or_default(),
    })
}

/// Resolves `path` against `value`, returning the sub-value.
///
/// Supports the two forms a hand-written config needs: dotted keys (`data.users`)
/// and indexing of arrays/objects (`items[0]`, `a["b"]`). Not a general JSONPath
/// implementation — no wildcards, filters or recursive descent — because a
/// mapping language that can express anything is one that cannot be validated,
/// and a wrong mapping here means silently wrong user records.
///
/// Exposed for tests; the connector's own entry point is [`fetch_users`].
pub fn lookup<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in split_path(path)? {
        current = match segment {
            Segment::Key(key) => current.get(key)?,
            Segment::Index(index) => current.get(index)?,
        };
    }
    Some(current)
}

enum Segment<'a> {
    Key(&'a str),
    Index(usize),
}

/// Splits `a.b[0].c` into keys and indices, rejecting malformed syntax.
///
/// Splitting happens in two passes because a dotted key is legal when quoted:
/// `["a.b"]` is one key, not two, so the top-level `.` scan has to know it is
/// inside a bracket and inside quotes.
fn split_path(path: &str) -> Option<Vec<Segment<'_>>> {
    let path = path.trim();
    // A leading `$` is the JSONPath root marker and means the same as omitting
    // it, so a config copied from a tool that emits one needs no editing.
    // `$.data` and `$data` both become `data`; a bare `$` then fails the
    // empty-path check below.
    let path = match path.strip_prefix('$') {
        Some(rest) => rest.strip_prefix('.').unwrap_or(rest),
        None => path,
    };
    if path.is_empty() {
        return None;
    }

    let mut parts: Vec<&str> = Vec::new();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut start = 0usize;
    for (i, c) in path.char_indices() {
        match c {
            '"' | '\'' => match quote {
                Some(open) if open == c => quote = None,
                Some(_) => {}
                None => quote = Some(c),
            },
            '[' if quote.is_none() => depth += 1,
            // An unbalanced `]` is malformed; `checked_sub` turns it into `None`.
            ']' if quote.is_none() => depth = depth.checked_sub(1)?,
            '.' if quote.is_none() && depth == 0 => {
                parts.push(&path[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&path[start..]);

    // Unterminated bracket or quote, or an empty segment (`a..b`, `.a`, `a.`):
    // all typos, all refused rather than skipped, so a mapping that would
    // resolve to nothing is visible at configuration time.
    if depth != 0 || quote.is_some() || parts.iter().any(|p| p.is_empty()) {
        return None;
    }

    let mut segments = Vec::new();
    for part in parts {
        segments.extend(split_segment(part)?);
    }
    (!segments.is_empty()).then_some(segments)
}

/// Splits one `name[expr][expr]` segment into keys and indices.
fn split_segment(part: &str) -> Option<Vec<Segment<'_>>> {
    let mut segments = Vec::new();
    let (name, mut rest) = match part.find('[') {
        Some(bracket) => (&part[..bracket], &part[bracket..]),
        None => (part, ""),
    };
    if !name.is_empty() {
        segments.push(Segment::Key(name));
    }
    while !rest.is_empty() {
        let close = rest.find(']')?;
        let inner = rest[1..close].trim();
        // Quoted form indexes an object key (`a["b"]`); bare form indexes an
        // array position. Both are part of the documented subset.
        let inner = inner
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| inner.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
            .unwrap_or(inner);
        match inner.parse::<usize>() {
            Ok(index) => segments.push(Segment::Index(index)),
            Err(_) if !inner.is_empty() => segments.push(Segment::Key(inner)),
            Err(_) => return None,
        }
        rest = &rest[close + 1..];
    }
    (!segments.is_empty()).then_some(segments)
}

/// Resolves a path and coerces the result to a string.
///
/// Numbers and booleans are stringified because employee ids come back as JSON
/// numbers often enough to matter. Arrays and objects are refused: an object at
/// an email path means the mapping is wrong, and `"[object Object]"` in a user's
/// email field is far worse than an error.
fn string_at(value: &Value, path: &str) -> Option<String> {
    lookup(value, path).and_then(scalar_to_string)
}

/// Coerces a scalar JSON value to a string, refusing containers.
fn scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// Resolves a path to a list of strings, accepting either an array or a single
/// scalar (some APIs return one group as a bare string).
///
/// Public because the mapping preview counts how many sampled entries carry a
/// value for the groups path — the same resolution the sync performs, so the
/// count cannot overstate what would be synced.
pub fn strings_at_path(value: &Value, path: &str) -> Vec<String> {
    match lookup(value, path) {
        // Group *objects* (`{id, name}`) are skipped: picking a field would be a
        // guess, and inventing a group name is worse than reporting none.
        Some(Value::Array(items)) => items.iter().filter_map(scalar_to_string).collect(),
        Some(scalar) => scalar_to_string(scalar).into_iter().collect(),
        None => Vec::new(),
    }
}

/// Resolves a path that must point at an array, with a message naming the path
/// when it does not.
///
/// A missing `users_path` is an error rather than an empty listing: treating a
/// renamed upstream field as "the directory is now empty" would disable every
/// user the source manages, which is the single most destructive thing this
/// feature can do.
///
/// Public because the mapping preview calls it: the check that keeps a bad
/// `users_path` from emptying the directory is worth running *before* the first
/// sync, and running the same code is what makes the preview credible.
pub fn entries_at<'a>(value: &'a Value, path: &str) -> AppResult<&'a [Value]> {
    let found = lookup(value, path).ok_or_else(|| {
        AppError::upstream(format!(
            "http_json response has nothing at users_path `{path}`; the source \
             returned {} — check the mapping against the upstream document",
            summarize(value)
        ))
    })?;
    found.as_array().map(|a| a.as_slice()).ok_or_else(|| {
        AppError::upstream(format!(
            "http_json users_path `{path}` is not an array (found {})",
            summarize(found)
        ))
    })
}

/// One-word description of a JSON value, for error messages that must not
/// include the document itself (it can be large, and it holds employee PII).
fn summarize(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}
