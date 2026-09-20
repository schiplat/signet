//! LDIF parsing for the mapping preview (§13).
//!
//! The LDAP mapping form asks for attribute names, and the usual way to get one
//! wrong is to guess: `uid` vs `sAMAccountName`, `entryUUID` vs `objectGUID`,
//! `mail` vs `userPrincipalName`. `ldapsearch -LLL` already prints the truth,
//! so the form accepts that output and turns it into a clickable attribute list
//! — no connection, no credential, no new outbound surface.
//!
//! Only what is needed to *show* and *extract* is implemented (RFC 2849 subset):
//! attribute lines with base64 values, line folding, comments, and the `version`
//! header. URL-valued attributes, change records and control lines are rejected
//! rather than ignored, because silently skipping part of a pasted sample would
//! make the preview disagree with the directory.
//!
//! This parser never produces an [`UpstreamUser`] itself: it builds
//! [`RawEntry`](crate::directory::ldap::RawEntry)s, which
//! [`upstream_from_entry`](crate::directory::ldap::upstream_from_entry) then
//! reads exactly as it reads a live search response.

use crate::directory::ldap::RawEntry;
use crate::error::{AppError, AppResult};
use base64::Engine;
use std::collections::HashMap;

/// Parses an LDIF document into entries.
///
/// Returns an error for the first malformed line rather than skipping it: a
/// half-parsed sample would silently hide the attribute the admin is looking for
/// and send them chasing a mapping that was fine.
pub fn parse(input: &str) -> AppResult<Vec<RawEntry>> {
    let mut entries: Vec<RawEntry> = Vec::new();
    // One entry being built: dn plus its attributes. `binary` collects the
    // attributes whose values were base64-encoded (or not valid UTF-8).
    let mut dn: Option<String> = None;
    let mut text: Vec<(String, Vec<String>)> = Vec::new();
    let mut binary: Vec<(String, Vec<Vec<u8>>)> = Vec::new();

    let flush = |dn: &mut Option<String>,
                 text: &mut Vec<(String, Vec<String>)>,
                 binary: &mut Vec<(String, Vec<Vec<u8>>)>,
                 entries: &mut Vec<RawEntry>| {
        if let Some(dn) = dn.take() {
            entries.push(RawEntry::from_parts(
                dn,
                std::mem::take(text),
                std::mem::take(binary),
            ));
        }
    };

    for (line_no, line) in logical_lines(input).iter().enumerate() {
        let line = line.as_str();
        if line.is_empty() {
            // Blank line ends an entry. A sample with a single entry and no
            // trailing newline also lands here via the flush after the loop.
            flush(&mut dn, &mut text, &mut binary, &mut entries);
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        // `version: 1` heads an LDIF *file*, and parses fine as an attribute, so
        // it has to be dropped before the attribute branch rather than only when
        // the line fails to parse. It can only be legal before the first entry.
        if entries.is_empty() && dn.is_none() && is_version_line(line) {
            continue;
        }

        let Some((name, value)) = split_attribute(line, line_no)? else {
            return Err(parse_error(
                line_no,
                "expected `attribute: value` (or `attribute:: base64`)",
            ));
        };

        if name.eq_ignore_ascii_case("dn") {
            match value {
                ParsedValue::Text(value) => {
                    // A second `dn` means the previous entry was not blank-line
                    // terminated; accept it rather than merging two entries.
                    flush(&mut dn, &mut text, &mut binary, &mut entries);
                    dn = Some(value);
                }
                ParsedValue::Binary(_) => {
                    return Err(parse_error(line_no, "dn must not be binary or base64-only"))
                }
            }
            continue;
        }

        match value {
            ParsedValue::Text(value) => push_text(&mut text, &name, value),
            ParsedValue::Binary(value) => push_binary(&mut binary, &name, value),
        }
    }

    // A paste may legitimately omit the trailing blank line.
    flush(&mut dn, &mut text, &mut binary, &mut entries);
    Ok(entries)
}

/// A value as read from one attribute line, before it is attributed to a name.
enum ParsedValue {
    Text(String),
    /// Base64 that did not decode to UTF-8 — an AD `objectGUID`, for instance.
    Binary(Vec<u8>),
}

/// Splits input into logical lines, resolving RFC 2849 line folding.
///
/// A continuation is any line starting with a single space (or tab), appended to
/// the previous line with the marker removed. `ldapsearch` folds at 76 columns
/// by default, and an unhandled fold turns one value into two bogus attributes —
/// the exact failure this preview exists to prevent.
fn logical_lines(input: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // CRLF is common for a paste from a Windows shell.
    for raw in input.replace("\r\n", "\n").replace('\r', "\n").split('\n') {
        let is_continuation = raw.starts_with(' ') || raw.starts_with('\t');
        if is_continuation && !out.is_empty() {
            let last = out.last_mut().expect("checked non-empty");
            last.push_str(&raw[1..]);
            continue;
        }
        out.push(raw.trim_end().to_string());
    }
    out
}

/// Splits `name: value` / `name:: base64` / `name:< url`, decoding base64.
///
/// Returns `None` when the line is not an attribute at all, and an error when it
/// looks like one but cannot be honoured (a URL-valued attribute, a bad base64).
fn split_attribute(line: &str, line_no: usize) -> AppResult<Option<(String, ParsedValue)>> {
    let Some((name, rest)) = line.split_once(':') else {
        return Ok(None);
    };
    if name.is_empty() || name.contains(' ') {
        return Ok(None);
    }
    // `name:< file://…` pulls a value from disk. Refused outright: it cannot be
    // honoured from a paste, and showing an empty value instead would be a lie.
    if rest.starts_with('<') {
        return Err(parse_error(
            line_no,
            "URL-valued attributes cannot be read from a paste",
        ));
    }
    if let Some(encoded) = rest.strip_prefix(':') {
        // Base64 value (`attribute::`). RFC 2849 base64-wraps a value whenever it
        // holds non-ASCII bytes, so base64 alone does not mean "binary" — a
        // non-ASCII display name is base64 too. What separates the two is
        // printability, and the heuristic errs towards *binary* on purpose,
        // because the costs are asymmetric: a text attribute misread as binary
        // surfaces as an unresolved row (loud, fixable), while an AD `objectGUID`
        // misread as text would silently hand the admin a control-character
        // string as a user's external id. The live path does not guess here — it
        // gets this from protocol metadata (`bin_attrs`) — which is the one place
        // the paste cannot follow it.
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|e| parse_error(line_no, &format!("invalid base64 value: {e}")))?;
        let value = match String::from_utf8(decoded) {
            Ok(text) if !text.chars().any(char::is_control) => ParsedValue::Text(text),
            Ok(text) => ParsedValue::Binary(text.into_bytes()),
            Err(e) => ParsedValue::Binary(e.into_bytes()),
        };
        return Ok(Some((name.to_string(), value)));
    }
    // Exactly one space separates the colon from the value (RFC 2849); any
    // additional spaces are part of the value, so only the first is removed.
    let value = rest.strip_prefix(' ').unwrap_or(rest);
    Ok(Some((
        name.to_string(),
        ParsedValue::Text(value.to_string()),
    )))
}

fn is_version_line(line: &str) -> bool {
    line.split_once(':')
        .is_some_and(|(name, _)| name.eq_ignore_ascii_case("version"))
}

fn push_text(text: &mut Vec<(String, Vec<String>)>, name: &str, value: String) {
    match text
        .iter_mut()
        .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
    {
        Some((_, values)) => values.push(value),
        None => text.push((name.to_string(), vec![value])),
    }
}

fn push_binary(binary: &mut Vec<(String, Vec<Vec<u8>>)>, name: &str, value: Vec<u8>) {
    match binary
        .iter_mut()
        .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
    {
        Some((_, values)) => values.push(value),
        None => binary.push((name.to_string(), vec![value])),
    }
}

fn parse_error(line_no: usize, message: &str) -> AppError {
    // 1-based, and counting physical lines including folds. Close enough to guide
    // a human to the bad line, which is all this is for.
    AppError::bad_request(format!("LDIF line {}: {message}", line_no + 1))
}

/// Builds the `member DN → group names` map from pasted entries.
///
/// The live sync resolves membership from the *group* side with a server-side
/// `group_filter` on `group_base_dn` (`fetch_group_membership`). A paste has no
/// server to filter for it, so this approximates that search: an entry whose DN
/// falls under `group_base_dn` and that carries `member_attribute` is treated as
/// a group, and its name comes from `name_attribute`.
///
/// This is why the preview labels the groups column "best effort": the user and
/// identifier columns are exact, this one is a faithful reconstruction of a
/// query rather than the query itself. [`super::mapping`] says so in its
/// warnings, and the live probe is what makes it exact.
pub fn membership_map(
    entries: &[RawEntry],
    group_base_dn: &str,
    member_attribute: &str,
    name_attribute: &str,
) -> HashMap<String, Vec<String>> {
    let base = group_base_dn.trim().to_lowercase();
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for entry in entries {
        if !base.is_empty() && !entry.dn.to_lowercase().ends_with(&base) {
            continue;
        }
        let members = entry.all_text(member_attribute);
        if members.is_empty() {
            continue;
        }
        let Some(name) = entry.text(name_attribute) else {
            continue;
        };
        for member in members {
            out.entry(member.trim().to_lowercase())
                .or_default()
                .push(name.clone());
        }
    }
    for names in out.values_mut() {
        names.sort();
        names.dedup();
    }
    out
}
