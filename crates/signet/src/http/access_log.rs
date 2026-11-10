use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;
use std::time::Instant;

use crate::http::extract::client_ip;
use crate::http::request_id::RequestId;

/// Single-line access log: one INFO line per request with method, path, query,
/// client IP, status and latency. The correlation id is carried as a plain
/// field so logs stay flat and greppable.
pub async fn track(req: Request, next: Next) -> Response {
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_else(|| "-".to_string());

    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(decode_query).unwrap_or_default();

    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = client_ip(req.headers(), peer).unwrap_or_else(|| "-".to_string());

    // Share the resolved IP with the handlers: audit events read it from here
    // instead of every admin handler taking a `ConnectInfo` extractor.
    let audit_ip = client_ip(req.headers(), peer);
    let mut req = req;
    req.extensions_mut()
        .insert(crate::http::extract::AuditIp(audit_ip));

    let start = Instant::now();
    let resp = next.run(req).await;
    let latency_ms = start.elapsed().as_millis() as u64;
    let status = resp.status().as_u16();

    match status {
        500.. => tracing::error!(
            request_id = %request_id,
            method = %method,
            path = %path,
            query = %query,
            ip = %ip,
            status = status,
            latency_ms = latency_ms,
            "http request"
        ),
        400..=499 => tracing::warn!(
            request_id = %request_id,
            method = %method,
            path = %path,
            query = %query,
            ip = %ip,
            status = status,
            latency_ms = latency_ms,
            "http request"
        ),
        _ => tracing::info!(
            request_id = %request_id,
            method = %method,
            path = %path,
            query = %query,
            ip = %ip,
            status = status,
            latency_ms = latency_ms,
            "http request"
        ),
    }

    resp
}

/// Percent-decodes a raw query string into a readable `k=v&k=v` form, with
/// credential-bearing parameters redacted.
///
/// Some credentials live in the URL by design — password-reset links carry a
/// live one-time `token`, and OAuth callbacks carry the `code` (plus, on
/// misconfigured clients, the PKCE `code_verifier`). The request that redeems
/// them would otherwise log them verbatim, and log streams travel far beyond
/// the process that wrote the line.
fn decode_query(raw: &str) -> String {
    raw.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            let k = urlencoding::decode(k).ok()?;
            let v = urlencoding::decode(v).ok()?;
            if REDACTED_QUERY_KEYS
                .iter()
                .any(|r| k.eq_ignore_ascii_case(r))
            {
                Some(format!("{k}=[redacted]"))
            } else {
                Some(format!("{k}={v}"))
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Query parameters whose values are one-time credentials; redacted in access
/// logs. Matched case-insensitively.
const REDACTED_QUERY_KEYS: &[&str] = &["token", "code", "code_verifier"];
