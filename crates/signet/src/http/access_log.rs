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

/// Percent-decodes a raw query string into a readable `k=v&k=v` form.
fn decode_query(raw: &str) -> String {
    raw.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            let k = urlencoding::decode(k).ok()?;
            let v = urlencoding::decode(v).ok()?;
            Some(format!("{k}={v}"))
        })
        .collect::<Vec<_>>()
        .join("&")
}
