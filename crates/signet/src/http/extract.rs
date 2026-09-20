use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

/// Best-effort client IP: first `X-Forwarded-For` hop, else `X-Real-IP`, else peer.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<String> {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let t = first.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    if let Some(real) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let t = real.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    peer.map(|p| p.ip().to_string())
}

pub fn peer_from_connect(info: Option<&ConnectInfo<SocketAddr>>) -> Option<SocketAddr> {
    info.map(|c| c.0)
}

pub fn parse_ip(raw: &str) -> Option<IpAddr> {
    raw.trim().parse().ok()
}

/// Best-effort User-Agent string from the request headers.
pub fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}
