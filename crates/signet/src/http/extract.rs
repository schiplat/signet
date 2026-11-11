use axum::extract::ConnectInfo;
use axum::extract::Extension;
use axum::http::HeaderMap;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

/// The resolved client IP of the current request, as a request extension.
///
/// The access-log middleware computes the IP for every request anyway (same
/// [`client_ip`] trust rules as everywhere else), so it inserts the value here
/// and audit-recording handlers read it instead of re-deriving it — which they
/// could not do without each taking a `ConnectInfo` extractor. Handlers take it
/// as `Option<Extension<AuditIp>>`: absent when the route is driven without the
/// middleware stack (tests), and `None` inside when the request has no
/// determinable client IP.
#[derive(Clone, Debug, Default)]
pub struct AuditIp(pub Option<String>);

/// Handler-side extraction of [`AuditIp`].
///
/// Handlers take the extension as `Option<Extension<AuditIp>>` and pass it
/// here; named `audit_ip` so a handler can hold both the parameter and the
/// result under their natural names (call it by full path).
pub fn audit_ip(ext: Option<Extension<AuditIp>>) -> Option<String> {
    ext.and_then(|e| e.0 .0)
}

/// Parsed `SIGNET_TRUSTED_PROXIES`. Empty (the default) trusts nobody, so
/// `X-Forwarded-For` is ignored everywhere: the peer address is the client IP.
static TRUSTED_PROXIES: OnceLock<Vec<IpNet>> = OnceLock::new();

/// Installs the trusted-proxy list parsed by `Config::from_env`. Later calls
/// (and races between them) are ignored: configuration is fixed for the life of
/// the process.
pub fn init_trusted_proxies(proxies: Vec<IpNet>) {
    let _ = TRUSTED_PROXIES.set(proxies);
}

fn trusted_proxies() -> &'static [IpNet] {
    TRUSTED_PROXIES.get_or_init(Vec::new)
}

/// Best-effort client IP, in strict order of trust:
///
/// 1. Only when the direct peer is a listed trusted proxy
///    (`SIGNET_TRUSTED_PROXIES`) are `X-Forwarded-For` / `X-Real-IP` believed —
///    and then the *rightmost untrusted* hop of the chain is taken, not the
///    first, because every proxy appends the address it saw and the leftmost
///    entry is whatever the client chose to send.
/// 2. Otherwise the peer address itself. Header values are attacker-controlled;
///    without a trusted proxy they must not influence IP allowlists, rate
///    limits, login alerts, or audit trails.
///
/// Callers that need a deterministic list (tests) use [`client_ip_with`].
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<String> {
    client_ip_with(headers, peer, trusted_proxies())
}

/// [`client_ip`] against an explicit trusted-proxy list.
pub fn client_ip_with(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trusted: &[IpNet],
) -> Option<String> {
    let peer_ip = peer?.ip();
    if trusted.iter().any(|net| net.contains(&peer_ip)) {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(ip) = rightmost_untrusted(xff, trusted) {
                return Some(ip.to_string());
            }
        }
        if let Some(real) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Some(ip) = parse_hop(real) {
                // A proxy that forwards a client-supplied `X-Real-IP` would
                // otherwise let that client name any address — including one of
                // our own proxies, or a value chosen to dodge an allowlist. A
                // hop that is itself trusted makes no client assertion, so fall
                // through to the peer address.
                if !trusted.iter().any(|net| net.contains(&ip)) {
                    return Some(ip.to_string());
                }
            }
        }
    }
    Some(peer_ip.to_string())
}

/// Walks an `X-Forwarded-For` chain from the right and returns the first
/// address that is not one of our own proxies — the last box to have touched
/// the connection that we did not operate, i.e. the client.
///
/// A malformed entry poisons the whole header (return `None`): a chain we
/// cannot parse is a chain we cannot trust. If every hop is one of our proxies,
/// the header makes no client assertion, so there is nothing to return either.
fn rightmost_untrusted(xff: &str, trusted: &[IpNet]) -> Option<IpAddr> {
    for hop in xff.split(',').rev() {
        if hop.trim().is_empty() {
            continue;
        }
        let ip = parse_hop(hop)?;
        if !trusted.iter().any(|net| net.contains(&ip)) {
            return Some(ip);
        }
    }
    None
}

/// Parses one forwarded-for hop. Some proxies write `ip:port` despite the
/// header being address-only, so accept that form before distrusting the chain.
fn parse_hop(raw: &str) -> Option<IpAddr> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Some(ip);
    }
    t.parse::<SocketAddr>().ok().map(|a| a.ip())
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
