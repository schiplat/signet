//! Unified outbound HTTP policy.
//!
//! Every server-side request to a URL an operator can configure (webhooks,
//! upstream IdP endpoints, and — from P4 on — directory sync sources) goes
//! through this module, so one SSRF/timeout policy applies everywhere instead
//! of each call site re-implementing a weaker variant.
//!
//! The guard is deliberately layered:
//!
//! * [`validate_shape`] is synchronous and checks the URL itself: scheme, host,
//!   and literal addresses.
//! * [`ensure_allowed`] additionally resolves the host and rejects a name that
//!   lands in private space. A literal check alone is not enough: `http://2130706433/`
//!   and `http://0x7f.0.0.1/` are parsed as *domains*, and any public DNS name
//!   can be pointed at `127.0.0.1`.
//!
//! Callers that fetch a **stored** URL must re-validate on every attempt rather
//! than trusting the check performed when the URL was saved: DNS can be
//! re-pointed in between (DNS rebinding).

use crate::error::{AppError, AppResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;
use url::{Host, Url};

/// Timeout for establishing the TCP/TLS connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Timeout for the whole request, including reading the response.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Hard cap on a response body we are willing to buffer.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// True when `ip` is routable on the public internet — i.e. not loopback,
/// private, link-local, CGNAT, multicast, benchmarking, documentation, or
/// otherwise reserved space.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        // The std predicates above do not cover everything we care about:
        || a == 0 // 0.0.0.0/8      "this network"
        || (a == 100 && (64..=127).contains(&b)) // 100.64.0.0/10   CGNAT
        || (a == 192 && b == 0 && c == 0) // 192.0.0.0/24    IETF protocol assignments
        || (a == 192 && b == 88 && c == 99) // 192.88.99.0/24  6to4 relay anycast
        || (a == 198 && (18..=19).contains(&b)) // 198.18.0.0/15   benchmarking
        || a >= 240) // 240.0.0.0/4     reserved (includes broadcast)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    // IPv4-mapped (::ffff:a.b.c.d) must be judged as the IPv4 address it
    // carries, otherwise ::ffff:127.0.0.1 would look like a normal v6 address.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let [s0, s1, ..] = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s0 & 0xfe00) == 0xfc00 // fc00::/7        unique local
        || (s0 & 0xffc0) == 0xfe80 // fe80::/10       link local
        || (s0 == 0x2001 && s1 == 0x0db8) // 2001:db8::/32    documentation
        || (s0 == 0x2001 && s1 == 0x0000) // 2001::/32        Teredo
        || s0 == 0x2002) // 2002::/16        6to4
}

fn is_blocked_host_name(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost" || host.ends_with(".localhost") || host.ends_with(".localdomain")
}

/// Whether a literal host (as parsed from the URL) is off-limits under the
/// strict policy.
fn literal_host_is_blocked(host: &Host<&str>) -> bool {
    match host {
        Host::Ipv4(v4) => !is_public_ip(IpAddr::V4(*v4)),
        Host::Ipv6(v6) => !is_public_ip(IpAddr::V6(*v6)),
        Host::Domain(d) => is_blocked_host_name(d),
    }
}

/// Parses and validates an outbound URL **without** touching the network.
///
/// Rejects non-`http(s)` schemes, missing hosts, embedded credentials, and —
/// unless `allow_private` — literal loopback/private/link-local addresses.
/// Name resolution is left to [`ensure_allowed`], so a domain that merely
/// *looks* public passes here.
///
/// `allow_private` is the deployment-wide opt-in
/// (`SIGNET_OUTBOUND_ALLOW_PRIVATE`) for intranet destinations; pass `false`
/// wherever that policy is not available and the strict check is wanted.
pub fn validate_shape(raw: &str, allow_private: bool) -> AppResult<Url> {
    let url =
        Url::parse(raw.trim()).map_err(|_| AppError::bad_request("url is not a valid URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AppError::bad_request("url must be http(s)"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(AppError::bad_request("url must not embed credentials"));
    }
    match url.host() {
        None => return Err(AppError::bad_request("url is missing a host")),
        Some(host) if !allow_private && literal_host_is_blocked(&host) => {
            return Err(AppError::bad_request("url host is not publicly routable"));
        }
        Some(_) => {}
    }
    Ok(url)
}

/// [`validate_shape`] plus DNS resolution: every address the host currently
/// resolves to must be publicly routable, so a public name pointing at private
/// space is rejected too.
pub async fn ensure_allowed(raw: &str, allow_private: bool) -> AppResult<Url> {
    let url = validate_shape(raw, allow_private)?;

    // The operator opted in to intranet destinations, so neither a literal
    // private address nor a private resolution result is a reason to refuse.
    if allow_private {
        return Ok(url);
    }
    // Literal addresses were fully checked above; nothing to resolve.
    if matches!(url.host(), Some(Host::Ipv4(_) | Host::Ipv6(_))) {
        return Ok(url);
    }
    let host = url
        .host_str()
        .ok_or_else(|| AppError::bad_request("url is missing a host"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| AppError::bad_request(format!("url host did not resolve: {e}")))?
        .collect();
    if resolved.is_empty() {
        return Err(AppError::bad_request("url host did not resolve"));
    }
    if resolved.iter().any(|addr| !is_public_ip(addr.ip())) {
        return Err(AppError::bad_request(
            "url host resolves to a non-public address",
        ));
    }
    Ok(url)
}

static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

/// Shared outbound client: bounded timeouts, an identifying user agent, and
/// **redirects disabled** — following a redirect would let a validated URL
/// bounce the request into private space and bypass [`ensure_allowed`].
pub fn client() -> &'static reqwest::Client {
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("signet")
            .build()
            .expect("build outbound HTTP client")
    })
}

/// Buffers a response body, bailing out once it exceeds [`MAX_RESPONSE_BYTES`].
///
/// `reqwest`'s `text()`/`bytes()` are unbounded, so an oversized (or malicious)
/// response could otherwise exhaust memory.
pub async fn read_body_capped(mut resp: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
            anyhow::bail!("response body exceeds {MAX_RESPONSE_BYTES} bytes");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}
