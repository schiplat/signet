//! Contract tests for the unified outbound HTTP guard.
//!
//! These cover the offline, deterministic half of the policy: URL shape and
//! literal-address classification. `ensure_allowed` adds DNS resolution on top
//! of `validate_shape`; it is exercised by integration tests against a live
//! resolver rather than here, because its result depends on the host's DNS.

use signet::outbound::{is_public_ip, validate_shape};
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("test ip literal")
}

/// The production default: public destinations only.
fn strict(raw: &str) -> bool {
    validate_shape(raw, false).is_ok()
}

/// `SIGNET_OUTBOUND_ALLOW_PRIVATE=true`.
fn permissive(raw: &str) -> bool {
    validate_shape(raw, true).is_ok()
}

// --- literal address classification ---

#[test]
fn blocks_loopback_private_and_link_local_v4() {
    for addr in [
        "127.0.0.1",
        "127.1.2.3",
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "169.254.169.254", // cloud instance metadata
        "100.64.0.1",      // CGNAT
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",    // multicast
        "198.51.100.7", // documentation
        "203.0.113.7",  // documentation
        "192.0.2.7",    // documentation
        "198.18.0.1",   // benchmarking
        "240.0.0.1",    // reserved
    ] {
        assert!(!is_public_ip(ip(addr)), "{addr} must be blocked");
    }
}

#[test]
fn allows_public_v4() {
    for addr in ["1.1.1.1", "8.8.8.8", "140.82.121.4"] {
        assert!(is_public_ip(ip(addr)), "{addr} must be allowed");
    }
}

#[test]
fn blocks_loopback_unique_local_and_link_local_v6() {
    for addr in [
        "::1",
        "::",
        "fc00::1",      // unique local
        "fd12:3456::1", // unique local
        "fe80::1",      // link local
        "ff02::1",      // multicast
        "2001:db8::1",  // documentation
        "2002::1",      // 6to4
        "2001::1",      // Teredo
    ] {
        assert!(!is_public_ip(ip(addr)), "{addr} must be blocked");
    }
}

#[test]
fn blocks_ipv4_mapped_loopback_v6() {
    // Without unwrapping the mapped payload this would look like a normal v6
    // address and slip through.
    assert!(!is_public_ip(ip("::ffff:127.0.0.1")));
    assert!(!is_public_ip(ip("::ffff:10.0.0.1")));
    // A mapped *public* address is still public.
    assert!(is_public_ip(ip("::ffff:1.1.1.1")));
}

#[test]
fn allows_public_v6() {
    assert!(is_public_ip(ip("2606:4700:4700::1111")));
}

// --- url shape, strict policy ---

#[test]
fn rejects_non_http_schemes() {
    for url in [
        "ftp://example.com/hook",
        "file:///etc/passwd",
        "gopher://example.com/",
        "javascript:alert(1)",
    ] {
        assert!(!strict(url), "{url} must be rejected");
    }
}

#[test]
fn rejects_private_and_loopback_literal_hosts() {
    for url in [
        "http://127.0.0.1/hook",
        "http://127.0.0.1:8080/hook",
        "http://[::1]/hook",
        "http://[::ffff:127.0.0.1]/hook",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.1.2.3/hook",
        "http://192.168.0.10/hook",
    ] {
        assert!(!strict(url), "{url} must be rejected");
    }
}

#[test]
fn rejects_localhost_names() {
    for url in [
        "http://localhost/hook",
        "http://localhost:9000/hook",
        "http://LOCALHOST/hook",
        "http://api.localhost/hook",
        "http://localhost./hook",
    ] {
        assert!(!strict(url), "{url} must be rejected");
    }
}

#[test]
fn rejects_embedded_credentials() {
    assert!(!strict("http://user:pass@example.com/hook"));
    assert!(!strict("http://user@example.com/hook"));
}

#[test]
fn rejects_garbage_and_missing_host() {
    // Note: "https:///path" is deliberately absent — the WHATWG parser drops the
    // redundant slashes and yields host "path", which is a valid domain.
    for url in ["", "not a url", "http://", "https://"] {
        assert!(!strict(url), "{url:?} must be rejected");
    }
}

#[test]
fn accepts_public_https_urls() {
    for url in [
        "https://hooks.example.com/services/abc",
        "http://example.com/hook",
        "https://open.feishu.cn/open-apis/bot/v2/hook/xyz",
    ] {
        assert!(strict(url), "{url} must be accepted");
    }
}

#[test]
fn rejects_dotted_and_numeric_encodings_of_private_v4() {
    // The WHATWG URL parser canonicalises non-dotted IPv4 forms before we see
    // them, so decimal/hex/octal spellings of 127.0.0.1 are caught here rather
    // than slipping through as domain names.
    for url in [
        "http://2130706433/hook", // decimal
        "http://0x7f.0.0.1/hook", // hex
        "http://0177.0.0.1/hook", // octal
        "http://127.1/hook",      // short form
    ] {
        assert!(!strict(url), "{url} must be rejected");
    }
}

#[test]
fn shape_check_defers_name_resolution_to_ensure_allowed() {
    // A public-looking name passes the synchronous layer by design; only the
    // DNS lookup in `ensure_allowed` can tell that it points at private space.
    assert!(strict("https://evil.example.com/hook"));
}

// --- url shape, permissive policy ---

#[test]
fn allow_private_permits_intranet_destinations() {
    // The whole point of the opt-in: webhook receivers on a trusted intranet.
    for url in [
        "http://10.1.2.3/hook",
        "http://192.168.0.10:8080/hook",
        "http://172.16.5.5/hook",
        "http://[fd12:3456::1]/hook",
        "http://localhost:9000/hook",
        "http://gitlab.internal/hook",
    ] {
        assert!(permissive(url), "{url} must be accepted when opted in");
    }
}

#[test]
fn allow_private_does_not_relax_scheme_or_credentials() {
    // The flag widens the *address* policy only; these stay rejected.
    for url in [
        "file:///etc/passwd",
        "gopher://10.0.0.1/",
        "http://user:pass@10.0.0.1/hook",
        "http://",
    ] {
        assert!(!permissive(url), "{url} must still be rejected");
    }
}

#[test]
fn allow_private_still_allows_public_destinations() {
    assert!(permissive("https://hooks.example.com/services/abc"));
}
