//! The client-IP extractor's trusted-proxy rules.
//!
//! `client_ip` feeds IP allowlists, the rate limiter, login alerts, and audit
//! rows. `X-Forwarded-For` is attacker-controlled, so it may only influence the
//! answer when the direct peer is a proxy this deployment operates — and then
//! it is the *rightmost* untrusted hop that counts, never the first, because
//! the first entry is whatever the client chose to put there.

use signet::http::extract::client_ip_with;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use ipnet::IpNet;

fn addr(ip: &str) -> Option<SocketAddr> {
    Some(SocketAddr::new(ip.parse::<IpAddr>().unwrap(), 44444))
}

fn headers(xff: Option<&str>, real: Option<&str>) -> axum::http::HeaderMap {
    let mut h = axum::http::HeaderMap::new();
    if let Some(v) = xff {
        h.insert("x-forwarded-for", v.parse().unwrap());
    }
    if let Some(v) = real {
        h.insert("x-real-ip", v.parse().unwrap());
    }
    h
}

fn proxies(entries: &[&str]) -> Vec<IpNet> {
    entries
        .iter()
        .map(|e| {
            if let Ok(net) = IpNet::from_str(e) {
                net
            } else {
                IpNet::from(e.parse::<IpAddr>().unwrap())
            }
        })
        .collect()
}

const PROXY: &str = "10.0.0.9";
const CLIENT: &str = "203.0.113.7";
const ATTACKER_CLAIM: &str = "1.2.3.4";

/// The peer is not ours, so the headers are the client's own writing: the peer
/// address is the only thing that can be believed.
#[test]
fn an_untrusted_peer_never_earns_header_trust() {
    let h = headers(Some(ATTACKER_CLAIM), Some(ATTACKER_CLAIM));
    assert_eq!(
        client_ip_with(&h, addr(PROXY), &proxies(&["172.16.0.1"])),
        Some(PROXY.to_string())
    );
}

/// No peer at all (possible in tests/middleware before ConnectInfo lands):
/// same answer — nothing.
#[test]
fn a_missing_peer_yields_nothing_even_with_headers() {
    let h = headers(Some(ATTACKER_CLAIM), None);
    assert_eq!(client_ip_with(&h, None, &proxies(&["10.0.0.9"])), None);
}

/// Behind a trusted proxy, the rightmost hop we do not operate is the client.
/// The chain here reads "claimed client, real client, our proxy" — a spoofed
/// first entry must not win.
#[test]
fn behind_a_trusted_proxy_the_rightmost_untrusted_hop_wins() {
    let h = headers(Some(&format!("{ATTACKER_CLAIM}, {CLIENT}")), None);
    assert_eq!(
        client_ip_with(&h, addr(PROXY), &proxies(&[PROXY])),
        Some(CLIENT.to_string())
    );
}

/// One hop, no chain: the plain proxy deployment.
#[test]
fn a_single_hop_behind_a_trusted_proxy_is_the_client() {
    let h = headers(Some(CLIENT), None);
    assert_eq!(
        client_ip_with(&h, addr(PROXY), &proxies(&[PROXY])),
        Some(CLIENT.to_string())
    );
}

/// A chain we cannot parse is a chain we cannot trust: fall back to the peer
/// rather than guess which fragment was the client.
#[test]
fn a_malformed_header_falls_back_to_the_peer() {
    let h = headers(Some(&format!("{CLIENT}, not-an-ip")), None);
    assert_eq!(
        client_ip_with(&h, addr(PROXY), &proxies(&[PROXY])),
        Some(PROXY.to_string())
    );
}

/// Every hop is one of our own proxies: the header asserts nothing about the
/// client, so the peer (our egress proxy) is the honest answer.
#[test]
fn an_all_trusted_chain_falls_back_to_the_peer() {
    let h = headers(Some(PROXY), None);
    assert_eq!(
        client_ip_with(&h, addr(PROXY), &proxies(&[PROXY])),
        Some(PROXY.to_string())
    );
}

/// `X-Real-IP` is trusted under the same rule, only after XFF.
#[test]
fn x_real_ip_is_used_only_behind_a_trusted_proxy() {
    let h = headers(None, Some(CLIENT));
    assert_eq!(
        client_ip_with(&h, addr(PROXY), &proxies(&[PROXY])),
        Some(CLIENT.to_string())
    );
    // And it loses to XFF when both exist:
    let h2 = headers(Some(ATTACKER_CLAIM), Some(CLIENT));
    assert_eq!(
        client_ip_with(&h2, addr(PROXY), &proxies(&[PROXY])),
        Some(ATTACKER_CLAIM.to_string())
    );
}

/// Some proxies write `ip:port` into the chain despite the header being
/// address-only; accept the form instead of distrusting an otherwise clean chain.
#[test]
fn an_ip_port_hop_still_parses() {
    let h = headers(Some(&format!("{CLIENT}:52341")), None);
    assert_eq!(
        client_ip_with(&h, addr(PROXY), &proxies(&[PROXY])),
        Some(CLIENT.to_string())
    );
}

/// CIDR entries: any address inside a trusted network is a trusted proxy.
#[test]
fn trusted_cidrs_cover_whole_ranges() {
    let h = headers(Some(CLIENT), None);
    assert_eq!(
        client_ip_with(&h, addr("172.16.9.9"), &proxies(&["172.16.0.0/12"])),
        Some(CLIENT.to_string())
    );
}
