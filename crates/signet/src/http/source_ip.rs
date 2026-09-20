use crate::error::{AppError, AppResult};
use crate::http::extract::parse_ip;
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

/// When allowlist is enabled, source IP must match one of the CIDRs/IPs.
/// Empty allowlist with enable=true denies all (minimum privilege).
pub fn check_client_source_ip(
    allowlist_enabled: bool,
    allowed_cidrs: &[String],
    source_ip: Option<&str>,
) -> AppResult<()> {
    if !allowlist_enabled {
        return Ok(());
    }
    let Some(raw) = source_ip.map(str::trim).filter(|s| !s.is_empty()) else {
        return Err(AppError::forbidden("client IP required for allowlist"));
    };
    let ip = parse_ip(raw).ok_or_else(|| AppError::forbidden("invalid client IP"))?;
    if ip_allowed(ip, allowed_cidrs) {
        Ok(())
    } else {
        Err(AppError::forbidden("client IP not allowed"))
    }
}

pub fn ip_allowed(ip: IpAddr, allowed_cidrs: &[String]) -> bool {
    for entry in allowed_cidrs {
        let e = entry.trim();
        if e.is_empty() {
            continue;
        }
        if let Ok(net) = IpNet::from_str(e) {
            if net.contains(&ip) {
                return true;
            }
            continue;
        }
        if let Ok(single) = e.parse::<IpAddr>() {
            if single == ip {
                return true;
            }
        }
    }
    false
}

pub fn normalize_cidrs(raw: &[String]) -> AppResult<Vec<String>> {
    let mut out = Vec::new();
    for r in raw {
        let t = r.trim();
        if t.is_empty() {
            continue;
        }
        if IpNet::from_str(t).is_ok() || t.parse::<IpAddr>().is_ok() {
            out.push(t.to_string());
            continue;
        }
        return Err(AppError::bad_request(format!(
            "invalid IP or CIDR: {t} (examples: 203.0.113.10, 10.0.0.0/8)"
        )));
    }
    out.sort();
    out.dedup();
    Ok(out)
}
