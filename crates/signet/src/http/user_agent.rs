//! Best-effort User-Agent parsing into a human-readable (browser, os) pair.
//! Intentionally lightweight: no external parser dependency, covers the common
//! browsers/OSes seen in practice. Unknown values simply return `None`.

/// Returns `(browser, os)` describing a User-Agent string, either may be `None`.
pub fn parse(ua: &str) -> (Option<String>, Option<String>) {
    (detect_browser(ua), detect_os(ua))
}

fn detect_browser(ua: &str) -> Option<String> {
    let ua = ua.to_ascii_lowercase();
    // Edge ships both "Edg/" and "Chrome/", so it must be checked first.
    if ua.contains("edg/") {
        return Some(with_major(ua.as_str(), "edge", "edg/"));
    }
    if ua.contains("opr/") || ua.contains("opera") {
        let tok = if ua.contains("opr/") {
            "opr/"
        } else {
            "version/"
        };
        return Some(with_major(ua.as_str(), "opera", tok));
    }
    if ua.contains("crios/") {
        return Some(with_major(ua.as_str(), "chrome", "crios/"));
    }
    if ua.contains("chrome/") {
        return Some(with_major(ua.as_str(), "chrome", "chrome/"));
    }
    if ua.contains("fxios/") {
        return Some(with_major(ua.as_str(), "firefox", "fxios/"));
    }
    if ua.contains("firefox/") {
        return Some(with_major(ua.as_str(), "firefox", "firefox/"));
    }
    if ua.contains("safari/") && ua.contains("version/") {
        return Some(with_major(ua.as_str(), "safari", "version/"));
    }
    None
}

fn detect_os(ua: &str) -> Option<String> {
    let ua = ua.to_ascii_lowercase();
    if ua.contains("windows nt 10") {
        return Some("Windows 10/11".into());
    }
    if ua.contains("windows nt 6.3") {
        return Some("Windows 8.1".into());
    }
    if ua.contains("windows nt 6.2") {
        return Some("Windows 8".into());
    }
    if ua.contains("windows nt 6.1") {
        return Some("Windows 7".into());
    }
    if ua.contains("windows") {
        return Some("Windows".into());
    }
    if ua.contains("android") {
        return Some("Android".into());
    }
    if ua.contains("iphone") || ua.contains("ipad") || ua.contains("ipod") {
        return Some("iOS".into());
    }
    if ua.contains("cros") {
        return Some("ChromeOS".into());
    }
    if ua.contains("mac os x") || ua.contains("macintosh") {
        return Some("macOS".into());
    }
    if ua.contains("linux") {
        return Some("Linux".into());
    }
    None
}

/// Extracts `Name <major-version>` following a token such as `chrome/`.
fn with_major(ua: &str, name: &str, token: &str) -> String {
    match major_version(ua, token) {
        Some(v) => format!("{name} {v}"),
        None => name.to_string(),
    }
}

fn major_version(ua: &str, token: &str) -> Option<String> {
    let start = ua.find(token)? + token.len();
    let rest = &ua[start..];
    let digits: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    digits
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}
