//! The SSO `return_to` sanitizer and login-URL builder.
//!
//! `return_to` is browser input that becomes a server-issued redirect after
//! sign-in succeeds. The rule mirrors the login page's: only same-origin
//! `/oauth/authorize` / `/oauth/end_session` paths survive — anything absolute
//! or protocol-relative would let a crafted `start` call turn Signet into an
//! open redirect the moment a victim completes a third-party login.

use signet::federation::{login_url, safe_return_to};

#[test]
fn authorize_and_end_session_paths_survive() {
    let ok = [
        "/oauth/authorize?response_type=code&client_id=cella&redirect_uri=http%3A%2F%2Flocalhost%2Fcb",
        "/oauth/authorize",
        "/oauth/end_session?client_id=cella",
    ];
    for v in ok {
        assert_eq!(
            safe_return_to(Some(v)).as_deref(),
            Some(v),
            "a legitimate in-flow URL must survive: {v}"
        );
    }
}

#[test]
fn absolute_and_protocol_relative_urls_are_refused() {
    let refused = [
        "https://evil.example/steal",
        "http://evil.example/",
        "//evil.example",
        "javascript:alert(1)",
        "mailto:x@y.z",
    ];
    for v in refused {
        assert!(
            safe_return_to(Some(v)).is_none(),
            "an off-origin target must be refused: {v}"
        );
    }
}

#[test]
fn anything_but_the_oidc_endpoints_is_refused() {
    // The SSO flow only ever resumes an OIDC flow; a same-origin path like
    // /overview is not one, and letting arbitrary paths through would make
    // the redirect surface the whole router.
    assert!(safe_return_to(Some("/overview")).is_none());
    assert!(safe_return_to(Some("/oauth/authorize/../settings")).is_none());
    assert!(safe_return_to(Some("/login")).is_none());
}

#[test]
fn blank_and_missing_are_none() {
    assert!(safe_return_to(None).is_none());
    assert!(safe_return_to(Some("")).is_none());
    assert!(safe_return_to(Some("   ")).is_none());
}

#[test]
fn surrounding_whitespace_is_trimmed() {
    assert_eq!(
        safe_return_to(Some("  /oauth/authorize?client_id=cella  ")).as_deref(),
        Some("/oauth/authorize?client_id=cella")
    );
}

#[test]
fn login_url_encodes_return_to_into_the_query() {
    let rt = "/oauth/authorize?client_id=cella&redirect_uri=http%3A%2F%2Flocalhost%2Fcb";
    let url = login_url("/login?sso_step=mfa", Some(rt));
    assert_eq!(
        url,
        "/login?sso_step=mfa&return_to=%2Foauth%2Fauthorize%3Fclient_id%3Dcella%26redirect_uri%3Dhttp%253A%252F%252Flocalhost%252Fcb"
    );

    // Without one, the base URL stays untouched (no dangling '&').
    assert_eq!(
        login_url("/login?sso_error=upstream_error", None),
        "/login?sso_error=upstream_error"
    );
}
