//! Tests for the audit client-attribution parsing contract
//! (`resolve_audit_client_id`), per the test-directory rule: all tests live
//! under `crates/signet/tests/`, not inline in `src/`.

use signet::audit::resolve_audit_client_id_contract as extract;

#[test]
fn parses_client_id_from_return_to() {
    assert_eq!(
        extract(Some(
            "/oauth/authorize?response_type=code&client_id=webapp&scope=openid"
        )),
        Some("webapp".into())
    );
    assert_eq!(
        extract(Some("/oauth/authorize?client_id=my-app&state=x%20y")),
        Some("my-app".into())
    );
}

#[test]
fn decodes_urlencoded_client_ids() {
    assert_eq!(
        extract(Some("/oauth/authorize?client_id=%C3%A9")),
        Some("é".into())
    );
}

#[test]
fn missing_or_malformed_inputs_yield_none() {
    assert_eq!(extract(Some("/login")), None);
    assert_eq!(extract(Some("/oauth/authorize?response_type=code")), None);
    assert_eq!(extract(Some("/oauth/authorize?client_id=")), None);
    assert_eq!(extract(Some("  ")), None);
    assert_eq!(extract(None), None);
}

#[test]
fn does_not_match_keys_merely_containing_client_id() {
    assert_eq!(extract(Some("/oauth/authorize?xclient_id=evil")), None);
}
