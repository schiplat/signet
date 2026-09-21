//! Pins the SSO callback URL handed to upstream identity providers.
//!
//! This is the URL an operator registers with the IdP, and the same one the
//! authorize and token-exchange requests send as `redirect_uri`. Nothing in
//! this process fails if it is wrong: the provider rejects the sign-in with a
//! `redirect_uri_mismatch`, which reads like a provider-side misconfiguration.
//! `docs/api-v1.md` documents the shape, so it is asserted here literally.
//!
//! `federation::CALLBACK_PATH` is the single literal behind both the route
//! registration in `federation::routes` and the composed URL, and
//! `crate::API_PREFIX` is shared with the router's `nest`, so the two cannot
//! drift. What these tests add is a tripwire on the literal values themselves:
//! reintroducing a hardcoded path or prefix on one side would compile and be
//! caught here instead of at the IdP.
//!
//! Deliberately not covered: that the route is actually *mounted* at this path.
//! That needs a router-level test, and the suite has none.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

#[test]
fn the_callback_url_is_the_documented_shape() {
    assert_eq!(
        format!(
            "{}{}",
            signet::API_PREFIX,
            signet::federation::callback_path("acme")
        ),
        "/api/v1/auth/sso/acme/callback"
    );
}

#[test]
fn the_api_prefix_is_what_the_docs_promise() {
    // Asserted separately so a change to either half names the half that broke.
    assert_eq!(signet::API_PREFIX, "/api/v1");
}

#[test]
fn the_callback_path_carries_the_provider_code() {
    assert_eq!(
        signet::federation::callback_path("corp-oidc"),
        "/auth/sso/corp-oidc/callback"
    );
}
