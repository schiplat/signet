//! Tests for `Config::public_base()`.
//!
//! The same base URL is handed to three different consumers: the SSO callback
//! URL that goes upstream as the OAuth `redirect_uri`, the password-reset link
//! in an email, and the SCIM base URL shown to an IdP. They have to agree, and
//! every one of them appends a leading-slash path, so a trailing slash on the
//! configured value turns into a literal `//` in a URL a third party has to
//! reach. The tests below pin the two behaviours that keep that from happening:
//! the preference order and the trimming.
//!
//! `Config::from_env` rejects a trailing slash on `SIGNET_ISSUER` but does not
//! validate `SIGNET_PUBLIC_BASE_URL`, so trimming cannot be left to the loader.
//!
//! Test code never lives in `src/` — see `.cursor/rules/test-directory.mdc`.

mod common;

#[tokio::test]
async fn a_configured_public_base_url_wins_over_the_issuer() {
    let Some(state) = common::state_with(|cfg| {
        cfg.public_base_url = Some("https://sso.example.com".into());
    })
    .await
    else {
        return;
    };

    assert_eq!(state.config.public_base(), "https://sso.example.com");
}

#[tokio::test]
async fn a_trailing_slash_on_the_public_base_url_is_trimmed() {
    let Some(state) = common::state_with(|cfg| {
        cfg.public_base_url = Some("https://sso.example.com/".into());
    })
    .await
    else {
        return;
    };

    assert_eq!(
        state.config.public_base(),
        "https://sso.example.com",
        "a trailing slash must not reach a URL that appends a path"
    );

    // The failure this guards against: composing the path without the trim
    // would yield `https://sso.example.com//reset-password?token=…`.
    let link = format!("{}/reset-password?token=abc", state.config.public_base());
    assert_eq!(link, "https://sso.example.com/reset-password?token=abc");
}

#[tokio::test]
async fn an_unset_public_base_url_falls_back_to_the_issuer() {
    let Some(state) = common::state_with(|cfg| cfg.public_base_url = None).await else {
        return;
    };

    assert_eq!(state.config.public_base(), state.config.issuer);
}

#[tokio::test]
async fn a_base_url_of_only_slashes_does_not_leak_into_a_url() {
    let Some(state) = common::state_with(|cfg| {
        cfg.public_base_url = Some("https://sso.example.com///".into());
    })
    .await
    else {
        return;
    };

    assert_eq!(state.config.public_base(), "https://sso.example.com");
}
