-- Per-provider sign-in domain allowlist.
--
-- The global list (`app_settings.auth.allowed_email_domains`, see
-- `docs/sign-in-allowlist.md`) says which domains may sign in or be provisioned at
-- all. This column is the narrower, provider-specific case: a provider an
-- administrator wants restricted to a subset of those domains — an IdP that only
-- should serve the corporate tenant while the global list also admits a partner
-- domain that signs in elsewhere.
--
-- Empty means "no provider-level restriction", which is what every provider had
-- before this column existed, so nothing changes until it is set. It can only
-- ever narrow the global list, never widen it: both are checked.
--
-- Left ungated for a provider whose identity carries no email (WeChat): a
-- configured list there is checked against nothing, and an address that cannot be
-- shown to belong is refused rather than admitted.
ALTER TABLE upstream_providers
    ADD COLUMN allowed_email_domains TEXT[] NOT NULL DEFAULT '{}';
