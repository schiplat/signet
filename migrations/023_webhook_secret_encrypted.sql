-- 023 Encrypt webhook signing secrets at rest.
--
-- `webhooks.secret` was stored in plaintext, unlike every other secret in the
-- schema (SSO client secrets, TOTP secrets) which is sealed with the
-- application key using AES-256-GCM (crates/signet/src/encryption.rs).
--
-- This adds the encrypted column. Existing plaintext values are migrated at
-- boot by `bootstrap::encrypt_webhook_secrets`, which then clears the legacy
-- column; SQL alone cannot perform the encryption.
--
-- The legacy `secret` column is intentionally NOT dropped here: it has to stay
-- readable until every deployment has booted once and migrated its rows. Drop
-- it in a later migration once that is guaranteed.

ALTER TABLE webhooks ADD COLUMN secret_enc TEXT;
