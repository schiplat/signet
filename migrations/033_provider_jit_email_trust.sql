-- Per-provider JIT provisioning and email trust.
--
-- The global JIT toggle (`app_settings.sso.jit_provision`) is all-or-nothing:
-- it cannot say "the corporate Feishu tenant may auto-create accounts, but
-- GitHub — where anyone can register — may only link existing ones". These
-- columns move both decisions onto the provider row:
--
-- jit_mode: 'inherit' follows the global toggle; 'on'/'off' override it for
-- this provider alone.
--
-- email_trust: how a provider's email assertion is read for auto-link and JIT.
-- 'inherit' keeps the adapter's reported flag. 'any' treats any returned email
-- as verified (what the Feishu adapter used to hard-code — it has no verified
-- flag — so existing Feishu providers are pinned to 'any' below to keep their
-- behavior). 'verified' demands an explicit upstream verified flag, which is
-- also what the now-honest Feishu adapter reports (false): selecting it turns
-- a provider from auto-link into pending-link-only.
--
-- Everything defaults to 'inherit' / current behavior, so no flow changes
-- until an administrator touches the new fields.
ALTER TABLE upstream_providers
    ADD COLUMN jit_mode TEXT NOT NULL DEFAULT 'inherit'
        CHECK (jit_mode IN ('inherit', 'on', 'off')),
    ADD COLUMN email_trust TEXT NOT NULL DEFAULT 'inherit'
        CHECK (email_trust IN ('inherit', 'any', 'verified'));

UPDATE upstream_providers SET email_trust = 'any' WHERE provider_type = 'feishu';
