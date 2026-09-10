-- Default: SSO JIT provisioning on (Feishu/Google OA first-login auto-create).
-- Admins can toggle via Dashboard → Settings (app_settings key).
INSERT INTO app_settings (key, value)
VALUES ('sso.jit_provision', 'true'::jsonb)
ON CONFLICT (key) DO NOTHING;
