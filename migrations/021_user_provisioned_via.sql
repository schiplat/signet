-- Track how the local account was first created (e.g. SSO JIT).
-- NULL = admin / self-service / password signup / SCIM / legacy.
ALTER TABLE users ADD COLUMN IF NOT EXISTS provisioned_via TEXT;

-- Best-effort backfill: empty password + linked identity ≈ SSO JIT.
UPDATE users u
SET provisioned_via = 'sso_jit'
WHERE u.provisioned_via IS NULL
  AND (u.password_hash IS NULL OR u.password_hash = '')
  AND EXISTS (
      SELECT 1 FROM user_identities ui WHERE ui.user_id = u.id
  );
