-- Two upstream authorities can each want an account disabled, and neither could
-- record that intent: SCIM's `active: false` and the sync's "absent upstream"
-- both wrote `users.status` directly. Only the local admin had a durable intent
-- (`local_disabled`, migration 024), so the other two had nothing to hold their
-- decision and each could silently undo the other.
--
-- Concretely, the sync's update path re-derived `status` from `local_disabled`
-- whenever a managed field changed, so a profile edit upstream re-enabled an
-- account the IdP had deactivated. In the other direction a SCIM `active: true`
-- re-enabled a user the directory had dropped.
--
-- These two columns give the upstreams the same kind of durable record the admin
-- already had. `status` becomes the answer derived from all three flags and is
-- never something an authority writes on its own.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS directory_disabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS scim_disabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Rows that are disabled without a local intent were disabled by an upstream,
-- and the old schema cannot say which. Attribute each one to the authority that
-- can actually release it: a linked user belongs to a directory source,
-- anything else was SCIM's doing. A wrong guess is recoverable — the claim is
-- released when that authority next speaks — whereas leaving both flags clear
-- would silently re-enable accounts that were deliberately disabled.
UPDATE users u
SET directory_disabled = TRUE
WHERE u.status = 'disabled'
  AND NOT u.local_disabled
  AND EXISTS (SELECT 1 FROM directory_entries e WHERE e.user_id = u.id);

UPDATE users u
SET scim_disabled = TRUE
WHERE u.status = 'disabled'
  AND NOT u.local_disabled
  AND NOT u.directory_disabled;

-- A local disable intent that never reached `status` would fail the constraint
-- below. Nothing in the old code could write this pair, but a hand edit might
-- have, and failing the migration is a worse outcome than reconciling it: the
-- flag is the intent, so the derived answer is 'disabled'.
UPDATE users SET status = 'disabled' WHERE local_disabled AND status <> 'disabled';

-- The invariant, enforced by the database.
--
-- Every write path writes only its own flag and then derives `status`. This is
-- what proves none were missed: a path that forgets the derivation gets a hard
-- error instead of storing a contradiction. Silent inconsistency is what this
-- change exists to remove, so the guarantee is worth having in the schema
-- rather than only in a Rust helper every caller has to remember to use.
ALTER TABLE users
    ADD CONSTRAINT users_status_matches_flags
    CHECK (status = CASE WHEN local_disabled OR directory_disabled OR scim_disabled
                         THEN 'disabled' ELSE 'active' END);
