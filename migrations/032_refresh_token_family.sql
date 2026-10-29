-- Groups the refresh tokens issued from one authorization grant into a family,
-- so presenting a rotated (already-revoked) token again can revoke the whole
-- chain as refresh-token reuse.
--
-- Nullable: rows from before this column have no family; the reuse check treats
-- such a row as a family of one (`COALESCE(family_id, id)`). Rotation copies
-- the parent's family_id, so a chain reads: grant -> r1 -> r2 -> r3, all sharing
-- one family_id.
ALTER TABLE refresh_tokens
    ADD COLUMN family_id UUID;

CREATE INDEX refresh_tokens_family_idx ON refresh_tokens(family_id);
