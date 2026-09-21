-- A group delete from the IdP must not destroy data either.
--
-- `delete_group` used to remove the `scim_groups` row and strip the name from
-- every user's `groups`, in one statement each and with no audit. An IdP that
-- deleted a group by mistake left nothing to recover from: no record that the
-- group existed, no record of who was in it.
--
-- Same shape as the user side (D3): mark, do not remove. The row stays as a
-- tombstone, and the membership it had is kept on it, because the membership
-- itself does have to be released — `users.groups` is what the `groups` claim is
-- built from, so leaving the name there would keep granting a group the IdP has
-- deleted. The snapshot is the recovery path.
ALTER TABLE scim_groups
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
    -- Who was in the group at the moment it was deleted. `users.groups` no
    -- longer carries the name, so this is the only record of the membership.
    ADD COLUMN IF NOT EXISTS members_at_delete UUID[];

-- Replacing a tombstoned group is normal — an IdP that deletes a group and
-- creates it again must not collide with the mark we left behind. The unique
-- constraint becomes a partial index over the live rows, so at most one live
-- group per name and any number of tombstones.
ALTER TABLE scim_groups DROP CONSTRAINT IF EXISTS scim_groups_display_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS scim_groups_live_display_name_key
    ON scim_groups (display_name) WHERE deleted_at IS NULL;
