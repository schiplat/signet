-- Who owns a user's upstream-managed attributes.
--
-- `directory_entries` answers this for a directory source: the link is the
-- record. SCIM has no link table, so it had no way to say "this account is
-- mine". `users.provisioned_via` cannot carry it (it is a *first-create* record
-- and SCIM writes nothing at all), and `users.external_id` cannot either (it is
-- nullable, and SCIM clients are free never to send one).
--
-- Two things went wrong without it:
--
--   * SCIM-provisioned users were not protected from deletion. The guard reads
--     the directory link, found none, and let the IdP — or a local admin —
--     hard-delete the row. That loses its sessions and its audit attribution
--     (`audit_logs.actor_user_id` is `ON DELETE SET NULL`), and the IdP's next
--     push provisions a *new* account with a new id, so the person's history
--     does not follow them.
--   * Their `email` / `username` / `display_name` stayed locally editable, so a
--     local edit raced the next push instead of being refused like a directory
--     user's.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS scim_managed BOOLEAN NOT NULL DEFAULT FALSE;

-- Backfilled from the only signal the schema has: `external_id` is written by
-- SCIM and by nothing else (`models::insert_user` is its only writer, and SCIM
-- is the only caller that sets it). A client that never sent `externalId` is
-- missed, and that is not recoverable from the data.
--
-- Marking too much is the recoverable direction: revoking the SCIM token
-- retires the authority and clears the flag, whereas a user wrongly left
-- unmanaged can be deleted outright.
UPDATE users SET scim_managed = TRUE WHERE external_id IS NOT NULL;
