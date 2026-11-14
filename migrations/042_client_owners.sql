-- Self-service client registration (GitHub-style "Developer settings").
--
-- A logged-in user can register an OAuth client through the dashboard and
-- becomes its owner. Ownership is what lets the new /api/v1/me/clients
-- endpoints scope every read and write to `owner_id = current user` without
-- touching the admin surface.
--
-- client_name: until now a client's display name lived nowhere — RFC 7591
-- registration accepted `client_name` and threw it away (register.rs kept it
-- only in the audit detail), and admin-created clients were identified by
-- their client_id alone. The self-service form is name-first, so the column
-- lands with this migration. '' (not NULL) keeps the existing read paths and
-- the AdminClient projection simple: an empty name means "no name", and the
-- dashboards fall back to client_id.
--
-- owner_id: nullable on purpose. Every client that predates this migration is
-- administrator-managed (owner NULL) and must stay exactly that — the admin
-- surface keeps working unchanged. NULL also covers a deleted owner: the
-- account removal must not cascade into a live integration, so the client
-- survives as an unowned, admin-managed app (SET NULL, not CASCADE). Rotating
-- or deleting it stays an admin operation, which is the same policy GitHub
-- applies to apps left behind by a departed owner.
--
-- The FK targets users(id) with the standard cascade shape used across this
-- schema (040_admin_api_tokens.sql user_id). One index: every /me/clients
-- read is `WHERE owner_id = $1`, and that is the only new access path.

ALTER TABLE client_apps ADD COLUMN client_name TEXT NOT NULL DEFAULT '';
ALTER TABLE client_apps ADD COLUMN owner_id UUID REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX client_apps_owner_idx ON client_apps (owner_id);
