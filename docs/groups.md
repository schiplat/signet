# Groups and departments

> English · [简体中文](./zh-CN/groups.md)

Groups and departments are one organisational tree: a **group** is a functional
unit (engineering, ops), a **department** is a place in the company hierarchy.
Both are nodes of the same table and behave identically except for the label.
Nodes may nest, and the tree is what the OIDC `groups` claim reads.

## 1. Data model

`scim_groups` is the one place a group exists:

| Column | Notes |
|---|---|
| `id` | UUID primary key. `users.groups` / `users.directory_groups/pub` store this, never a name |
| `display_name` | Unique among live rows; the name every surface shows |
| `kind` | `department` or `group` |
| `parent_id` | Parent node; `NULL` at the root. Cycles are rejected on move |
| `source` | `local`, `scim` or `directory` — who owns the node |
| `deleted_at` | Tombstone; the row stops being visible and stops resolving names |

Membership is a `users` column, not a join table: `users.groups` holds
locally-managed membership, and `users.directory_groups` holds membership
written by directory sync. Both store ids. The two are kept apart so a sync that
replaces `directory_groups` cannot clobber a group an administrator assigned by
hand.

Reads resolve ids back to names through `signet_group_names(uuid[])`
(migration `043`), so renames no longer rewrite every member row. Writes go
through `signet_group_ids(text[])`, which creates a row for a name it has not
seen. Applications never observe ids: the claim, the SCIM projections and the
dashboard all see names.

## 2. Source and editability

| `source` | Name | Membership | Existence |
|---|---|---|---|
| `local` | dashboard | dashboard | dashboard |
| `scim` | SCIM client | SCIM client | SCIM client |
| `directory` | directory sync | directory sync | directory sync |

Only a `local` node is editable end to end. A `scim` or `directory` node appears
in the tree and can be moved under another parent, but its name and membership
stay owned by its source — an edit here would be silently undone by the next
sync, so the API refuses it instead. Deleting such a node is likewise refused;
it disappears when the source stops listing it.

## 3. OIDC claim semantics

The `groups` claim in `id_token` / UserInfo publishes the **direct** group names
of a user: group nodes only, no departments, and no ancestors.

- A user in `eng` gets `["eng"]`, even if `eng` sits under a department `rnd`.
- A user in both `eng` and `oncall` gets both names.
- Tombstoned groups are not published — membership that outlives what the IdP
  deleted stops being visible the moment the group is deleted (migration `028`
  semantics, preserved by `signet_group_names`).
- Order follows the stored membership array, not alphabetical order: the
  directory-sync fingerprint compares the claim, and a reordering on every read
  would make an unchanged user look changed forever.

## 4. Permissions

| Action | admin | manager | member |
|---|---|---|---|
| View the tree | yes | yes | no |
| Create a `department` / `group` | yes | yes | no |
| Rename / move / set members | yes | yes | no |
| Delete | yes | no | no |

Deleting a department is refused while it still has children: children would
otherwise be orphaned, so they are moved (or removed) first. Deleting a group
releases its members' membership; the user rows survive.

## 5. HTTP API

All paths live under `/api/v1` and are staff-only.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/admin/groups` | The whole tree, flat, ordered by depth then name |
| `POST` | `/admin/groups` | `{display_name, kind?, parent_id?}` |
| `PATCH` | `/admin/groups/{id}` | Rename and/or move (`parent_id: null` promotes to root) |
| `DELETE` | `/admin/groups/{id}` | admin only; refused while the node has children |
| `GET` | `/admin/groups/{id}/members` | Page through members |
| `PUT` | `/admin/groups/{id}/members/{user_id}` | Add one member (idempotent) |
| `DELETE` | `/admin/groups/{id}/members/{user_id}` | Remove one member |

Moves are validated against cycles: a node may not become a descendant of
itself. A rejected move returns `400` and leaves the tree untouched.

## 6. Relationship with SCIM and directory sync

- **SCIM** (`/scim/v2/Groups`) creates and owns `source = 'scim'` nodes. A SCIM
  delete tombstones the row (migration `028`) rather than dropping it, so the
  membership it removed stays explainable in the audit trail.
- **Directory sync** creates and owns `source = 'directory'` nodes and sweeps
  its own empty, child-less groups after a successful run.
- Neither source touches a `local` node, and a `local` node never blocks a
  sync: the tree is a display and membership surface, not an authorisation
  boundary.
