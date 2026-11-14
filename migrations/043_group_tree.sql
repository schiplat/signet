-- Group identity moves from display name to id, and groups become a tree.
-- Requires PostgreSQL 13+ for gen_random_uuid().
--
-- users.groups / users.directory_groups stored display names, so a group's
-- identity WAS its name: the same string lived in scim_groups.display_name and
-- in every member row, with nothing keeping them in agreement. Renaming a
-- group meant rewriting every member row, and any path that forgot left
-- membership pointing at a name that no longer existed.
--
-- Now both columns store scim_groups.id. scim_groups is the one place a group
-- exists, display_name is an attribute of that row, and a rename is a single
-- UPDATE. Read shape is unchanged: signet_group_names() resolves ids back to
-- live names, so the groups claim, the SCIM projections and the dashboard keep
-- seeing names.
--
-- Resolution by function rather than by join is deliberate: several read paths
-- are RETURNING clauses after an INSERT/UPDATE, and a RETURNING clause cannot
-- contain a subquery. A scalar function can.
--
-- The same table gains the org tree: parent_id (adjacency list), kind
-- (department | group) and source (who owns the row: local admin, SCIM, or a
-- directory source). Ownership decides which fields the dashboard may edit:
-- name/membership/deletion belong to the source, while moving a node and
-- labelling it a department stay local operations.

-- -- 1. Tree + ownership columns ---------------------------------------------
ALTER TABLE scim_groups
    ADD COLUMN parent_id UUID REFERENCES scim_groups(id) ON DELETE RESTRICT,
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'group'
        CHECK (kind IN ('group', 'department')),
    ADD COLUMN source TEXT NOT NULL DEFAULT 'local'
        CHECK (source IN ('local', 'scim', 'directory')),
    -- Which directory source created a `source='directory'` row. The sweep
    -- after a sync only prunes its own groups, so one source cannot tombstone
    -- another's not-yet-populated nodes.
    ADD COLUMN source_id UUID REFERENCES directory_sources(id) ON DELETE SET NULL;

-- Every row that exists before this migration was created by SCIM: until now
-- there was no other writer of scim_groups (locally typed names had no row at
-- all). Claiming them keeps the dashboard from renaming groups an IdP owns.
UPDATE scim_groups SET source = 'scim';

ALTER TABLE scim_groups
    ADD CONSTRAINT scim_groups_no_self_parent CHECK (parent_id IS NULL OR parent_id <> id);

CREATE INDEX scim_groups_parent_idx ON scim_groups (parent_id);

-- -- 2. Names that until now existed only on a user become real rows ----------
--
-- Membership used to be implicit: a string no scim_groups row carried was a
-- local group existing solely because someone typed it. The conversion below
-- can only map names to ids, so each such name gets a row first.
--
-- A name in both columns is a local group (the admin's assignment wins); a name
-- only in directory_groups is owned by the directory that produced it.
--
-- A name carried only by a tombstone gets a NEW live row instead of reviving the
-- tombstone: the tombstone records that an IdP deleted a group (and who was in
-- it, migration 028), and membership assigned afterwards belongs to a different
-- group.
INSERT INTO scim_groups (id, display_name, source)
SELECT gen_random_uuid(), name, CASE WHEN in_local THEN 'local' ELSE 'directory' END
FROM (
    SELECT btrim(n) AS name, bool_or(in_local) AS in_local
    FROM (
        SELECT unnest(groups) AS n, TRUE AS in_local FROM users
        UNION ALL
        SELECT unnest(directory_groups) AS n, FALSE AS in_local FROM users
    ) raw
    GROUP BY 1
) d
WHERE name <> ''
  AND NOT EXISTS (
      SELECT 1 FROM scim_groups g
      WHERE g.display_name = name AND g.deleted_at IS NULL
  );

-- -- 3. Rewrite both columns as uuid[] ----------------------------------------
--
-- The old columns are dropped rather than altered in place: there is no USING
-- expression that can reach scim_groups, so the mapping has to happen first.
ALTER TABLE users ADD COLUMN groups_uuid UUID[] NOT NULL DEFAULT '{}';
ALTER TABLE users ADD COLUMN directory_groups_uuid UUID[] NOT NULL DEFAULT '{}';

UPDATE users u
SET groups_uuid = COALESCE((
        SELECT array_agg(DISTINCT g.id)
        FROM scim_groups g
        WHERE g.deleted_at IS NULL AND g.display_name = ANY(u.groups)
    ), '{}'),
    directory_groups_uuid = COALESCE((
        SELECT array_agg(DISTINCT d.id)
        FROM scim_groups d
        WHERE d.deleted_at IS NULL AND d.display_name = ANY(u.directory_groups)
    ), '{}');

-- Dropping the old column also drops users_groups_gin (migration 030), which is
-- rebuilt below over the new type.
ALTER TABLE users DROP COLUMN groups;
ALTER TABLE users DROP COLUMN directory_groups;
ALTER TABLE users RENAME COLUMN groups_uuid TO groups;
ALTER TABLE users RENAME COLUMN directory_groups_uuid TO directory_groups;

-- Same predicate forms as 030 (containment `@>`, never `= ANY`) so the planner
-- can serve every membership write from the index.
CREATE INDEX users_groups_gin ON users USING GIN (groups);
CREATE INDEX users_directory_groups_gin ON users USING GIN (directory_groups);

-- -- 4. The one read-side translation ---------------------------------------
--
-- Ids are what is stored; names are what the OIDC groups claim, the SCIM
-- projections and the dashboard expose. Every SELECT and RETURNING of those two
-- columns goes through this, so the shape the application sees does not change
-- with the storage model.
--
-- A tombstoned group has no name: membership that outlived what the IdP deleted
-- stops being published the moment the group is deleted, which is the same
-- guarantee migration 028 gave by clearing the name out of the arrays.
CREATE FUNCTION signet_group_names(ids UUID[]) RETURNS TEXT[]
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    -- WITH ORDINALITY, not ORDER BY display_name: the result feeds the
    -- directory-sync fingerprint and the OIDC claim, and reordering it on every
    -- read would make an unchanged user look changed forever.
    SELECT COALESCE(array_agg(g.display_name ORDER BY i.ord), '{}')
    FROM unnest(ids) WITH ORDINALITY AS i(id, ord)
    JOIN scim_groups g ON g.id = i.id AND g.deleted_at IS NULL
$$;

COMMENT ON FUNCTION signet_group_names(UUID[]) IS
    'Resolves users.groups / users.directory_groups ids to display names for read paths; see migration 043.';

-- -- 5. Names to ids, for the write paths ------------------------------------
--
-- A name with no live row is created, which is what keeps locally-managed groups
-- (typo-and-go, no SCIM resource behind them) working after the move. Unknown
-- names come back with a fresh id; callers never see a dangling name.
--
-- `src` records who owns the row a caller creates. The directory engine passes
-- 'directory' so its groups can be told apart from admin-created ones; SCIM
-- inserts directly and marks 'scim'. The default keeps existing admin/import
-- call sites local.
CREATE FUNCTION signet_group_ids(
    names TEXT[],
    src TEXT DEFAULT 'local',
    src_id UUID DEFAULT NULL
) RETURNS UUID[]
LANGUAGE plpgsql AS $$
DECLARE
    out_ids UUID[];
BEGIN
    IF names IS NULL OR array_length(names, 1) IS NULL THEN
        RETURN '{}';
    END IF;

    -- Concurrent writers resolving the same new name would race the partial
    -- unique index; the loser's INSERT waits and then finds nothing to insert,
    -- and a same-statement snapshot can miss the winner's row. Serialising the
    -- name→id resolution removes that window entirely. Key is arbitrary and
    -- distinct from the setup lock.
    PERFORM pg_advisory_xact_lock(0x5369_676E_6770_6964);

    INSERT INTO scim_groups (id, display_name, source, source_id)
    SELECT gen_random_uuid(), n, src, src_id
    FROM (SELECT DISTINCT btrim(unnest(names)) AS n) x
    WHERE n <> ''
      AND NOT EXISTS (
          SELECT 1 FROM scim_groups g
          WHERE g.display_name = n AND g.deleted_at IS NULL
      )
    ON CONFLICT (display_name) WHERE deleted_at IS NULL DO NOTHING;

    -- Idempotent: an existing name keeps the row it already had, so a repeated
    -- write does not churn membership. Order follows the caller's list (first
    -- appearance wins for a repeated name), which keeps the stored value stable
    -- across runs that pass the same names and lets the fingerprint compare it
    -- without an extra sort.
    SELECT COALESCE(array_agg(id ORDER BY first_ord), '{}')
    INTO out_ids
    FROM (
        SELECT g.id, min(i.ord) AS first_ord
        FROM unnest(names) WITH ORDINALITY AS i(name, ord)
        JOIN scim_groups g
          ON g.display_name = btrim(i.name) AND g.deleted_at IS NULL
        GROUP BY g.id
    ) s;

    RETURN out_ids;
END;
$$;

COMMENT ON FUNCTION signet_group_ids(TEXT[], TEXT, UUID) IS
    'Resolves group names to scim_groups ids, creating a row for an unknown name with the given source (and directory source id); see migration 043.';
