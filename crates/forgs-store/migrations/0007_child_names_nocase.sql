-- Child names compare case-insensitively (security audit 2026-10, AN-6).
--
-- Before this migration only the root name space compared `lower(...)`. For a
-- child kind whose `NameRules` do not fold case, `Foo` and `foo` could sit
-- side by side under one parent, `foo` could be claimed after `Foo` was
-- released (its tombstone compared exactly), and a path lookup depended on
-- case. Now every sibling uniqueness check, every tombstone key and every
-- path lookup uses `lower(name_canonical)`, at the root and below it. The
-- display case (`name`, and `name_canonical` of non-folding kinds) is kept.
--
-- The migrator refuses to run this if two siblings already differ only by
-- case (the new unique index could not be built); rename one of them first.

-- Child tombstone keys are now lower-cased, like root ones. Two tombstones
-- that differ only by case collapse into one (the earliest-inserted wins).
INSERT OR IGNORE INTO forgs_ns_tombstone
    (parent_key, name_canonical, node_id, user_id, released_at, released_by, cause)
SELECT parent_key, lower(name_canonical), node_id, user_id, released_at, released_by, cause
  FROM forgs_ns_tombstone
 WHERE parent_key <> '' AND name_canonical <> lower(name_canonical);
DELETE FROM forgs_ns_tombstone
 WHERE parent_key <> '' AND name_canonical <> lower(name_canonical);

DROP INDEX forgs_ns_node_child_name;
CREATE UNIQUE INDEX forgs_ns_node_child_name
    ON forgs_ns_node (parent_id, lower(name_canonical)) WHERE parent_id IS NOT NULL;

DROP TRIGGER forgs_ns_node_tombstone_insert;
CREATE TRIGGER forgs_ns_node_tombstone_insert
BEFORE INSERT ON forgs_ns_node
WHEN EXISTS (
    SELECT 1 FROM forgs_ns_tombstone t
     WHERE t.parent_key = COALESCE(NEW.parent_id, '')
       AND t.name_canonical = lower(NEW.name_canonical))
BEGIN
    SELECT RAISE(ABORT, 'forgs: name is tombstoned');
END;

-- A case-only rename keeps the tombstone key, so it is not checked (the node
-- still holds that name).
DROP TRIGGER forgs_ns_node_tombstone_update;
CREATE TRIGGER forgs_ns_node_tombstone_update
BEFORE UPDATE OF name_canonical, parent_id ON forgs_ns_node
WHEN (lower(NEW.name_canonical) IS NOT lower(OLD.name_canonical)
      OR NEW.parent_id IS NOT OLD.parent_id)
 AND EXISTS (
    SELECT 1 FROM forgs_ns_tombstone t
     WHERE t.parent_key = COALESCE(NEW.parent_id, '')
       AND t.name_canonical = lower(NEW.name_canonical))
BEGIN
    SELECT RAISE(ABORT, 'forgs: name is tombstoned');
END;
