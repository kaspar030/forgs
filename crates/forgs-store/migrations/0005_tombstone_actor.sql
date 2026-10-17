-- Who released a name, and how (security audit 2026-10, HTTP-07).
--
-- Released names are blocked forever, so an unlimited rename loop lets one
-- account burn any free name for everyone. The store now rate-limits name
-- releases per acting user and per renamed user / node, counting these rows
-- inside a window; and an operator can find and release the tombstones one
-- abusive actor created (`Store::tombstones_released_by`,
-- `Store::release_tombstones_by`).
--
-- `released_by` is the acting user's id, NULL when the app / an operator
-- acted (and for rows from before this migration). Like `node_id` and
-- `user_id` it carries no foreign key: the tombstone outlives the actor.
-- `cause` is 'rename' or 'delete'; NULL on rows from before this migration.
ALTER TABLE forgs_ns_tombstone ADD COLUMN released_by TEXT;
ALTER TABLE forgs_ns_tombstone ADD COLUMN cause TEXT
    CHECK (cause IS NULL OR cause IN ('rename', 'delete'));

CREATE INDEX forgs_ns_tombstone_by_actor
    ON forgs_ns_tombstone (released_by, released_at) WHERE released_by IS NOT NULL;
CREATE INDEX forgs_ns_tombstone_by_node
    ON forgs_ns_tombstone (node_id, released_at) WHERE node_id IS NOT NULL;
CREATE INDEX forgs_ns_tombstone_by_user
    ON forgs_ns_tombstone (user_id, released_at) WHERE user_id IS NOT NULL;
CREATE INDEX forgs_ns_tombstone_by_time ON forgs_ns_tombstone (released_at);
