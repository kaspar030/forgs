-- Index audit rows by time alone (security audit 2026-10, HTTP-05).
--
-- `Store::sweep` now deletes audit rows older than the store's audit
-- retention (`DELETE FROM forgs_audit WHERE ts < ?`). The existing
-- `forgs_audit_by_ns_ts` index leads with `ns_node_id`, so without this one
-- the retention sweep would scan the whole table while holding SQLite's
-- write lock.
CREATE INDEX forgs_audit_by_ts ON forgs_audit (ts);
