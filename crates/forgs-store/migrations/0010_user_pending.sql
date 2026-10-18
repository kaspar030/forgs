-- Signup approval: `forgs_user.state` gains `pending` (docs/design.md §4).
--
-- A pending user signed up under an approval policy and has not been
-- approved yet. They cannot log in, their credentials do not authenticate,
-- and every liveness check (`state = 'active'`) already excludes them.
--
-- SQLite cannot alter a CHECK constraint. Rebuilding `forgs_user` would mean
-- recreating its triggers and touching every foreign key into it, so the
-- stored schema text is rewritten instead: widening a CHECK never makes an
-- existing row invalid, which is the case SQLite documents as safe for
-- `writable_schema`.
--
-- Rewriting `sqlite_schema` does not bump the schema cookie, so other open
-- connections would keep their cached (old) CHECK and go on refusing
-- `pending`. The throwaway CREATE/DROP below is real DDL: it bumps the
-- cookie, and every connection re-reads the schema on its next statement.

PRAGMA writable_schema = ON;

UPDATE sqlite_schema
   SET sql = replace(sql,
                     'CHECK (state IN (''active'', ''disabled''))',
                     'CHECK (state IN (''active'', ''disabled'', ''pending''))')
 WHERE type = 'table' AND name = 'forgs_user';

PRAGMA writable_schema = RESET;

CREATE TABLE forgs_schema_bump_0010 (x INTEGER) STRICT;
DROP TABLE forgs_schema_bump_0010;
