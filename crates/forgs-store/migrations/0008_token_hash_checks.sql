-- Token-hash shape checks (security audit 2026-10, SC-7).
--
-- Every stored credential hash is the lowercase-hex SHA-256 of a secret
-- (`forgs::TokenHash`): exactly 64 characters of `[0-9a-f]`. A value of any
-- other shape can never match a lookup (which hashes a presented secret), so
-- it is a bug in the writer, e.g. an app inserting raw secrets or upper-case
-- hex; refuse it at the database instead of storing a dead or, worse, a
-- plaintext credential.
--
-- Enforced by triggers rather than column CHECKs: SQLite can only add a
-- CHECK by rebuilding the table, and a rebuild inside forgs' migrator runs
-- with foreign keys on (they cannot be toggled inside a transaction), where
-- `DROP TABLE` is an implicit `DELETE` that would fire any app foreign key
-- pointing at these tables. Triggers give the same guarantee for every
-- write path without touching existing rows.
--
-- Existing rows are not rewritten: a malformed hash already stored is inert
-- (nothing can redeem it) and expires or is swept like any other.

CREATE TRIGGER forgs_session_hash_insert
BEFORE INSERT ON forgs_session
WHEN length(NEW.token_hash) <> 64 OR NEW.token_hash GLOB '*[^0-9a-f]*'
BEGIN
    SELECT RAISE(ABORT, 'forgs: malformed token hash');
END;
CREATE TRIGGER forgs_session_hash_update
BEFORE UPDATE OF token_hash ON forgs_session
WHEN length(NEW.token_hash) <> 64 OR NEW.token_hash GLOB '*[^0-9a-f]*'
BEGIN
    SELECT RAISE(ABORT, 'forgs: malformed token hash');
END;

CREATE TRIGGER forgs_refresh_token_hash_insert
BEFORE INSERT ON forgs_refresh_token
WHEN length(NEW.token_hash) <> 64 OR NEW.token_hash GLOB '*[^0-9a-f]*'
BEGIN
    SELECT RAISE(ABORT, 'forgs: malformed token hash');
END;
CREATE TRIGGER forgs_refresh_token_hash_update
BEFORE UPDATE OF token_hash ON forgs_refresh_token
WHEN length(NEW.token_hash) <> 64 OR NEW.token_hash GLOB '*[^0-9a-f]*'
BEGIN
    SELECT RAISE(ABORT, 'forgs: malformed token hash');
END;

CREATE TRIGGER forgs_workload_token_hash_insert
BEFORE INSERT ON forgs_workload_token
WHEN length(NEW.token_hash) <> 64 OR NEW.token_hash GLOB '*[^0-9a-f]*'
BEGIN
    SELECT RAISE(ABORT, 'forgs: malformed token hash');
END;
CREATE TRIGGER forgs_workload_token_hash_update
BEFORE UPDATE OF token_hash ON forgs_workload_token
WHEN length(NEW.token_hash) <> 64 OR NEW.token_hash GLOB '*[^0-9a-f]*'
BEGIN
    SELECT RAISE(ABORT, 'forgs: malformed token hash');
END;

CREATE TRIGGER forgs_api_key_hash_insert
BEFORE INSERT ON forgs_api_key
WHEN length(NEW.key_hash) <> 64 OR NEW.key_hash GLOB '*[^0-9a-f]*'
BEGIN
    SELECT RAISE(ABORT, 'forgs: malformed token hash');
END;
CREATE TRIGGER forgs_api_key_hash_update
BEFORE UPDATE OF key_hash ON forgs_api_key
WHEN length(NEW.key_hash) <> 64 OR NEW.key_hash GLOB '*[^0-9a-f]*'
BEGIN
    SELECT RAISE(ABORT, 'forgs: malformed token hash');
END;

CREATE TRIGGER forgs_pending_device_hash_insert
BEFORE INSERT ON forgs_pending_device
WHEN length(NEW.device_hash) <> 64 OR NEW.device_hash GLOB '*[^0-9a-f]*'
BEGIN
    SELECT RAISE(ABORT, 'forgs: malformed token hash');
END;
CREATE TRIGGER forgs_pending_device_hash_update
BEFORE UPDATE OF device_hash ON forgs_pending_device
WHEN length(NEW.device_hash) <> 64 OR NEW.device_hash GLOB '*[^0-9a-f]*'
BEGIN
    SELECT RAISE(ABORT, 'forgs: malformed token hash');
END;
