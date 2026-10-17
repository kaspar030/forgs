-- Absolute lifetime for session refresh chains (security audit 2026-10).
--
-- `auth_time` is when the chain's original authentication happened (login,
-- device flow, signup or refresh-token redemption). `grant_type: refresh`
-- carries it unchanged into the replacement session, so a refresh chain can
-- be capped at an absolute age no matter how often it is refreshed.
--
-- STRICT tables need a default for a NOT NULL column add; existing sessions
-- start their chain at their own issue time.
ALTER TABLE forgs_session ADD COLUMN auth_time INTEGER NOT NULL DEFAULT 0;
UPDATE forgs_session SET auth_time = issued_at;
