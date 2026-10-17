-- Link a workload token to the API key it was minted from (security audit
-- 2026-10, HTTP-10 / AN-7).
--
-- Revoking a key, disabling its creator, removing the creator's membership
-- or deleting the creator must end the workload tokens already minted from
-- it, not leave them valid until expiry. `api_key_id` is what finds them.
-- NULL means "not minted from a key" (OIDC, app-minted).
--
-- Deliberately **no foreign key** (and no trigger): the sweep deletes
-- consumed single-use keys, and that must not cascade into (or be blocked
-- by) the live tokens they minted. Tokens are deleted explicitly by the
-- store on revoke / disable / remove / user deletion, and the sweep keeps a
-- consumed key while a token still references it.
--
-- Tokens minted before this migration have `api_key_id` NULL and cannot be
-- found this way; they still die at their expiry (at most the workload TTL
-- cap).
--
-- `forgs_api_key.created_by` (0001) is NULL for shell-minted keys. From this
-- version on, deleting a user deletes their keys, so NULL means shell-minted
-- only; keys orphaned by a user deletion *before* this version cannot be told
-- apart and should be reviewed by an admin (`keys list`).
ALTER TABLE forgs_workload_token ADD COLUMN api_key_id TEXT;
CREATE INDEX forgs_workload_token_by_api_key
    ON forgs_workload_token (api_key_id) WHERE api_key_id IS NOT NULL;
