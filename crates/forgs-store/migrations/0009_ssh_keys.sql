-- SSH public keys as a user credential (docs/design.md §3).
--
-- A key maps to exactly one user: the fingerprint (`SHA256:` + 43 base64
-- characters, what `ssh-keygen -lf` prints) is globally UNIQUE. It is a
-- public value, not a token hash, so the 0008 hash-shape triggers do not
-- apply. Keys go with their user (`ON DELETE CASCADE`); a disabled user's
-- keys are kept but inert (the lookup joins `forgs_user.state`).

CREATE TABLE forgs_ssh_key (
    id           TEXT NOT NULL PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES forgs_user (id) ON DELETE CASCADE,
    key_type     TEXT NOT NULL CHECK (key_type IN
                     ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ssh-rsa')),
    public_key   TEXT NOT NULL CHECK (public_key <> ''),
    fingerprint  TEXT NOT NULL UNIQUE
                     CHECK (fingerprint LIKE 'SHA256:%' AND length(fingerprint) = 50),
    title        TEXT NOT NULL CHECK (title <> ''),
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    expires      INTEGER
) STRICT;

CREATE INDEX forgs_ssh_key_by_user ON forgs_ssh_key (user_id);
CREATE INDEX forgs_ssh_key_by_expires ON forgs_ssh_key (expires);
