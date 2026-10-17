-- Single-use record of exchanged workload JWTs (security audit 2026-10,
-- IDP-5: replay defence).
--
-- Keyed per issuer: a `jti` is only unique within one issuer. A row is kept
-- until the JWT stops verifying (`exp` + leeway), after which the JWT is
-- refused anyway; the sweep removes it then.
CREATE TABLE forgs_workload_jti (
    issuer     TEXT    NOT NULL CHECK (issuer <> ''),
    jti        TEXT    NOT NULL CHECK (jti <> ''),
    subject    TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    expires    INTEGER NOT NULL,
    PRIMARY KEY (issuer, jti)
) STRICT;
CREATE INDEX forgs_workload_jti_by_expires ON forgs_workload_jti (expires);
