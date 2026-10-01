-- Refresh sessions outlive the OP process and service VM. Raw bearer secrets
-- never enter the database. Rotation replaces the hash atomically; revocation
-- deletes it. Issuer namespaces sessions when a database hosts multiple OPs.
CREATE TABLE oidc_refresh_sessions (
    issuer text NOT NULL,
    token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
    client_id text NOT NULL,
    xid bytea NOT NULL CHECK (octet_length(xid) = 32),
    sub text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    refreshed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, token_hash)
);
