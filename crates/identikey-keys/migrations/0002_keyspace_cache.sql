-- add-keyspace-runtime
--
-- Optional materialization of applied keyspace roster/epoch/wraps.
-- This is a cache of identikey-log replicas, not the home (ADR-012).
-- Deleting these rows must not prevent holders from continuing the
-- keyspace from their log replicas.

CREATE TABLE keyspace_cache (
    keyspace_id bytea PRIMARY KEY,
    epoch       bigint NOT NULL,
    profile     text NOT NULL,
    faded       boolean NOT NULL,
    roster      jsonb NOT NULL DEFAULT '[]'::jsonb,
    wraps       jsonb NOT NULL DEFAULT '[]'::jsonb,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT keyspace_cache_id_len CHECK (octet_length(keyspace_id) = 32)
);

COMMENT ON TABLE keyspace_cache IS
    'Cache of applied keyspace.* ops. Not the source of truth. identikey-log replicas are.';
COMMENT ON COLUMN keyspace_cache.keyspace_id IS
    'identikey-log content_hash of the genesis op (32 bytes).';
