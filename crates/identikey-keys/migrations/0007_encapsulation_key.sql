-- Held user X25519 scalar for C2 rows created after this migration.
-- Nullable at C2 so rows written earlier stay inert. Every other rung
-- must be null. This is not managed_key_blob.

ALTER TABLE custody_records
    ADD COLUMN encapsulation_key_blob bytea;

ALTER TABLE custody_records
    ADD CONSTRAINT custody_encapsulation_key_rung CHECK (
        rung = 'c2' OR encapsulation_key_blob IS NULL
    );

COMMENT ON COLUMN custody_records.encapsulation_key_blob IS
    'IKEK v1 envelope of the user X25519 scalar (c2_wrap_recipient). C2 only, and null for rows created before the seal. Not the operational companion and not managed_key_blob.';

-- One-shot consent to export that scalar or unwrap one wrap.
CREATE TABLE encapsulation_attempts (
    id                 uuid PRIMARY KEY,
    xid                bytea NOT NULL REFERENCES accounts (xid),
    purpose            text NOT NULL,
    webauthn_challenge bytea NOT NULL,
    webauthn_state     bytea,
    wrap_digest        bytea,
    iat                bigint NOT NULL,
    exp                bigint NOT NULL,
    used_at            timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT encapsulation_purpose_known CHECK (purpose IN ('export', 'unwrap')),
    CONSTRAINT encapsulation_challenge_len CHECK (octet_length(webauthn_challenge) > 0),
    CONSTRAINT encapsulation_wrap_digest CHECK (
        (purpose = 'unwrap' AND octet_length(wrap_digest) = 32)
        OR
        (purpose = 'export' AND wrap_digest IS NULL)
    )
);

CREATE INDEX encapsulation_attempts_xid_created_idx
    ON encapsulation_attempts (xid, created_at);

COMMENT ON TABLE encapsulation_attempts IS
    'Single-use encapsulation consent. Export and unwrap consume the row in the same transaction as the key use.';
