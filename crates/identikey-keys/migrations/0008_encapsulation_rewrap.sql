-- Friend rewrap. A rewrap attempt stores the friend XID and the recipient
-- captured from that friend's document. Export stores neither. Unwrap
-- stores only the wrap digest. Do not edit 0007: that migration has run.

ALTER TABLE encapsulation_attempts
    ADD COLUMN friend_xid bytea,
    ADD COLUMN recipient bytea;

ALTER TABLE encapsulation_attempts
    DROP CONSTRAINT encapsulation_purpose_known;

ALTER TABLE encapsulation_attempts
    ADD CONSTRAINT encapsulation_purpose_known CHECK (
        purpose IN ('export', 'unwrap', 'rewrap')
    );

ALTER TABLE encapsulation_attempts
    DROP CONSTRAINT encapsulation_wrap_digest;

ALTER TABLE encapsulation_attempts
    ADD CONSTRAINT encapsulation_wrap_digest CHECK (
        (
            purpose = 'unwrap'
            AND octet_length(wrap_digest) = 32
            AND friend_xid IS NULL
            AND recipient IS NULL
        )
        OR (
            purpose = 'export'
            AND wrap_digest IS NULL
            AND friend_xid IS NULL
            AND recipient IS NULL
        )
        OR (
            purpose = 'rewrap'
            AND octet_length(wrap_digest) = 32
            AND octet_length(friend_xid) = 32
            AND octet_length(recipient) = 32
        )
    );

COMMENT ON COLUMN encapsulation_attempts.friend_xid IS
    'Friend account for purpose rewrap. Null for export and unwrap.';

COMMENT ON COLUMN encapsulation_attempts.recipient IS
    'Friend X25519 captured at begin for purpose rewrap. Null otherwise.';
