-- identikey-core-zan.1
--
-- The store the rest of the product sits on. Four load-bearing facts:
--
--   1. The account key is a XID (ADR-001): 32-byte SHA-256 of the inception
--      key's CBOR. Never a pairwise sub (ADR-009 — that is a token-boundary
--      projection). Never a key fingerprint (that made PQ migration an
--      identity break).
--   2. C1/C2 hold a managed key blob; C0/C3/C4 must not (I3). Climbing the
--      ladder without dropping the server copy is a half-migration.
--   3. consent_log is append-only and hash-chained. C2 is "we cannot sign
--      without an authenticated instruction you can audit." A log we can
--      rewrite is C1 with extra steps.
--   4. AAGUID is a UX hint (passkey-requirements R3). No CHECK or policy
--      branch may mention it.
--
-- We do not import identikey-storage-auth. That crate is AGPL and depends
-- on recrypt; sharing a workspace with it collapses the commercial licence
-- (LEARNINGS 2026-07-28). The consent log takes the hash-chain *pattern*
-- and nothing else.
--
-- Out of this file on purpose: OIDC clients/tokens (ccf.*), device records
-- (zan.8), guardian tables (vt4), pairwise salt (88b), envelope encryption
-- of managed_key_blob.

-- ---------------------------------------------------------------------------
-- accounts
-- ---------------------------------------------------------------------------

CREATE TABLE accounts (
    xid         bytea PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    display_name text,
    email       text,
    email_verified_at timestamptz,
    phone       text,
    phone_verified_at timestamptz,
    disabled_at timestamptz,
    CONSTRAINT accounts_xid_len CHECK (octet_length(xid) = 32)
);

COMMENT ON TABLE accounts IS
    'One row per identity we persist state about. Keyed by XID, not by email and not by pairwise sub.';
COMMENT ON COLUMN accounts.xid IS
    '32-byte XID (SHA-256 of the inception public signing key''s CBOR). Canonical internal identity.';
COMMENT ON COLUMN accounts.email IS
    'A1 account-recovery destination. Never a path to key material (I2).';

CREATE UNIQUE INDEX accounts_email_lower_unique
    ON accounts (lower(email))
    WHERE email IS NOT NULL;

CREATE UNIQUE INDEX accounts_phone_unique
    ON accounts (phone)
    WHERE phone IS NOT NULL;

-- ---------------------------------------------------------------------------
-- credentials — access methods (A0–A4), not identity
-- ---------------------------------------------------------------------------

CREATE TABLE credentials (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    xid                     bytea NOT NULL REFERENCES accounts (xid),
    kind                    text NOT NULL,
    nickname                text,
    created_at              timestamptz NOT NULL DEFAULT now(),
    last_used_at            timestamptz,
    revoked_at              timestamptz,

    -- kind = passkey (A3)
    webauthn_credential_id  bytea,
    cose_public_key         bytea,
    sign_counter            bigint,
    transports              text[],
    aaguid                  bytea,
    backed_up               boolean,

    -- kind = oidc_apple | oidc_google (A2)
    issuer                  text,
    subject_at_issuer       text,

    -- kind = identikey_auth (A4): a device key that can authenticate *to us*.
    -- Not the managed Sign key. Never key material we can use to sign as the user.
    device_public_key       bytea,

    CONSTRAINT credentials_kind_known CHECK (
        kind IN ('passkey', 'oidc_apple', 'oidc_google', 'identikey_auth')
    ),
    CONSTRAINT credentials_kind_shape CHECK (
        (kind = 'passkey'
            AND webauthn_credential_id IS NOT NULL
            AND cose_public_key IS NOT NULL
            AND sign_counter IS NOT NULL
            AND issuer IS NULL
            AND subject_at_issuer IS NULL
            AND device_public_key IS NULL)
        OR
        (kind IN ('oidc_apple', 'oidc_google')
            AND issuer IS NOT NULL
            AND subject_at_issuer IS NOT NULL
            AND webauthn_credential_id IS NULL
            AND cose_public_key IS NULL
            AND sign_counter IS NULL
            AND device_public_key IS NULL)
        OR
        (kind = 'identikey_auth'
            AND device_public_key IS NOT NULL
            AND webauthn_credential_id IS NULL
            AND issuer IS NULL
            AND subject_at_issuer IS NULL)
    ),
    CONSTRAINT credentials_aaguid_len CHECK (
        aaguid IS NULL OR octet_length(aaguid) = 16
    ),
    CONSTRAINT credentials_webauthn_id_len CHECK (
        webauthn_credential_id IS NULL OR octet_length(webauthn_credential_id) > 0
    )
);

COMMENT ON TABLE credentials IS
    'Access methods. A passkey is A3 (auth to us), never the identity and never the managed key.';
COMMENT ON COLUMN credentials.aaguid IS
    'UX hint only (provider name/icon). Self-asserted; never a policy input.';
COMMENT ON COLUMN credentials.device_public_key IS
    'A4 device public key for authenticating TO this server. Not custody key material.';

CREATE INDEX credentials_xid_idx ON credentials (xid);

CREATE UNIQUE INDEX credentials_webauthn_credential_id_unique
    ON credentials (webauthn_credential_id)
    WHERE webauthn_credential_id IS NOT NULL;

CREATE UNIQUE INDEX credentials_federated_unique
    ON credentials (kind, issuer, subject_at_issuer)
    WHERE issuer IS NOT NULL;

-- ---------------------------------------------------------------------------
-- custody_records — current rung + current XID document
-- ---------------------------------------------------------------------------

CREATE TABLE custody_records (
    xid                 bytea PRIMARY KEY REFERENCES accounts (xid),
    rung                text NOT NULL,
    xid_document        bytea NOT NULL,
    managed_key_blob    bytea,
    successor_digest    bytea,
    entered_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT custody_rung_known CHECK (
        rung IN ('c0', 'c1', 'c2', 'c3', 'c4')
    ),
    -- I3: a self-custodial (or throwaway) row must not retain a server key.
    -- C1/C2 are the rungs at which we hold Sign; the blob is required there
    -- so a "C2 with no key" cannot be inserted by accident.
    CONSTRAINT custody_managed_key_matches_rung CHECK (
        (rung IN ('c1', 'c2') AND managed_key_blob IS NOT NULL)
        OR
        (rung IN ('c0', 'c3', 'c4') AND managed_key_blob IS NULL)
    ),
    CONSTRAINT custody_successor_digest_len CHECK (
        successor_digest IS NULL OR octet_length(successor_digest) = 32
    )
);

COMMENT ON TABLE custody_records IS
    'Current custody rung and current XID document. Privilege split lives in the document, not in extra columns.';
COMMENT ON COLUMN custody_records.managed_key_blob IS
    'Envelope-encrypted managed Sign+Auth material. Present at C1/C2 only. Encryption is a later task; the NULL constraint is the invariant.';
COMMENT ON COLUMN custody_records.successor_digest IS
    'Pre-rotation extension point (identikey-core-29v). NULL until a distinct successor custody domain exists.';
COMMENT ON COLUMN custody_records.xid_document IS
    'Current signed XID document. Source of truth for keys and privileges (ADR-007/008).';

-- ---------------------------------------------------------------------------
-- custody_events — explicit rung changes (I3 / I4)
-- ---------------------------------------------------------------------------

CREATE TABLE custody_events (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    xid             bytea NOT NULL REFERENCES accounts (xid),
    from_rung       text,
    to_rung         text NOT NULL,
    ceremony        text NOT NULL,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    consent_id      uuid,
    CONSTRAINT custody_events_to_rung_known CHECK (
        to_rung IN ('c0', 'c1', 'c2', 'c3', 'c4')
    ),
    CONSTRAINT custody_events_from_rung_known CHECK (
        from_rung IS NULL OR from_rung IN ('c0', 'c1', 'c2', 'c3', 'c4')
    )
);

COMMENT ON TABLE custody_events IS
    'Append-only history of custody-rung changes. Downward moves (I4) must appear here; silent demotion is a bug.';

CREATE INDEX custody_events_xid_occurred_idx
    ON custody_events (xid, occurred_at);

-- ---------------------------------------------------------------------------
-- consent_log — the C1/C2 line
-- ---------------------------------------------------------------------------

CREATE TABLE consent_log (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    xid             bytea NOT NULL REFERENCES accounts (xid),
    seq             bigint NOT NULL,
    prev_hash       bytea,
    entry_hash      bytea NOT NULL,
    recorded_at     timestamptz NOT NULL DEFAULT now(),

    action          text NOT NULL,
    audience        text,
    purpose         text,

    access_level    text NOT NULL,
    credential_id   uuid REFERENCES credentials (id),
    proof_kind      text NOT NULL,
    proof_bytes     bytea NOT NULL,
    proof_hash      bytea NOT NULL,
    result          text NOT NULL,

    CONSTRAINT consent_log_xid_seq UNIQUE (xid, seq),
    CONSTRAINT consent_seq_positive CHECK (seq >= 1),
    CONSTRAINT consent_entry_hash_len CHECK (octet_length(entry_hash) = 32),
    CONSTRAINT consent_proof_hash_len CHECK (octet_length(proof_hash) = 32),
    CONSTRAINT consent_prev_hash_len CHECK (
        prev_hash IS NULL OR octet_length(prev_hash) = 32
    ),
    CONSTRAINT consent_access_level_known CHECK (
        access_level IN ('a0', 'a1', 'a2', 'a3', 'a4')
    ),
    CONSTRAINT consent_proof_kind_known CHECK (
        proof_kind IN (
            'webauthn_assertion',
            'identikey_auth_response',
            'password',
            'email_link',
            'sms_otp',
            'oidc_assertion'
        )
    ),
    CONSTRAINT consent_result_known CHECK (
        result IN ('signed', 'refused', 'error')
    )
);

COMMENT ON TABLE consent_log IS
    'C2 consent: an authenticated instruction that we signed (or refused) on the user''s behalf. Append-only, hash-chained per account.';
COMMENT ON COLUMN consent_log.proof_bytes IS
    'The access-credential proof (WebAuthn assertion or identikey-auth Response). Not a signature by the managed Sign key.';
COMMENT ON COLUMN consent_log.entry_hash IS
    'SHA-256 of the v1 canonical encoding in identikey_keys::consent. Verified in-process; Postgres only chains prev_hash.';

CREATE INDEX consent_log_xid_recorded_idx
    ON consent_log (xid, recorded_at);

CREATE FUNCTION consent_log_enforce_chain() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    expected_seq bigint;
    expected_prev bytea;
BEGIN
    SELECT COALESCE(MAX(seq), 0) + 1
      INTO expected_seq
      FROM consent_log
     WHERE xid = NEW.xid;

    SELECT entry_hash
      INTO expected_prev
      FROM consent_log
     WHERE xid = NEW.xid
     ORDER BY seq DESC
     LIMIT 1;

    IF NEW.seq IS DISTINCT FROM expected_seq THEN
        RAISE EXCEPTION
            'consent_log seq must be contiguous for xid: expected %, got %',
            expected_seq, NEW.seq;
    END IF;

    IF expected_seq = 1 THEN
        IF NEW.prev_hash IS NOT NULL THEN
            RAISE EXCEPTION 'first consent_log entry must have NULL prev_hash';
        END IF;
    ELSIF NEW.prev_hash IS DISTINCT FROM expected_prev THEN
        RAISE EXCEPTION 'consent_log prev_hash does not match previous entry_hash';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER consent_log_chain
    BEFORE INSERT ON consent_log
    FOR EACH ROW
    EXECUTE FUNCTION consent_log_enforce_chain();

CREATE FUNCTION forbid_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER consent_log_no_update
    BEFORE UPDATE OR DELETE ON consent_log
    FOR EACH ROW
    EXECUTE FUNCTION forbid_mutation();

CREATE TRIGGER custody_events_no_update
    BEFORE UPDATE OR DELETE ON custody_events
    FOR EACH ROW
    EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------------------
-- challenges — WebAuthn / identikey-auth ceremony state
-- ---------------------------------------------------------------------------

CREATE TABLE challenges (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    xid         bytea REFERENCES accounts (xid),
    challenge   bytea NOT NULL,
    kind        text NOT NULL,
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    consumed_at timestamptz,
    CONSTRAINT challenges_kind_known CHECK (
        kind IN ('webauthn_register', 'webauthn_authenticate', 'identikey_auth')
    ),
    CONSTRAINT challenges_challenge_len CHECK (octet_length(challenge) > 0)
);

COMMENT ON TABLE challenges IS
    'Short-lived ceremony nonces. xid is NULL for discoverable-credential authentication.';
COMMENT ON COLUMN challenges.xid IS
    'NULL for usernameless (discoverable) WebAuthn authentication.';

CREATE UNIQUE INDEX challenges_challenge_unique ON challenges (challenge);
CREATE INDEX challenges_expires_at_idx ON challenges (expires_at);

ALTER TABLE custody_events
    ADD CONSTRAINT custody_events_consent_id_fkey
    FOREIGN KEY (consent_id) REFERENCES consent_log (id);
