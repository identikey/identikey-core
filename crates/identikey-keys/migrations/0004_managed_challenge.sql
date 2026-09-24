-- Durable, one-shot C2 managed challenge signing attempts.
CREATE TABLE managed_challenge_attempts (
    request_id             uuid PRIMARY KEY,
    xid                    bytea NOT NULL REFERENCES accounts (xid),
    challenge_digest       bytea NOT NULL,
    challenge              bytea NOT NULL,
    verifier_commitment    bytea NOT NULL,
    proof_kind             text NOT NULL,
    webauthn_state         bytea,
    consent_iat            bigint NOT NULL,
    consent_exp            bigint NOT NULL,
    state                  text,
    credential_id          uuid REFERENCES credentials (id),
    consenting_public      bytea,
    consent_proof          bytea,
    response               bytea,
    failure                text,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT managed_challenge_digest_len CHECK (octet_length(challenge_digest) = 32),
    CONSTRAINT managed_challenge_verifier_len CHECK (octet_length(verifier_commitment) = 32),
    CONSTRAINT managed_challenge_proof_known CHECK (proof_kind IN ('a3', 'a4')),
    CONSTRAINT managed_challenge_state_known CHECK (
        state IS NULL OR state IN ('authorized', 'claimed', 'completed', 'failed', 'indeterminate')
    ),
    CONSTRAINT managed_challenge_response_state CHECK (
        (state = 'completed' AND response IS NOT NULL) OR
        (state IS DISTINCT FROM 'completed' AND response IS NULL)
    ),
    CONSTRAINT managed_challenge_replay UNIQUE (xid, challenge_digest)
);

CREATE INDEX managed_challenge_xid_created_idx
    ON managed_challenge_attempts (xid, created_at);

COMMENT ON TABLE managed_challenge_attempts IS
    'Immutable challenge/client binding plus the one-shot managed signing state machine.';

CREATE FUNCTION managed_challenge_binding_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.xid IS DISTINCT FROM OLD.xid
       OR NEW.challenge_digest IS DISTINCT FROM OLD.challenge_digest
       OR NEW.challenge IS DISTINCT FROM OLD.challenge
       OR NEW.verifier_commitment IS DISTINCT FROM OLD.verifier_commitment
       OR NEW.proof_kind IS DISTINCT FROM OLD.proof_kind
       OR NEW.consent_iat IS DISTINCT FROM OLD.consent_iat
       OR NEW.consent_exp IS DISTINCT FROM OLD.consent_exp THEN
        RAISE EXCEPTION 'managed challenge binding is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER managed_challenge_binding_no_update
    BEFORE UPDATE ON managed_challenge_attempts
    FOR EACH ROW
    EXECUTE FUNCTION managed_challenge_binding_immutable();
