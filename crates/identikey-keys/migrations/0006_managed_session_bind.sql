-- Preserve shipped attempts as legacy rows; no invented consent inputs.
ALTER TABLE managed_challenge_attempts
    ADD COLUMN session_public_key bytea,
    ADD COLUMN operation text[],
    ADD COLUMN resource text[],
    ADD COLUMN channel bytea,
    ADD COLUMN bind_signature bytea,
    ADD CONSTRAINT managed_channel_len CHECK (octet_length(channel) = 32),
    ADD CONSTRAINT managed_bind_signature_len CHECK (octet_length(bind_signature) = 64);

-- Withdraw old completed results, which have no consented session bind.
ALTER TABLE managed_challenge_attempts DROP CONSTRAINT managed_challenge_response_state;
UPDATE managed_challenge_attempts SET state = 'failed', response = NULL,
    failure = 'legacy attempt has no session bind'
    WHERE state = 'completed';
ALTER TABLE managed_challenge_attempts ADD CONSTRAINT managed_challenge_response_state CHECK (
    (state IS NOT DISTINCT FROM 'completed' AND response IS NOT NULL AND bind_signature IS NOT NULL
        AND session_public_key IS NOT NULL AND operation IS NOT NULL
        AND resource IS NOT NULL AND channel IS NOT NULL) OR
    (state IS DISTINCT FROM 'completed' AND response IS NULL AND bind_signature IS NULL)
);

CREATE OR REPLACE FUNCTION managed_challenge_binding_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.xid IS DISTINCT FROM OLD.xid
       OR NEW.challenge_digest IS DISTINCT FROM OLD.challenge_digest
       OR NEW.challenge IS DISTINCT FROM OLD.challenge
       OR NEW.verifier_commitment IS DISTINCT FROM OLD.verifier_commitment
       OR NEW.session_public_key IS DISTINCT FROM OLD.session_public_key
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.resource IS DISTINCT FROM OLD.resource
       OR NEW.channel IS DISTINCT FROM OLD.channel
       OR NEW.proof_kind IS DISTINCT FROM OLD.proof_kind
       OR NEW.consent_iat IS DISTINCT FROM OLD.consent_iat
       OR NEW.consent_exp IS DISTINCT FROM OLD.consent_exp THEN
        RAISE EXCEPTION 'managed challenge binding is immutable';
    END IF;
    RETURN NEW;
END;
$$;

