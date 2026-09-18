-- Hosted-being git signing keys. Not OP auth (identikey_auth).
-- device_public_key is the SSH public key bytes (OpenSSH or raw).

ALTER TABLE credentials DROP CONSTRAINT credentials_kind_known;
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_shape;

ALTER TABLE credentials ADD CONSTRAINT credentials_kind_known CHECK (
    kind IN ('passkey', 'oidc_apple', 'oidc_google', 'identikey_auth', 'ssh_git')
);

ALTER TABLE credentials ADD CONSTRAINT credentials_kind_shape CHECK (
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
    OR
    (kind = 'ssh_git'
        AND device_public_key IS NOT NULL
        AND webauthn_credential_id IS NULL
        AND cose_public_key IS NULL
        AND sign_counter IS NULL
        AND issuer IS NULL
        AND subject_at_issuer IS NULL)
);

COMMENT ON COLUMN credentials.device_public_key IS
    'A4 device public key (identikey_auth) OR OpenSSH git-signing pubkey (ssh_git). Never a private key.';
