-- Recovery-address verification only. Never a credential or key-use proof.
CREATE TABLE email_magic_links (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    xid bytea NOT NULL REFERENCES accounts (xid),
    email text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now() + interval '15 minutes'
);

CREATE INDEX email_magic_links_expires_idx ON email_magic_links (expires_at);
