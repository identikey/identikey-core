# Design — pairwise salt

Security-sensitive secret. Same class as the JWT signing key.

## Generation

- 32 random bytes from the OS CSPRNG at first boot if unset.
- Fail boot if the operator set an empty value or a well-known
  placeholder (`changeme`, all-zero).
- Never commit a default in `.env.example` beyond a commented
  `IDENTIKEY_PAIRWISE_SALT=` with a warning.

## Storage

- Env or the same secret store as the signing key. Not Postgres
  (a DB dump would publish every user's correlation key).
- Never appear in `tracing` fields, error strings, or `/health`.

## KDF

Named by `docs/oidc-implementation-checklist.md`. Until that file
exists, do not implement this change.
