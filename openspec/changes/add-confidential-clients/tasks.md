# Tasks

- [x] Confidential clients authenticate with `client_secret_basic`
      and `client_secret_post`; secrets stored hashed
- [x] Two `basic` clients and one `post` client can be registered
- [x] Discovery lists `none`, `client_secret_basic`,
      `client_secret_post`
- [x] PKCE `S256` still required when a secret is used
- [x] Documented `oidcc-basic-certification-test-plan` command and
      login automation
- [x] Tests: secret mismatch refused; public client without secret
      still works with PKCE

Not owed here (bullets, not boxes):

- Required Basic OP CI job
- DCR
- URN grant — `add-urn-grant`
- Passkeys — `add-passkey-ceremonies`
