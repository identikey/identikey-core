# Tasks

- [ ] Confidential clients authenticate with `client_secret_basic`
      and `client_secret_post`; secrets stored hashed
- [ ] Two `basic` clients and one `post` client can be registered
- [ ] Discovery lists `none`, `client_secret_basic`,
      `client_secret_post`
- [ ] PKCE `S256` still required when a secret is used
- [ ] Documented `oidcc-basic-certification-test-plan` command and
      login automation
- [ ] Tests: secret mismatch refused; public client without secret
      still works with PKCE

Not owed here (bullets, not boxes):

- Required Basic OP CI job
- DCR
- URN grant — `add-urn-grant`
- Passkeys — `add-passkey-ceremonies`
