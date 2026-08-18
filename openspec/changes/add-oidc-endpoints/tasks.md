# Tasks

- [ ] Discovery + JWKS serve on `identikey-server`
- [ ] `/authorize` requires PKCE S256 and exact redirect; refuses implicit and ROPC
- [ ] `/token` exchanges a one-time code; PKCE downgrade refused
- [ ] `/userinfo` `/introspect` `/revoke` exist
- [ ] Tests: discovery shape, PKCE required, code replay rejected

Not owed here (bullets, not boxes):

- Finishing login — `add-dev-authorize`
- OIDF job — `add-oidf-conformance`
- Hashed refresh lifecycle — `add-refresh-lifecycle`
