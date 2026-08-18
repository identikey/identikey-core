# Tasks

- [x] Discovery + JWKS serve on `identikey-server`
- [x] `/authorize` requires PKCE S256 and exact redirect; refuses implicit and ROPC
- [x] `/token` exchanges a one-time code; PKCE downgrade refused
- [x] `/userinfo` `/introspect` `/revoke` exist
- [x] Tests: discovery shape, PKCE required, code replay rejected

Not owed here (bullets, not boxes):

- Finishing login — `add-dev-authorize`
- OIDF job — `add-oidf-conformance`
- Hashed refresh lifecycle — `add-refresh-lifecycle`
