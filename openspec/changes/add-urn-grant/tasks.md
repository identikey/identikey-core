# Tasks

- [ ] Grant wire format cited:
      `identikey-protocol/docs/standards/identikey-oidc-urn-grant-v1.md`
      (depend on `identikey-auth`; do not fork the wire)
- [ ] `/token` accepts the URN grant with an `identikey-auth`
      `Response`
- [ ] A WebAuthn assertion at this grant is refused; no tokens
- [ ] Issued `sub` goes through `subject()`
- [ ] Tests: valid Response mints; assertion rejected; replay of
      the nonce rejected

Not owed here (bullets, not boxes):

- WebAuthn at `/authorize` — `add-passkey-ceremonies`
- Confidential clients — `add-confidential-clients`
- Holding a user private key in `identikey-oidc`
