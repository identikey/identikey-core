# Tasks

- [ ] Grant wire format written or cited (`identikey-protocol`
      standards, or a draft path named here)
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
