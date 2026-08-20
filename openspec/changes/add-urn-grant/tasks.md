# Tasks

- [x] Grant wire format cited:
      `identikey-protocol/docs/standards/identikey-oidc-urn-grant-v1.md`
      (depend on `identikey-auth`; do not fork the wire)
- [x] `/token` accepts the URN grant with an `identikey-auth`
      `Response`
- [x] A WebAuthn assertion at this grant is refused; no tokens
- [x] Issued `sub` goes through `subject()`
- [x] Tests: valid Response mints; assertion rejected; replay of
      the nonce rejected

Not owed here (bullets, not boxes):

- WebAuthn at `/authorize` — `add-passkey-ceremonies`
- Confidential clients — `add-confidential-clients`
- Holding a user private key in `identikey-oidc`
