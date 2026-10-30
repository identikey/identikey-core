# Tasks

- [ ] `identikey-oidc` and `identikey-oidc-client` no longer depend on `josekit`
- [ ] The replacement crate's lockfile edge does not include `openssl`
- [ ] An existing OKP Ed25519 `signing.jwk` still loads, signs, and verifies
- [ ] A public-only JWK cannot sign, and a token from another key fails verification
- [ ] `webauthn-rs-core` may still depend on `openssl`
- [ ] Fresh advise after preparation

## Out of scope

- Removing openssl from webauthn-rs.
- Signing-key rotation and claim changes.
