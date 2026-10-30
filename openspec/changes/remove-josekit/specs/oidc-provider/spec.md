## ADDED Requirements

### Requirement: JOSE signing does not use josekit

`identikey-oidc` and `identikey-oidc-client` SHALL sign and verify
EdDSA ID tokens without the `josekit` crate. The JOSE crate they use
SHALL NOT depend on `openssl`. An OKP Ed25519 private JWK produced by
the current signer SHALL still load and sign. A token signed that way
SHALL still verify in the client. A public-only JWK SHALL NOT sign.
Discovery, claim names, and the `signing.jwk` path SHALL stay as they
are. `webauthn-rs` MAY continue to depend on `openssl`.

#### Scenario: Existing signing JWK still signs

- GIVEN an OKP Ed25519 private JWK written by the current signer
- WHEN the OP loads it and signs an ID token
- THEN the client accepts that token and the process did not use josekit to sign it

#### Scenario: Public JWK cannot sign

- GIVEN an OKP Ed25519 JWK with no private scalar
- WHEN the OP tries to use it as a signing key
- THEN loading it as a signer fails

#### Scenario: webauthn keeps openssl

- GIVEN a lockfile after josekit is gone
- WHEN openssl edges are listed
- THEN `webauthn-rs-core` may still depend on openssl and neither OIDC crate does
