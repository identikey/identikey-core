# remove-josekit

> **PENDING**

Bead from `identikey-core-ccf.10`. Steer 2026-10-30.
**Rigor:** architecture

**Preparation:** 2026-10-30. `josekit` 0.10.3 is the JOSE crate in
`identikey-oidc` and `identikey-oidc-client`, and `Cargo.lock` shows
it depends on `openssl`. The same lock shows `openssl` also under
`webauthn-rs-core`, `webauthn-authenticator-rs`, and
`webauthn-attestation-ca`. Call sites are EdDSA only: generate and
load an OKP Ed25519 JWK, sign an ID token, publish a public JWKS, and
verify that token. Outcome: new contract. Authority: none.

## Why

`identikey-core-ccf.10` asks whether linking both openssl and rustls
is a decision or an accident. The webauthn-rs edge is the maintained
Rust WebAuthn stack. The josekit edge is a choice. ID tokens are
EdDSA. That choice can drop its openssl dependency without changing
the token.

## What

- Remove `josekit` from `identikey-oidc` and `identikey-oidc-client`.
- Keep EdDSA OKP Ed25519: the same `signing.jwk` file and env JWK still
  load, sign, and verify. Discovery and claim shape stay.
- The replacement JOSE crate SHALL NOT depend on `openssl`.
- `webauthn-rs` keeps its openssl link. This change does not make the
  graph a single crypto backend.
- Capability: ADDED requirement on `oidc-provider`.

## Impact

- Capabilities: `oidc-provider` gains one requirement. No living
  requirement is rewritten.
- ADRs: none

## User journey & surfaces

No new UI because discovery, the token endpoint, and the JWKS URL stay
the surfaces a client already uses.

Working: a current `signing.jwk` still signs, and the client still
accepts that token.

Empty: no second signing algorithm appears in discovery.

Failed: a public-only JWK still cannot sign. A token signed by a
different key still fails verification.

Off: passkey registration still uses webauthn-rs, which still links
openssl.

## Out of scope

- Replacing `webauthn-rs` or its openssl stack. `identikey-core-ccf.10`
  keeps that edge.
- Signing-key overlap and retirement. `add-oidc-signing-rotation`.
- Changing EdDSA, the `kid`, or ID-token claims.
- Post-quantum token signatures.
