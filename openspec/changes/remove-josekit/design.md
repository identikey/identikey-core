# remove-josekit

## What moves

`SigningKey` in `crates/identikey-oidc/src/signing.rs` and the EdDSA
verifier in `crates/identikey-oidc-client/src/lib.rs` stop importing
`josekit`. The public behavior of those types stays: generate, load a
private OKP Ed25519 JWK from JSON, expose `kid` and a public JWKS, and
sign an ID token with `iss`, `sub`, `aud`, `iat`, `exp`, and optional
`nonce`.

The client still checks EdDSA, issuer, audience, expiry, and optional
nonce.

## Replacement

One maintained JOSE crate whose resolved dependency tree does not
include `openssl`. It has to read and write the JWK JSON this process
already stores (`kty` OKP, `crv` Ed25519, `alg` EdDSA, `use` sig, `kid`).
The crate name is fixed in this design before code lands, after a lockfile
check. It is not josekit and it is not a JOSE implementation written in
this repo.

`Cargo.lock` after the swap has no `josekit` package. `identikey-oidc`
and `identikey-oidc-client` do not depend on `openssl`. `webauthn-rs-core`
still does.

## What stays

Discovery text, grant types, and the signing-key file path
`signing.jwk`. A file written by today's binary loads in the new one.
A token signed by today's binary still verifies.

`add-oidc-signing-rotation` remains the overlap rule. This change does
not publish a second `kid` and does not retire one.
