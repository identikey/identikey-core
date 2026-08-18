# Design — code+PKCE endpoints

Cite `docs/oidc-implementation-checklist.md`. Do not implement a
grant that file refuses.

## Metadata

`issuer` is the public origin (HTTPS in prod; loopback allowed in
dev). Advertise `response_types_supported: ["code"]`,
`code_challenge_methods_supported: ["S256"]`,
`subject_types_supported: ["pairwise", "public"]`. Do not advertise
`token`, `id_token`, or `password`.

## `/authorize`

Exact redirect match. Require `code_challenge` + `S256`. CORS off.
Does not mint tokens. Completing the login is `add-dev-authorize`.

## `/token`

Require `code_verifier` if a challenge was stored (always, in v1).
Reject verifier without a prior challenge (PKCE downgrade).
Authorization codes are one-time; a replay invalidates tokens from
that code.

## Signing

EdDSA / Ed25519 via `josekit`, JWKS from the same key. `identikey-oidc`
never holds a *user* private key.
