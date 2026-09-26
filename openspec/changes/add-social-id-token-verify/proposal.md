# add-social-id-token-verify

> **PENDING**

Bead `identikey-core-ccf.6`. Steer 2026-09-26.

**Preparation:** still valid. Behavior source is
`web/src/lib/auth/provider-jwks/provider-jwks.ts`,
`web/src/lib/auth/apple/verify.ts`, and
`web/src/lib/auth/google/verify.ts`. `identikey-oidc-client` verifies
EdDSA tokens for an IdentiKey issuer and is the wrong home for RS256
Apple/Google keys. Authority: none (bare `/run` is not a grant).

## Why

Apple and Google identity tokens are how a C1/C2 account can be
checked once at signup (access level A2). The check exists only in
the TypeScript web tree. The Rust tree cannot verify those tokens.
`identikey-oidc-client` is EdDSA-only and must stay that way.

## What

- Add a library crate that verifies an Apple or Google identity token
  with `openidconnect` 4 (ramosbugs).
- Cache each provider's JWKS and refresh once when the token's `kid`
  is missing.
- Check RS256, the pinned issuer, a caller-supplied audience, and
  expiry (5 second skew). Return the same claims the TypeScript
  verifiers return.
- Capability: ADDED `social-id`.

## Impact

- Capabilities: ADDED `social-id`
- ADRs: none

## User journey & surfaces

No new UI because this crate does not serve a page or an HTTP route.
Callers in a later signup flow will use it. The TypeScript verifiers
under `web/src/lib/auth/` remain until the Rust tests pass.

## Out of scope

- `POST /apple-provision` and `POST /google-provision`, account
  creation, and passkey enrollment. Not this bead.
- Teaching `identikey-oidc-client` RS256.
- Treating a social token as A3 or A4 consent for managed signing.
- Deleting the TypeScript verifiers.
