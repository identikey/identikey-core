# Design — social identity-token verifier

**Change:** `add-social-id-token-verify`
**Bead:** `identikey-core-ccf.6`

## Home

A new crate. `openidconnect` 4 verifies the RS256 identity token and
holds the provider JWKS. `identikey-oidc-client` keeps verifying
IdentiKey-issued EdDSA tokens with josekit. Putting RSA verification
in that crate would make every IdentiKey RP depend on the social
IdPs.

## Check

The caller passes the provider (Apple or Google), the compact token,
and the audience (Apple Services ID or Google client id). Audience is
required. There is no env fallback in the library.

Accept only RS256. Pin the issuer set from the TypeScript verifiers.
Expiry uses a 5 second skew. Optional profile claims are returned
when present and omitted when absent. Apple's email is often absent
after the first token. That is success, not an error.

## Cache

One JWKS document per provider. A known `kid` is served from the
cache. An unknown `kid` fetches that provider's JWKS once, replaces
the cache, and looks again. A second miss, or a fetch failure, is an
error. Tests inject the document so they do not touch the network.

## Not this crate

No account row, no HTTP route, and no passkey ceremony. A successful
verify is not authorization to use a managed key.
