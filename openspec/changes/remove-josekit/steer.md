# steer remove-josekit

**When.** 2026-10-30
**Depth.** standard

## Decided
- Landing: replace josekit (user)
  Why: ID tokens are EdDSA. josekit 0.10.3 is the openssl edge that is a choice. webauthn-rs is the edge that stays.

## Skipped
- Which replacement crate. Named before code, from a lockfile check, not invented here.

## Feeds change
Remove josekit from the OP signer and the OIDC client. Keep the current JWK file and EdDSA tokens working. Do not claim the process has one crypto backend while webauthn-rs still links openssl.

## Auto
- No in-repo JOSE implementation.
- `add-oidc-signing-rotation` is not edited.
