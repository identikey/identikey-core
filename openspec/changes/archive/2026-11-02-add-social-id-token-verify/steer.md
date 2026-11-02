# steer add-social-id-token-verify

**When.** 2026-09-26
**Depth.** standard

## Decided

- Scope: library only (user). No provision routes, no account creation, no passkey enrollment.
  Why: the bead is the client-side verifier. Binding a social `sub` to a XID is a later trust decision.
- Home: new crate on `openidconnect` 4 (user). `identikey-oidc-client` stays EdDSA-only.
  Why: Apple and Google tokens are RS256. Folding that into the IdentiKey RP client couples every RP to those IdPs.

## Skipped

- (none)

## Auto

- One node covers Apple and Google. Source is `web/src/lib/auth/`.
- The TypeScript verifiers stay until the Rust tests pass.
- A verified social token is not managed-signing consent.

## Feeds change

Scaffold a PENDING library change. Do not activate it. Do not add HTTP routes or account rows. Do not edit `identikey-oidc-client`.
