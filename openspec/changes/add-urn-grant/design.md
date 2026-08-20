# Design — URN grant (A4 only)

Security: one proof format, one verifier. The grant proves "I hold
the IdentiKey key," not "I hold a passkey on an account."

## Proof

Accept only an `identikey-auth` `Response` (domain-separated dCBOR,
verifier nonce, audience-bound). Reject WebAuthn assertion bytes
before any token is minted. Do not share parsers with A3.

`identikey-oidc` still must not hold a *user* private key. The OP
verifies the Response and mints; custody stays in `identikey-keys`
/ the user's device.

## Spec first

Grant spec is
`identikey-protocol/docs/standards/identikey-oidc-urn-grant-v1.md`
(2026-08-19). Proof bytes are
`identikey-auth-challenge-v1.md` §8.1 (wallet or managed operator).
Do not invent a second wire format. First owed box is cite-and-depend,
not a new draft.

## Token minting

Same `/token` endpoint, `grant_type` =
`urn:identikey:params:oauth:grant-type:challenge-response`.
`sub` from `subject()`. Refresh hashed as today. PKCE does not
apply to this grant (no authorize redirect).
