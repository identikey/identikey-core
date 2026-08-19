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

The bead requires the grant spec in
`identikey-protocol/docs/standards/` before implementation. If that
file is not in this repo, this change's first owed box is to write
or cite it (sibling repo or a draft under `docs/` that the protocol
repo will take). Do not invent a second wire format.

## Token minting

Same `/token` endpoint, `grant_type` =
`urn:identikey:params:oauth:grant-type:challenge-response`.
`sub` from `subject()`. Refresh hashed as today. PKCE does not
apply to this grant (no authorize redirect).
