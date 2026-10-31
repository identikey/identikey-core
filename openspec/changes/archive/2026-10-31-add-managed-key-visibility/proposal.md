# add-managed-key-visibility

> **ACTIVE BUILD**

Node `identikey-core-zlf.8`. Depends on the folded account key model.
Activation needs a human. The first-wave grant does not cover it.

## Why

The server-held Sign key is easy to mistake for a device. The account
page lists passkeys and does not say that IdentiKey holds an
operational key, or that the page cannot revoke that key.

## What

- Capability `managed-custody`.
- A signed-in account page shows the Ed25519 operational public key
  from the custody record, labeled as held by IdentiKey, apart from
  the device list.
- The page offers no revoke, export, or rotate control for that key.
- An account whose operational key is still Schnorr, from before
  `35aee29`, is labeled as not usable for the responder.
- The page shows the public key only. It does not show
  `managed_key_blob` or any private seed.

## Impact

- Capabilities: ADDED `managed-custody`.
- ADRs: none. Distinct from OP signing-key rotation
  (`add-oidc-signing-rotation`).

## User journey & surfaces

Who: a person signed in at `GET /account`.

Working: the page shows the server-held key apart from passkey rows,
with no revoke control on that key.

Empty: an account with no operational public key shows that absence
and still lists devices as they are.

Failed: a signed-out request does not show the key. The page does
not offer a control that clears `managed_key_blob`.

Off: until this change is activated and built, the page stays as it
is.

## Out of scope

- Exporting or rotating the operational key.
- OP JWKS rotation (`identikey-core-ccf.9`).
- Adding, renaming, or revoking passkeys (`identikey-core-zlf.6`).
