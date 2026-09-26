# add-hybrid-transport

> **ACTIVE BUILD**

Bead `identikey-core-5gh.5`. Steer 2026-09-26. Activated in chat
2026-09-26.

**Preparation:** still valid. `passkey_manager_compat` already strips
`hints` and `authenticatorAttachment` so a platform-only hint cannot
hide 1Password, iCloud, or Google Password Manager. It does not ask
the browser for the hybrid (caBLE) transport. The living passkey
requirement forbids hints that prefer a platform authenticator only.
Authority: Duke said "activate" for this bead and for `5gh.2` only.

## Why

A phone and a computer can already complete WebAuthn over the
platform hybrid transport. The hosted ceremonies never ask for it,
and this repo must not invent a second QR protocol.

## What

- Registration and assertion options include the standard `hybrid`
  hint, together with the other transports, and still omit
  `authenticatorAttachment`.
- They MUST NOT send a hint list that is only `client-device`.
- No new QR page, no custom encoding, and no caBLE implementation of
  our own. The browser draws the QR.
- Capability: MODIFIED `passkeys`.

## Impact

- Capabilities: MODIFIED `passkeys`
- ADRs: none

## User journey & surfaces

On `GET /authorize/passkey` and on signup, the browser's passkey
sheet can offer a phone. The person scans the browser's own QR and
finishes on the phone. There is no IdentiKey QR page. If the browser
has no hybrid support, the existing on-device and password-manager
choices still work. The signed-out account page is unchanged.

## Out of scope

- A bespoke QR protocol or a temporary-device ceremony of our own
- Passkey names and icons — `add-passkey-legibility`
- Signal APIs — `identikey-core-5gh.3`
- Counter regression — `identikey-core-5gh.4`
