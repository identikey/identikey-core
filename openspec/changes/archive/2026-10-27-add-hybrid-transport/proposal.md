# add-hybrid-transport

> **ACTIVE BUILD**

Bead `identikey-core-5gh.5`. Steer 2026-09-26. Activated in chat
2026-09-26.

**Preparation:** revised 2026-10-27 after `reviews/2026-10-27-advise.md` send-back. Hint order is `client-device`, `hybrid`, `security-key`. The list is empty or all three. Why is a sheet-order nudge. Not verified on hardware. Fresh advise is owed. `passkey_manager_compat` already strips
`hints` and `authenticatorAttachment` so a platform-only hint cannot
hide 1Password, iCloud, or Google Password Manager. It does not ask
the browser for the hybrid (caBLE) transport. The living passkey
requirement forbids hints that prefer a platform authenticator only.
Authority: Duke said "activate" for this bead and for `5gh.2` only.

## Why

The hosted passkey sheet should be able to nudge a phone (the
browser's own hybrid QR) without putting that phone ahead of a local
or synced passkey. This repo does not invent a second QR protocol.
Whether any current browser hides hybrid until a hint is present was
not established; the change is the sheet-order nudge.

## What

- Registration and assertion options include all three hints, in this
  order: `client-device`, `hybrid`, `security-key`. The list is empty
  or those three values. It is never one or two values, and `hybrid`
  is not first.
- They still omit `authenticatorAttachment`.
- No new QR page, no custom encoding, and no caBLE implementation of
  our own. The browser draws the QR.
- A phone-to-computer ceremony has not been verified on hardware.
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
