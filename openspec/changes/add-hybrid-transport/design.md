# Design — hybrid transport

**Change:** `add-hybrid-transport`
**Bead:** `identikey-core-5gh.5`

## Options

`passkey_manager_compat` keeps removing `authenticatorAttachment` and
keeps requiring a discoverable credential. It stops deleting `hints`.
The hint list is `client-device`, `hybrid`, and `security-key`, in
that order. The list is empty or those three values. A one-value or
two-value list is rejected by the contract, including a list that is
only `client-device` and a list that is only `hybrid`. `hybrid` is
not first, because a hint list is ordered by preference and a
phone-first list puts the QR sheet ahead of a local or synced
passkey. webauthn-rs and the browser speak caBLE. This server does
not. A phone-to-computer ceremony is not verified on hardware.

## What does not change

No new route. No QR rendering. Password-manager registration still
works because nothing forces a platform attachment.
