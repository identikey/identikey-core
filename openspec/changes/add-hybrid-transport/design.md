# Design — hybrid transport

**Change:** `add-hybrid-transport`
**Bead:** `identikey-core-5gh.5`

## Options

`passkey_manager_compat` keeps removing `authenticatorAttachment` and
keeps requiring a discoverable credential. It stops deleting `hints`.
The hint list is `hybrid`, `security-key`, and `client-device`, in
that order. A list of only `client-device` stays forbidden. webauthn-rs
and the browser speak caBLE. This server does not.

## What does not change

No new route. No QR rendering. Password-manager registration still
works because nothing forces a platform attachment.
