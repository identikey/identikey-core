# add-recovery-authority

> **ACTIVE BUILD**

Node `identikey-core-zlf.2`. Depends on the folded account key model
(`identikey-core-zlf.1`, archive `2026-10-31-add-account-key-model`).
Steer 2026-10-30: a passkey enrolled by email recovery is an ordinary
A3 passkey. The mailbox ceremony is the limited step. This node is a
human gate. The first-wave grant does not activate it.

## Why

Recovery has to be able to put a person back on the account without
becoming a second way to use the server-held Sign key. The passkey
that recovery writes has to be the same kind of access as one saved
at signup, or the account grows a purpose-limited class that list,
revoke, and consent would have to special-case.

## What

- Capability `managed-custody`.
- An A1 recovery ceremony may enroll one `credentials` row of kind
  `passkey`. That row is an ordinary A3 passkey: `list_devices`,
  `revoke_device`, and C2 signing consent treat it like a passkey
  enrolled at signup.
- The ceremony does not mark the row purpose-limited and does not
  require a later upgrade assertion.
- The A1 proof and the recovery session do not read
  `managed_key_blob`, do not grant Elect or Transfer, including to
  an existing key, and do not mint Elect. After the ordinary
  passkey exists, that session stays inside those limits. C2
  signing consent is a fresh assertion of that passkey, the same
  as any other passkey.

## Impact

- Capabilities: ADDED `managed-custody`.
- ADRs: none.

## User journey & surfaces

No new UI because this change names what the recovery ceremony may
authorize. The mailbox ceremony is `add-email-magic-link`
(`identikey-core-zlf.7`). The lose-every-passkey drill is
`add-account-recovery-drill` (`identikey-core-zlf.10`).

## Out of scope

- Sending or verifying the email link (`identikey-core-zlf.7`).
- The recovery drill (`identikey-core-zlf.10`).
- A password credential and its hasher (`identikey-core-zlf.9`).
- Account-access revocation (`identikey-core-zlf.6`).
- SMS OTP, guardian recovery, and minting Elect from the mailbox.
