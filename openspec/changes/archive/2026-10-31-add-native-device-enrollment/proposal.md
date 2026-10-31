# add-native-device-enrollment

> **ACTIVE BUILD**

**Rigor:** architecture

Node `identikey-core-zlf.11`. Activated 2026-10-31. The human chose
Papyrus as the native enrollment journey. A standalone Linux enclave
enrollment is not this journey.

## Why

A native device needs a place on the account that is a credential
row. The hosted passkey path already works. The first native journey
has to name one client, and the clients that were not chosen.

## What

- Capability `managed-custody`.
- The chosen journey is Papyrus. `device_enroll` loads or creates
  the device signer and returns its classical public key and
  fingerprint. That local call does not write an account row.
- Account enrollment records that public key as a credentials row of
  kind `identikey_auth` on the signed-in XID.
- Consent is a signature by that device key. The account cookie and
  the mailbox do not substitute for it. That binding is the later
  node's work. Folding this decision does not deliver it, and the
  row is not surviving access until that login exists.
- `revoke_device` stays an unconditional soft-revoke. Account-facing
  removal of the Papyrus row uses `revoke_account_access`.
- Enrollment does not mint Elect. Hosted signup still discards Elect.
- The hosted passkey path does not wait on Papyrus.
- Papyrus may use a Secure Enclave, a TPM, or a software key. A
  Cargo `enclave` feature does not prove which one produced the key.
- Not chosen: a Linux-enclave-only enrollment that is not Papyrus.

## Impact

- Capabilities: ADDED `managed-custody`.
- No architecture decision record is amended.

## User journey & surfaces

No new UI because this change names Papyrus's existing device
commands. It does not add an account-page control.

Who: a person signed in to the hosted account, using Papyrus.

Working: Papyrus enrolls a device key, the account stores it as
`identikey_auth`, a signature from that key is the device proof,
and revoke removes the row.

Failed: the account cookie alone does not enroll the row and does
not count as device consent. Hosted passkey login still works with
no Papyrus device.

Off: a Linux TPM enrollment that does not go through Papyrus is not
specified here.

## Out of scope

- Implementing the account-binding route in this change. The
  contract names it. A later node builds it.
- Creating protocol beads.
- Choosing a second native client.
- Claiming the `enclave` feature is hardware assurance.
