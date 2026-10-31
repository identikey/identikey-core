## ADDED Requirements

### Requirement: Papyrus is the native enrollment journey

This node selects the journey and records Papyrus's current local
behavior. It does not deliver OP account binding or native account
login. Folding this decision SHALL NOT be read as those behaviors
having landed.

The native enrollment journey SHALL be Papyrus. `device_enroll`
SHALL load or create the device signer and SHALL return that
signer's classical public key and fingerprint. That call SHALL NOT
insert a credentials row. Papyrus MAY use a Secure Enclave, a TPM,
or a software signer inside this journey, including falling through
to software when a hardware signer fails. A Cargo `enclave` feature
SHALL NOT be treated as proof of which signer produced the key. A
Linux enclave enrollment that is not Papyrus SHALL NOT be this
journey. This change SHALL NOT create a protocol bead.

`revoke_device` SHALL remain an unconditional soft-revoke. A later
account-facing removal of a Papyrus `identikey_auth` row SHALL use
`revoke_account_access` and its existing last-access confirmation.
Until a later node can log an account in with that device key, an
`identikey_auth` row for this journey SHALL NOT be relied on as
surviving access.

The later account-binding node SHALL record the device public key
as one `identikey_auth` row on the signed-in XID, and only with a
signature by that key. The account cookie alone SHALL NOT insert
the row. The account cookie and the mailbox SHALL NOT substitute
for device consent. Enrollment SHALL NOT mint an Elect key. Hosted
signup SHALL still discard Elect. The hosted passkey path SHALL
NOT require a Papyrus device.

#### Scenario: Local enroll does not write the account

- GIVEN Papyrus calls `device_enroll` and the account has no `identikey_auth` row
- WHEN `device_enroll` returns the device public key
- THEN no credentials row has been inserted

#### Scenario: The primitive still revokes a sole native row

- GIVEN one `identikey_auth` row and no other credential
- WHEN `revoke_device` revokes that row
- THEN it is absent from a subsequent list

#### Scenario: Account-facing revoke of the last native login waits

- GIVEN one `identikey_auth` row and no other counted credential
- WHEN account-access revocation is asked to revoke it without a last-access confirmation
- THEN the row remains listed

#### Scenario: The cookie is not device consent

- GIVEN a later account-binding attempt for a Papyrus device public key
- WHEN the caller presents the account cookie and no signature by that device key
- THEN no `identikey_auth` row is inserted

#### Scenario: The hosted path does not wait

- GIVEN an account with no Papyrus credential
- WHEN the account holder signs in with a passkey
- THEN the passkey ceremony does not require Papyrus

#### Scenario: A Linux enclave outside Papyrus is not this journey

- GIVEN a Linux TPM key that was not enrolled through Papyrus
- WHEN the account lists devices
- THEN that key is not an `identikey_auth` row of this journey

#### Scenario: Folding does not deliver native login

- GIVEN this decision has been folded and no later account-binding node has landed
- WHEN a caller looks for a Papyrus device login on the account
- THEN no such login is available
- AND the absence is not treated as a lost surviving login
