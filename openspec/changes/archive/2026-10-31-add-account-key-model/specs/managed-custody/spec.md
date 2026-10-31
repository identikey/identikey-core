## ADDED Requirements

### Requirement: Email is an account channel, not a device

`accounts.email` SHALL be the A1 recovery destination for that
account. It SHALL NOT be a `credentials` kind. `list_devices` SHALL
NOT return it. Writing the column SHALL NOT insert a credential.
The existing unique index on `lower(email)` SHALL remain the rule
for which accounts may store the same address.

#### Scenario: Setting the address adds no device

- GIVEN an account with no email
- WHEN a verified A1 ceremony stores an address on `accounts.email`
- THEN `list_devices` for that XID is unchanged
- AND no credentials row was inserted

### Requirement: The managed Sign key is not a device record

`managed_key_blob` SHALL NOT appear in `list_devices`. `revoke_device`
SHALL NOT clear or rotate it. An A0 password proof and an A1 email
or SMS proof SHALL NOT decrypt `managed_key_blob`, SHALL NOT sign an
identikey-auth Challenge with that key, and SHALL NOT mint an Elect
key.

#### Scenario: Revoking a passkey leaves the operational key

- GIVEN a C2 account with a passkey and a `managed_key_blob`
- WHEN `revoke_device` revokes that passkey
- THEN the passkey is absent from `list_devices`
- AND `managed_key_blob` is unchanged

#### Scenario: Mailbox proof does not sign with the operational key

- GIVEN a C2 account whose A1 email is verified
- WHEN the caller presents only that A1 proof
- THEN the server does not decrypt `managed_key_blob` and does not produce an identikey-auth signature or an Elect key

### Requirement: Provider keys and discarded Elect are not account devices

The OP signing key and the pairwise salt SHALL NOT be stored as
credentials rows. An Elect private key discarded at hosted signup
SHALL NOT be reconstructed from the account session cookie or from
`accounts.email`.

#### Scenario: A cookie does not restore Elect

- GIVEN a hosted C2 account whose Elect private key was discarded at signup
- WHEN the caller presents that account's session cookie
- THEN no Elect private key is returned
- AND no credentials row is created for the OP signing key or the pairwise salt

### Requirement: Surviving access is an account login

A non-revoked credential SHALL count as account access only when its
kind is `passkey`, `oidc_apple`, `oidc_google`, or `identikey_auth`,
or a password kind when that credentials row exists. `ssh_git` SHALL
NOT count. `accounts.email` and `managed_key_blob` SHALL NOT count.

`revoke_device` SHALL remain an unconditional soft-revoke of the
addressed credential on that XID. It SHALL NOT evaluate surviving
access and SHALL NOT require confirmation. The living scenario
"Revoke hides the device" stays the rule for that primitive,
including when the addressed row is the only passkey. This
requirement does not claim that today's store enforces surviving
access.

Account-access revocation SHALL be a separate kind-generic
operation. It is the only operation that enforces this rule, for
every counted kind. `add-passkey-account-management`
(`identikey-core-zlf.6`) owns that operation and its verification,
including the passkey confirmation surface and the same operation
for `oidc_apple`, `oidc_google`, `identikey_auth`, and a password
row when that kind exists. Later nodes SHALL call it rather than
add a second policy. The operation and its revocation SHALL be one
atomic decision for the XID, under the account lock, with the
custody row locked before the credential row. While another counted
credential remains, the operation SHALL revoke the addressed row.
When the addressed row is the last counted credential and an
explicit last-access confirmation is absent, the operation SHALL
leave that row active. An `ssh_git` row, the mailbox, and the
managed Sign key SHALL NOT supply that confirmation. This rule
becomes living behavior when `identikey-core-zlf.6` lands the
operation. Folding this model SHALL NOT be read as that landing.

#### Scenario: The primitive still revokes a sole passkey

- GIVEN one non-revoked passkey and no other credential
- WHEN `revoke_device` revokes that passkey
- THEN the passkey is absent from a subsequent list

#### Scenario: Another account login keeps account-access revocation ordinary

- GIVEN a non-revoked passkey and a non-revoked `oidc_apple` credential
- WHEN account-access revocation revokes the passkey without a last-access confirmation
- THEN the passkey is revoked
- AND the `oidc_apple` credential remains

#### Scenario: A password row counts when it exists

- GIVEN a non-revoked passkey and a non-revoked password credential
- WHEN account-access revocation revokes the passkey without a last-access confirmation
- THEN the passkey is revoked
- AND the password credential remains

#### Scenario: ssh_git does not keep the last passkey ordinary

- GIVEN a non-revoked passkey, a non-revoked `ssh_git` credential, and no other counted credential
- WHEN account-access revocation is asked to revoke the passkey without a last-access confirmation
- THEN the passkey remains listed
- AND `revoke_device` for that same passkey still revokes it

#### Scenario: The last account login requires confirmation

- GIVEN one non-revoked passkey and no other counted credential
- WHEN account-access revocation is asked to revoke it without a last-access confirmation
- THEN the passkey remains listed

#### Scenario: Two concurrent unconfirmed revokes cannot clear the account

- GIVEN two non-revoked counted credentials and no last-access confirmation
- WHEN two account-access revocations for those two credentials run concurrently
- THEN one credential remains listed
- AND the revocation that would have removed the last counted credential leaves that row active
- AND both decisions used one account-scoped lock with the custody row before the credential row
