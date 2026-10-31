## ADDED Requirements

### Requirement: The account page manages its passkeys

A signed-in `GET /account` SHALL let the account holder add a passkey
on that XID, set or change that passkey's nickname, and revoke a
passkey. A missing session SHALL NOT add, rename, or revoke. A
credential that is not on that XID SHALL NOT be revoked.

Revoke of a counted credential SHALL use account-access revocation.
`revoke_device` SHALL stay an unconditional soft-revoke and SHALL
NOT be what the page calls for a counted kind. While another counted
credential remains, the revoke SHALL complete and the remaining
passkey SHALL still be able to sign in. When the addressed row is
the last counted credential, the page SHALL ask for an explicit
last-access confirmation and SHALL NOT remove the row until that
confirmation. The confirmation SHALL NOT start recovery.

The decision and the revocation SHALL be one atomic account-scoped
operation, with the custody row locked before the credential row.
Two concurrent unconfirmed account-access revocations of the last
two counted credentials SHALL leave one of them listed.

#### Scenario: Add and rename on the same account

- GIVEN a signed-in account with one passkey
- WHEN the account holder adds a second passkey and sets its nickname
- THEN `list_devices` shows both passkeys on that XID
- AND the second row's label is the nickname

#### Scenario: Ordinary revoke leaves a way in

- GIVEN a signed-in account with two non-revoked passkeys
- WHEN the account holder revokes one without a last-access confirmation
- THEN that passkey is absent from the list
- AND the remaining passkey can complete assertion

#### Scenario: The last counted credential waits for confirmation

- GIVEN a signed-in account whose only counted credential is one passkey
- WHEN the account holder asks to revoke it and does not confirm
- THEN the passkey remains listed
- AND no recovery ceremony starts

#### Scenario: Concurrent revokes cannot clear both last credentials

- GIVEN two non-revoked counted credentials and no last-access confirmation
- WHEN two account-access revocations for those credentials run concurrently
- THEN one credential remains listed

#### Scenario: A signed-out browser cannot manage passkeys

- GIVEN no account session
- WHEN a caller posts an add, rename, or revoke
- THEN no credential is inserted, renamed, or revoked
