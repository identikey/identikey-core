## ADDED Requirements

### Requirement: A password is a credential on the same account

When the hasher finding says go, an existing account SHALL be able
to attach a password as a credentials row that stores only a hash.
That row SHALL be listed and revoked with the other devices.
Password login SHALL use authorization-code plus PKCE and SHALL
resolve to the same XID as the account's passkey. The password
SHALL NOT be a resource-owner password grant. An A0 password proof
SHALL NOT consent to C2 signing. The hash is Argon2id with the parameters
recorded in `docs/spikes/password-hasher/finding.md`. This
requirement is not implemented until the node is activated.

#### Scenario: Password and passkey are the same account

- GIVEN an account that already has a passkey and a verified email
- WHEN a password is attached and then used to sign in
- THEN the OIDC subject is that account's XID
- AND the password row appears in `list_devices`

#### Scenario: Revoke hides the password

- GIVEN that password row
- WHEN `revoke_device` revokes it
- THEN it is absent from `list_devices`

#### Scenario: The password does not sign

- GIVEN a successful password login
- WHEN the caller asks that login to sign an identikey-auth Challenge
- THEN the server does not sign
