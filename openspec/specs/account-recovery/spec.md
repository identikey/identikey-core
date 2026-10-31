# account-recovery

Living truth for the hosted email magic link that stores a recovery
address, and for returning to that account after every passkey is
gone. Folded from `add-email-magic-link` (2026-10-31) and
`add-account-recovery-drill` (2026-10-31).

### Requirement: A magic link verifies the recovery address

A single-use magic link SHALL verify an email address for one XID
and SHALL store that address on `accounts.email` for that XID.
Writing the column SHALL NOT insert a credentials row. A second
redeem of the same link SHALL NOT change the account. An address
already stored for another account under `lower(email)` SHALL be
refused. Redeeming the link SHALL NOT read `managed_key_blob`,
SHALL NOT sign an identikey-auth Challenge, and SHALL NOT mint an
Elect key.

#### Scenario: Redeem once onto the same account

- GIVEN a magic link bound to one XID and an email address
- WHEN the link is redeemed
- THEN `accounts.email` for that XID is that address
- AND no credentials row is inserted

#### Scenario: A second redeem does nothing

- GIVEN a magic link that has already been redeemed
- WHEN it is redeemed again
- THEN the account is unchanged

#### Scenario: Another account cannot take the address

- GIVEN an address already stored on one account
- WHEN a second account redeems a link for that same address
- THEN the second account's email is unchanged
- AND the first account keeps the address

#### Scenario: The link does not touch key material

- GIVEN a C2 account with a `managed_key_blob`
- WHEN a magic link for that account is redeemed
- THEN `managed_key_blob` is unchanged
- AND the server does not produce an identikey-auth signature or an Elect key

### Requirement: Losing every passkey returns through the email channel

A person who removes every passkey, including the last counted
credential by explicit confirmation, SHALL be able to redeem that
account's email magic link and enroll one replacement passkey on
the same XID. The replacement SHALL be an ordinary `kind=passkey`
row. The recovery session SHALL NOT sign an identikey-auth
Challenge. A fresh assertion of the replacement passkey SHALL be
accepted on ordinary C2 consent terms. The journey SHALL NOT add a
second token store or a devices table.

#### Scenario: Return to the same account

- GIVEN an account with a verified email and one passkey
- WHEN that passkey is removed with last-access confirmation, the email link is redeemed, and a replacement passkey is enrolled
- THEN the replacement passkey is on the same XID
- AND it is kind `passkey`

#### Scenario: The recovery session does not sign

- GIVEN a replacement passkey just enrolled from the recovery session
- WHEN the caller presents the recovery session and asks for an identikey-auth signature
- THEN the server does not sign

#### Scenario: The replacement passkey can sign

- GIVEN that replacement passkey
- WHEN the caller presents a fresh assertion of it for C2 consent
- THEN consent succeeds on the same terms as a signup passkey
