## ADDED Requirements

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
