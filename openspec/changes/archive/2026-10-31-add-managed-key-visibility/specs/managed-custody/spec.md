## ADDED Requirements

### Requirement: The account page shows the server-held Sign key

A signed-in `GET /account` SHALL show the Ed25519 operational public
key from the custody record, labeled as held by IdentiKey, apart
from the device list. The page SHALL NOT offer revoke, export, or
rotate for that key. The page SHALL NOT show `managed_key_blob` or
a private seed. A signed-out request SHALL NOT show the key. An
account whose operational key is Schnorr, from before `35aee29`,
SHALL be labeled as not usable for the responder.

#### Scenario: The server-held key is not a device row

- GIVEN a signed-in C2 account with an Ed25519 operational public key and a passkey
- WHEN the account holder opens `GET /account`
- THEN the page shows that public key labeled as held by IdentiKey
- AND the passkey remains in the device list
- AND the page has no revoke control for the operational key

#### Scenario: A Schnorr operational key is labeled unusable

- GIVEN a signed-in account whose operational key is Schnorr from before `35aee29`
- WHEN the account holder opens `GET /account`
- THEN the page says that key is not usable for the responder
- AND the page does not show the private blob

#### Scenario: Signed out shows nothing

- GIVEN no account session
- WHEN `GET /account` is requested
- THEN the operational public key is not shown
