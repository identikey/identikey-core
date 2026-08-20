# passkeys

Living truth for WebAuthn registration and assertion (access level
A3) on `identikey-server`, stored as `credentials` rows in
`identikey-keys`. Folded from `add-passkey-ceremonies` (2026-08-20).

RP ID and expected origins are fail-closed at boot (`62j`). Related
origins are already served (`2js`). Nicknames, Signal APIs, and
synced-passkey counter policy are later slices (`5gh.2`–`5gh.4`).

### Requirement: Registration and assertion use webauthn-rs

The system SHALL perform WebAuthn registration and assertion with
`webauthn-rs`, using the fail-closed RP ID and origin allowlist
already parsed at boot. Discoverable (resident) keys SHALL be
requested. A verified assertion SHALL bind to an existing account
XID and SHALL NOT create an account implicitly.

#### Scenario: Registration stores a passkey credential

- GIVEN a stored account and valid registration options
- WHEN attestation verifies
- THEN a `credentials` row of kind passkey exists for that XID

#### Scenario: Unknown user is not created on assertion

- GIVEN no account for the asserted credential
- WHEN assertion is submitted
- THEN the ceremony fails and no account is inserted
