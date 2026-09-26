## MODIFIED Requirements

### Requirement: Registration and assertion use webauthn-rs

The system SHALL perform WebAuthn registration and assertion with
`webauthn-rs`, using the fail-closed RP ID and origin allowlist
already parsed at boot. Discoverable (resident) keys SHALL be
**required** so a synced authenticator (1Password, iCloud Keychain,
Google Password Manager) can store the passkey. Creation options
SHALL NOT set `authenticatorAttachment` or a hint list that is only
`client-device`. Registration and assertion options SHALL include the
hints `hybrid`, `security-key`, and `client-device`, so the browser
may offer its standard phone QR (caBLE) without hiding a synced
passkey provider. The server SHALL NOT implement caBLE itself and
SHALL NOT render a QR. A verified assertion SHALL bind to an existing
account XID and SHALL NOT create an account implicitly.

#### Scenario: Registration stores a passkey credential

- GIVEN a stored account and valid registration options
- WHEN attestation verifies
- THEN a `credentials` row of kind passkey exists for that XID

#### Scenario: Unknown user is not created on assertion

- GIVEN no account for the asserted credential
- WHEN assertion is submitted
- THEN the ceremony fails and no account is inserted

#### Scenario: Options offer hybrid and do not prefer the platform only

- GIVEN a registration or assertion ceremony is begun
- WHEN the public-key options are returned
- THEN the hint list is `hybrid`, `security-key`, and `client-device`
- AND `authenticatorAttachment` is absent
- AND the response is not a QR image and not a new ceremony route
