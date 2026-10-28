## MODIFIED Requirements

### Requirement: Registration and assertion use webauthn-rs
<!-- base: e736cc5d3c131991b09749af8194f3e5b90a617b openspec/specs/passkeys/spec.md -->

The system SHALL perform WebAuthn registration and assertion with
`webauthn-rs`, using the fail-closed RP ID and origin allowlist
already parsed at boot. Discoverable (resident) keys SHALL be
**required** so a synced authenticator (1Password, iCloud Keychain,
Google Password Manager) can store the passkey. Creation and request options
SHALL NOT set `authenticatorAttachment`. The hint list SHALL be
absent or exactly `client-device`, `hybrid`, `security-key`, in that
order. A one-value or two-value list SHALL NOT be sent. The server
SHALL NOT implement caBLE itself and SHALL NOT render a QR. A
verified assertion SHALL bind to an existing
account XID and SHALL NOT create an account implicitly.

#### Scenario: Registration stores a passkey credential

- GIVEN a stored account and valid registration options
- WHEN attestation verifies
- THEN a `credentials` row of kind passkey exists for that XID

#### Scenario: Unknown user is not created on assertion

- GIVEN no account for the asserted credential
- WHEN assertion is submitted
- THEN the ceremony fails and no account is inserted

#### Scenario: Options nudge a phone without leading with it

- GIVEN a registration or assertion ceremony is begun
- WHEN the public-key options are returned
- THEN the hint list is `client-device`, `hybrid`, and `security-key`
- AND `authenticatorAttachment` is absent
- AND the response is not a QR image and not a new ceremony route
