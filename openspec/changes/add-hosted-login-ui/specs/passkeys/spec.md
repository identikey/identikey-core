## ADDED Requirements

### Requirement: Authorization passkey page is a product surface

`GET /authorize/passkey` SHALL return HTML that performs a
usernameless WebAuthn assertion on this origin. It SHALL NOT
present the ceremony options as a raw JSON dump as the only UI.

#### Scenario: Passkey page asks the authenticator

- GIVEN a valid pending authorization
- WHEN the user is sent to `/authorize/passkey`
- THEN the response is `text/html`
- AND the page invokes `navigator.credentials.get`
- AND it does not require a username field

### Requirement: Signup creates a C2 account then a passkey

The host SHALL provide a signup surface that creates a C2 managed
identity and then performs WebAuthn registration. A verified
assertion SHALL still not insert an account.

#### Scenario: Signup stores a passkey

- GIVEN no account
- WHEN signup completes and attestation verifies
- THEN an account row and a passkey credential exist for that XID

#### Scenario: Unknown assertion still creates nothing

- GIVEN no account for the asserted credential
- WHEN assertion is submitted
- THEN the ceremony fails and no account is inserted
