# passkeys

Living truth for WebAuthn registration and assertion (access level
A3) on `identikey-server`, stored as `credentials` rows in
`identikey-keys`. Folded from `add-passkey-ceremonies` (2026-08-20),
`add-hosted-login-ui` (2026-08-27), and `add-account-profile`
(2026-09-24).

RP ID and expected origins are fail-closed at boot (`62j`). Related
origins are already served (`2js`). Nicknames, Signal APIs, and
synced-passkey counter policy are later slices (`5gh.2`–`5gh.4`).

### Requirement: Registration and assertion use webauthn-rs

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

### Requirement: First-party signup lands on the account profile

When signup is not an OIDC client journey, a verified registration
SHALL issue an HttpOnly account session and SHALL send the user to
`GET /account`. That page SHALL show the account XID, the current
custody rung, and that a passkey is registered. It SHALL NOT show
private keys, the managed key blob, or a pairwise `sub`. An OIDC
signup (`client_id` present) SHALL still return to `/authorize/passkey`.
`GET /account` without a session SHALL NOT create an account.

#### Scenario: Signup without an app shows the profile

- GIVEN a person completing `GET`/`POST /signup` with no `client_id`
- WHEN attestation verifies
- THEN the response sets an HttpOnly cookie and names `/account`
- AND `GET /account` with that cookie shows the new XID and a passkey

#### Scenario: App signup still finishes OIDC

- GIVEN signup started from `/authorize/passkey` with `client_id`
- WHEN attestation verifies
- THEN the page returns to `/authorize/passkey` with the original query

#### Scenario: Profile is not public

- GIVEN no account session cookie
- WHEN `GET /account`
- THEN the response is not the profile and no account is inserted

### Requirement: Recoverable hosted authentication

Hosted sign-in and signup SHALL present actionable user-facing feedback separately
from collapsed technical diagnostics. API error codes/descriptions SHALL remain
available to programmers without rendering response text as HTML. Cancellation
SHALL NOT imply that an account is missing. Unknown credentials SHALL offer
another passkey, password-manager/device guidance, and explicit signup without
implicitly creating an account. A local-development notice SHALL distinguish
local accounts from the live service. Feedback SHALL be keyboard accessible and
announced to assistive technology.

#### Scenario: An unrecognized passkey

- GIVEN a credential not registered with this server
- WHEN assertion fails
- THEN the page explains that the passkey is not registered here, offers retry
  and signup, and keeps the original error under Technical details

#### Scenario: A consumed or expired attempt

- GIVEN a failed or cancelled assertion attempt
- WHEN the user retries
- THEN a fresh validated challenge is requested with the same OIDC context
- AND no automatic reload loop or implicit account creation occurs

#### Scenario: Signup prompt cancellation

- GIVEN signup has returned a pending account and ceremony
- WHEN the user cancels the prompt and retries on the same page
- THEN a fresh registration ceremony reuses that pending account
- AND the page does not POST another signup for that retry

#### Scenario: Signup from an application

- GIVEN an OIDC sign-in journey
- WHEN the user visits signup and then returns or finishes registration
- THEN state, nonce, PKCE and redirect parameters are preserved
- AND successful registration explains the final sign-in step

#### Scenario: Service or browser failure

- GIVEN cancellation, missing browser support, or a network/server error
- WHEN the attempt fails
- THEN the user receives relevant recovery guidance and optional technical details
- AND unsupported browsers receive an explanation beside a disabled control
