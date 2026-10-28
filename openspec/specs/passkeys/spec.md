# passkeys

Living truth for WebAuthn registration and assertion (access level
A3) on `identikey-server`, stored as `credentials` rows in
`identikey-keys`. Folded from `add-passkey-ceremonies` (2026-08-20),
`add-hosted-login-ui` (2026-08-27), `add-account-profile`
(2026-09-24), and `add-passkey-legibility` (2026-10-27).

RP ID and expected origins are fail-closed at boot (`62j`). Related
origins are already served (`2js`). Signal APIs and synced-passkey
counter policy are later slices (`5gh.3`–`5gh.4`).

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
custody rung, and one row per registered passkey as defined by
"Passkey rows name the authenticator". It SHALL NOT show private
keys, the managed key blob, or a pairwise `sub`. An OIDC signup
(`client_id` present) SHALL still return to `/authorize/passkey`.
`GET /account` without a session SHALL NOT create an account.

#### Scenario: Signup without an app shows the profile

- GIVEN a person completing `GET`/`POST /signup` with no `client_id`
- WHEN attestation verifies
- THEN the response sets an HttpOnly cookie and names `/account`
- AND `GET /account` with that cookie shows the new XID and that passkey's row

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

### Requirement: Passkey rows name the authenticator

Registration of a passkey SHALL store the authenticator AAGUID when
the ceremony provides one, the registration-time backup state (the
BS bit, not backup eligibility), and a nickname when the trimmed
client value is nonempty. A later assertion SHALL NOT refresh that
backup bit. `GET /account` SHALL list each non-revoked passkey. The
visible label SHALL be the trimmed nonempty nickname when one is
stored, including when the AAGUID is absent from the pinned list or
that list cannot be read. Otherwise the label SHALL be the provider
name from that list, otherwise the text "Passkey". A blank nickname
SHALL be treated as absent. When that list entry has an icon, the
row SHALL show it. The row SHALL show the registration backup
snapshot as backed up or not backed up, and SHALL show when the
passkey was last used. A missing or legacy backup value SHALL be
shown as unknown and SHALL NOT be shown as "Not backed up". A
missing list entry, or a metadata list that cannot be read, SHALL
still render the row and SHALL NOT fail the page. Assertion and
authorization SHALL NOT accept or reject a ceremony based on the
AAGUID. Registration MAY read the AAGUID only to store it.

#### Scenario: Known authenticator shows its name

- GIVEN a passkey whose AAGUID is in the pinned metadata list and no nickname
- WHEN the account holder opens `GET /account`
- THEN the row shows that list entry's name
- AND it shows the backup flag and last-used time

#### Scenario: Nickname wins

- GIVEN a passkey with a trimmed nonempty nickname and a known AAGUID
- WHEN the account holder opens `GET /account`
- THEN the row's label is the nickname

#### Scenario: Nickname survives a missing list

- GIVEN a passkey with a trimmed nonempty nickname and an AAGUID absent from the list, or a metadata list that cannot be read
- WHEN the account holder opens `GET /account`
- THEN the row's label is the nickname
- AND the rest of the profile is shown

#### Scenario: Blank nickname is absent

- GIVEN a passkey whose nickname is empty or only whitespace and whose AAGUID is known
- WHEN the account holder opens `GET /account`
- THEN the row's label is that list entry's name

#### Scenario: Unknown AAGUID still lists the passkey

- GIVEN a passkey with no nickname whose AAGUID is absent from the list
- WHEN the account holder opens `GET /account`
- THEN the row is labeled "Passkey"
- AND the rest of the profile is shown

#### Scenario: Backup line is the registration snapshot

- GIVEN a passkey stored with the BS bit set or clear
- WHEN the account holder opens `GET /account` after a later assertion
- THEN the row still shows that registration snapshot
- AND a missing backup value is not shown as "Not backed up"

#### Scenario: AAGUID does not decide login

- GIVEN two passkeys for the same account with different stored AAGUIDs
- WHEN either one completes assertion
- THEN the ceremony result does not depend on which AAGUID was stored
