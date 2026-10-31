# passkeys

Living truth for WebAuthn registration and assertion (access level
A3) on `identikey-server`, stored as `credentials` rows in
`identikey-keys`. Folded from `add-passkey-ceremonies` (2026-08-20),
`add-hosted-login-ui` (2026-08-27), `add-account-profile`
(2026-09-24), `add-passkey-legibility` (2026-10-27),
`add-passkey-counter-policy` (2026-10-31), and
`add-passkey-signal-api` (2026-10-31).

RP ID and expected origins are fail-closed at boot (`62j`). Related
origins are already served (`2js`). Signal APIs are best-effort
hygiene after a ceremony the server has already accepted (`5gh.3`).

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

Login, signup, and device approval SHALL show a distinct visible status for each
of these outcomes: WebAuthn is unavailable or the origin is not a secure context;
the prompt ended with `NotAllowedError` or `AbortError`; the credential is not
stored; the ceremony is unknown or expired; the browser reports `NetworkError` or
the server responds with HTTP 5xx. The `NotAllowedError` and `AbortError` status
SHALL say the prompt was not completed. It SHALL NOT say the account is missing,
SHALL NOT say the person cancelled, and SHALL NOT say a provider is not installed.
The page SHALL NOT call `isUserVerifyingPlatformAuthenticatorAvailable` to claim
a provider is installed or absent. An AAGUID SHALL NOT decide whether a ceremony
is allowed. These diagnostics SHALL NOT insert, list, or revoke a credentials row.

A failure status SHALL include a control that copies a sanitized report. The
report SHALL include the ceremony stage, whether the origin is a secure context,
whether `PublicKeyCredential` and `navigator.credentials` are present, the error
name, and the server error code and HTTP status when the server returned one.
The stage SHALL be one of `support`, `prepare`, `prompt`, `finish`, or `deny`,
and it SHALL name an operation that ran. `prepare` SHALL cover a failed
`POST /signup`, registration begin, login options renewal, or device assert
begin that happens before the browser prompt. `deny` SHALL cover a failed
`POST /device/deny`. The page SHALL NOT label either of those `prompt` or
`finish`. The server error code in the report SHALL be a string or absent.
A failed clipboard write SHALL leave the failure status visible, SHALL say
the copy did not happen, and SHALL NOT say the report was copied.
The report SHALL NOT include cookies, authorization codes, PKCE verifiers,
challenges, WebAuthn credential ids, raw ceremony payloads, recovery tokens, or
email addresses. The page SHALL NOT send that report anywhere.

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

#### Scenario: An unfinished prompt is not a missing account

- GIVEN login or signup has opened the passkey prompt
- WHEN the prompt ends with `NotAllowedError` or `AbortError`
- THEN the status says the prompt was not completed
- AND the status does not say the account is missing, that the person cancelled, or that a provider is not installed
- AND no credentials row is inserted or revoked

#### Scenario: The copied report omits secrets

- GIVEN a failed ceremony whose request carried a credential id and a challenge
- WHEN the person copies the diagnostics
- THEN the copied text includes the error name and the ceremony stage
- AND the copied text does not include that credential id, the challenge, a cookie, or an email address
- AND the page does not send the report

#### Scenario: Preparation fails before the prompt

- GIVEN login, signup, or device approval is preparing a ceremony
- WHEN that request fails before the browser prompt opens
- THEN the copied stage is `prepare`
- AND the page did not call `navigator.credentials.create` or `navigator.credentials.get`

#### Scenario: Device denial is not a prompt

- GIVEN the device approval page
- WHEN `POST /device/deny` fails
- THEN the copied stage is `deny`
- AND the report does not say `prompt` or `finish`

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

### Requirement: A synced passkey counter may drop

A verified passkey assertion SHALL be accepted when its sign counter
is 0, including when the stored counter is already positive. That
acceptance SHALL NOT lower the stored counter and SHALL NOT be logged
as a regression or a drop. A verified assertion SHALL be accepted
when its sign counter is greater than 0 and lower than the stored
counter. That lower value SHALL be logged and SHALL NOT replace the
stored counter. A sign counter greater than 0 and equal to the stored
counter SHALL still fail. That failure is the clone signal. A higher
counter SHALL replace the stored counter. Every accepted assertion
SHALL set `last_used_at` to the current time and SHALL leave
`sign_counter` at the greater of the stored value and the presented
value.

This rule SHALL apply to hosted assertion, managed assertion, and the
encapsulation verifier. Before webauthn-rs checks the assertion, the
counter inside the `Passkey` it sees SHALL be 0, so the library's own
counter check does not reject the ceremony. `credentials.sign_counter`
and this rule SHALL be the only counter authority. The counter stored
in `passkey_json` SHALL NOT be raised after registration.

#### Scenario: A lower counter still signs in

- GIVEN a stored passkey whose counter is 10
- WHEN a verified assertion presents counter 4
- THEN the ceremony succeeds
- AND the stored counter remains 10
- AND the server logs the drop
- AND `last_used_at` advances

#### Scenario: Zero over a positive counter is not a reset

- GIVEN a stored passkey whose counter is 10
- WHEN a verified assertion presents counter 0
- THEN the ceremony succeeds
- AND the stored counter remains 10
- AND no regression and no drop is logged
- AND `last_used_at` advances

#### Scenario: Zero is not a regression

- GIVEN a stored passkey whose counter is 0
- WHEN a verified assertion presents counter 0
- THEN the ceremony succeeds
- AND no regression is logged

#### Scenario: A repeated positive counter fails

- GIVEN a stored passkey whose counter is 10
- WHEN a verified assertion presents counter 10
- THEN the ceremony fails
- AND the stored counter remains 10

#### Scenario: A registration counter above zero does not reject a later drop

- GIVEN a passkey whose `passkey_json` was registered at counter 5 and whose stored counter is 5
- WHEN a verified assertion presents counter 4
- THEN webauthn-rs does not reject the assertion for the counter
- AND the ceremony succeeds
- AND the stored counter remains 5
- AND the server logs the drop

### Requirement: Signal APIs are best-effort hygiene

After a successful passkey registration or assertion, the page SHALL
call `PublicKeyCredential.signalAllAcceptedCredentials` with the RP
ID, the WebAuthn user handle for that XID, and every live passkey
credential id stored for that XID. A live passkey is a `credentials`
row with `kind = 'passkey'` and `revoked_at` null. The user handle
SHALL be the unpadded base64url encoding of the 16 bytes of
`xid_user_id` for that XID, the same value as `user.id` in
registration options. Each credential id SHALL be the unpadded
base64url encoding of `webauthn_credential_id`, the same value as the
posted `credential.id`. The server SHALL include that handle and
those ids on the success response. The page SHALL make the call only
after the server has accepted the ceremony, and only when that list
is present and nonempty. If loading the list fails after the ceremony
was accepted, the server SHALL still return the existing success
(`redirect`, `next`, or device approval) without the signal fields,
and the page SHALL NOT call `signalAllAcceptedCredentials`. The page
SHALL NOT await that call without a bound. A synchronous throw, a
rejected promise, and a promise that never settles SHALL NOT change
the redirect, the signup navigation, or the device-approved state.

When assertion finish fails because no live row exists for that
credential id, the page SHALL call
`PublicKeyCredential.signalUnknownCredential` with the RP ID and that
credential id, and SHALL still present the existing failure. A
revoked passkey offered again is that case. The page SHALL NOT call
`signalUnknownCredential` when the credential id is stored for a
different XID, and that failure SHALL NOT use the same error as
"credential not found". The page SHALL NOT call
`signalUnknownCredential` when the RP ID is `localhost`. No other
failure SHALL call either function. The server SHALL NOT treat
either call as authorization. This slice SHALL NOT call
`signalCurrentUserDetails`.

#### Scenario: Login signals the stored ids and still redirects

- GIVEN two passkeys stored for one XID
- WHEN assertion of one of them succeeds
- THEN the page calls `signalAllAcceptedCredentials` with both ids and that XID's WebAuthn user handle
- AND the browser then follows the authorization redirect
- AND the redirect still happens when the function is missing or throws

#### Scenario: An unknown credential is reported and the failure remains

- GIVEN an assertion for a credential id this server does not store
- WHEN finish returns `credential not found`
- THEN the page calls `signalUnknownCredential` for that id
- AND the existing failure is shown

#### Scenario: A credential on another account is not reported unknown

- GIVEN a passkey stored for a different XID
- WHEN assertion finish is bound to this XID
- THEN the failure is not `credential not found`
- AND the page does not call `signalUnknownCredential`

#### Scenario: Localhost does not report an unknown credential

- GIVEN the RP ID is `localhost`
- WHEN assertion finish returns `credential not found`
- THEN the page does not call `signalUnknownCredential`
- AND the existing failure is shown

#### Scenario: A missing list still lets the person in

- GIVEN a ceremony the server has accepted
- WHEN the stored-id list cannot be loaded
- THEN the success response omits the signal fields
- AND the page does not call `signalAllAcceptedCredentials`
- AND login still follows `redirect`, signup still navigates, or device approval still shows "Approved"

#### Scenario: A signal that never settles still navigates

- GIVEN a successful login
- WHEN `signalAllAcceptedCredentials` returns a promise that does not settle
- THEN the page still follows the authorization redirect

#### Scenario: Other failures do not signal

- GIVEN a cancelled prompt or an expired ceremony
- WHEN the page handles that error
- THEN it calls neither Signal API
- AND the existing failure is shown
