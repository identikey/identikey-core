## MODIFIED Requirements

### Requirement: Recoverable hosted authentication
<!-- base: 7d5ac1862c06eb0c51dd942721403d24ebaafbd6 openspec/specs/passkeys/spec.md -->

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
