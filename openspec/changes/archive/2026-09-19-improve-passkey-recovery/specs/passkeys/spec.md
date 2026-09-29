## ADDED Requirements

Folded into the living passkeys specification on 2026-09-19.

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
