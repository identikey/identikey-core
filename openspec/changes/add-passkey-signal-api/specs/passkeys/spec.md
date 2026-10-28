## ADDED Requirements

### Requirement: Signal APIs are best-effort hygiene

After a successful passkey registration or assertion, the page SHALL
call `PublicKeyCredential.signalAllAcceptedCredentials` with the RP
ID, the WebAuthn user handle for that XID, and every credential id
stored for that XID. The server SHALL include that handle and those
ids on the success response. The page SHALL make the call only after
the server has accepted the ceremony. A missing function or a thrown
exception SHALL NOT change the redirect, the signup navigation, or
the device-approved state.

When assertion finish fails because the credential is not stored, the
page SHALL call `PublicKeyCredential.signalUnknownCredential` with
the RP ID and that credential id, and SHALL still present the
existing failure. No other failure SHALL call either function. The
server SHALL NOT treat either call as authorization. This slice SHALL
NOT call `signalCurrentUserDetails`.

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

#### Scenario: Other failures do not signal

- GIVEN a cancelled prompt or an expired ceremony
- WHEN the page handles that error
- THEN it calls neither Signal API
- AND the existing failure is shown
