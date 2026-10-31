## ADDED Requirements

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
