# Tasks

- [x] Register finish, assert finish, and device assert finish return the WebAuthn user handle and every stored credential id for that XID
- [x] The login, signup, and device pages call `signalAllAcceptedCredentials` only after success, then continue the existing navigation when the call is missing or throws
- [x] `credential not found` calls `signalUnknownCredential` and still shows the existing failure
- [x] Cancel and expired-ceremony failures call neither function
- [x] Tests cover the success list, a swallowed throw, the unknown-credential call, and a non-matching error

## Owed from advise 2026-10-30 (`reviews/2026-10-30-advise.md`)

The contract takes the recommended localhost rule: no `signalUnknownCredential` when the RP ID is `localhost`. A foreign XID is a different error from `credential not found`.

- [x] Wire encodings, the live-row definition, the nonempty list, the bounded signal call, the foreign-XID split, and the localhost exception are in the delta and design
- [x] Tests compare the user handle to `user.id` from `register/begin` and each credential id to the posted `credential.id`
- [x] A test offers a revoked passkey and sees `signalUnknownCredential`
- [x] A test where `signalAllAcceptedCredentials` never settles still redirects or shows "Approved"
- [x] A test where the credential id belongs to another XID does not signal
- [x] A test where the RP ID is `localhost` and the credential is unknown does not call `signalUnknownCredential`
- [x] A test where the stored-id list fails to load after an accepted ceremony omits the signal fields, makes no `signalAllAcceptedCredentials` call, and still redirects, navigates, or shows "Approved" (advise-2, `reviews/2026-10-30-advise-2.md`)

Out of scope: `signalCurrentUserDetails`, signaling after `revoke_device` (`identikey-core-5gh.6`), and the synced counter policy (`identikey-core-5gh.4`).
