# Tasks

- [ ] Register finish, assert finish, and device assert finish return the WebAuthn user handle and every stored credential id for that XID
- [ ] The login, signup, and device pages call `signalAllAcceptedCredentials` only after success, then continue the existing navigation when the call is missing or throws
- [ ] `credential not found` calls `signalUnknownCredential` and still shows the existing failure
- [ ] Cancel and expired-ceremony failures call neither function
- [ ] Tests cover the success list, a swallowed throw, the unknown-credential call, and a non-matching error

Out of scope: `signalCurrentUserDetails`, signaling after passkey removal, and the synced counter policy (`identikey-core-5gh.4`).
