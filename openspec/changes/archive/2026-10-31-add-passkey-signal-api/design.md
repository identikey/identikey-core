# add-passkey-signal-api

## Calls

The Signal APIs are `PublicKeyCredential` methods on the page. The
server never calls them and never treats them as authorization.

`signalAllAcceptedCredentials` runs only after the server has accepted
registration or assertion. The payload is the ceremony's RP ID, the
WebAuthn user handle from `xid_user_id` (UUID v5 over the XID bytes),
and every `webauthn_credential_id` stored for that XID, including the
one just created or used. One id would tell the provider the others
are gone.

`signalUnknownCredential` runs only when assert finish returns
`credential not found` and the RP ID is not `localhost`. That error
means no live `kind = passkey` row exists for the id, including a
revoked row. A row stored for another XID uses a different failure
and does not signal. The id is the one the page just posted, as
unpadded base64url, the same string as `credential.id`. The user
handle is unpadded base64url of the 16 bytes of `xid_user_id`, the
same string as `user.id` in `register/begin`. The RP ID is the one
already in the ceremony options. Expired sessions and user cancels
are not unknown credentials. `localhost` is shared by the dev OP and
`identikey-local`, which do not share a store, so an unknown signal
there would delete a passkey that is valid on the other OP.

`signalCurrentUserDetails` has no event. `user.name` is the base58btc
XID.

## Failure isolation

The page calls the function after it has the success or
`credential not found` result, and before it navigates or replaces
the device heading. It does not call `signalAllAcceptedCredentials`
when the list is missing or empty. A missing function, a synchronous
throw, a rejected promise, and a promise that never settles are all
caught. The call is not awaited without a bound. Login still assigns
`redirect`. Signup still assigns its next URL. Device approval still
shows "Approved". The unknown-credential page still shows the
existing failure copy.

## Where the list is loaded

Register finish and both assert finishes already know the XID once
the credential is stored or matched. They load that XID's passkey
ids after the row write. The JSON adds the user handle and the ids
next to the fields the pages already read. Begin responses stay
unchanged.
