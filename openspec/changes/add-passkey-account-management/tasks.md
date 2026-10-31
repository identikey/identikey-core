# Tasks

- [x] Add a second passkey on the signed-in XID from `GET /account`.
- [x] Let the signed-in account set or change a passkey nickname.
- [x] Revoke a passkey through kind-generic account-access revocation: ordinary while another counted credential remains, explicit confirmation before the last counted credential, one account-scoped lock with the custody row first.
- [x] Two concurrent unconfirmed revokes of the last two counted credentials leave one listed.
- [x] Sign in with a passkey that remains after an ordinary revoke.

`revoke_device` stays unconditional. Implemented under the ACTIVE BUILD grant.
