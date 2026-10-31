# add-passkey-account-management

> **ACTIVE BUILD**

Node `identikey-core-zlf.6`. Depends on the folded account key model.
The living requirement "Surviving access is an account login" names
this node as the owner of kind-generic account-access revocation.
Activation needs a human. The first-wave grant does not cover it.

## Why

A person with one passkey cannot add another, name it, or remove it
from the account page. Removing the last account login has to ask,
and two overlapping removals must not wipe the account by accident.

## What

- Capability `passkeys`.
- A signed-in account page can add a passkey on the same XID, set or
  change its nickname, and revoke a passkey.
- Revoke of a counted credential goes through account-access
  revocation, not a direct `revoke_device` from the page. The
  primitive stays unconditional.
- While another counted credential remains, revoke is ordinary.
  The last counted credential stays until the page gets an explicit
  last-access confirmation. That confirmation does not start
  recovery.
- The decision and the revoke are one account-scoped lock, custody
  row before credential row. Two concurrent unconfirmed revokes of
  the last two counted credentials leave one listed.
- After an ordinary revoke, a remaining passkey can still sign in.

## Impact

- Capabilities: ADDED `passkeys`.
- ADRs: none.

## User journey & surfaces

Who: a person already signed in at `GET /account`.

Working: add a second passkey, rename it, revoke one, sign in with
the one that remains.

Empty: an account with no passkey still cannot revoke. Add is the
enrollment ceremony on that XID.

Last access: revoking the last counted credential asks for
confirmation and does not remove the row until that confirmation.
It does not start email recovery.

Failed: a missing session does not add or revoke. A foreign
credential id does not revoke. A lost race that would remove the
last counted credential leaves that row active.

Off: the page does not offer this until the change is activated and
built.

## Out of scope

- Email recovery (`identikey-core-zlf.7`) and the recovery matrix
  (`identikey-core-zlf.2`).
- The recovery drill (`identikey-core-zlf.10`).
- Password rows (`identikey-core-zlf.9`). The operation must accept
  a password row when that kind exists; this change does not add
  the kind.
- Session invalidation beyond what the account key model recorded.
  The model recorded no extra session rule.
- Signal-after-revoke hygiene beyond the living signal requirement.
