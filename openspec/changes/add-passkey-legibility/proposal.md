# add-passkey-legibility

> **ACTIVE BUILD**

Bead `identikey-core-5gh.2`. Steer 2026-09-26. Activated in chat
2026-09-26.

**Preparation:** revised 2026-10-27 after
`reviews/2026-10-27-advise.md` send-back. Registration already
writes presentation metadata through `insert_passkey_with_metadata`.
`GET /account` already lists rows. This revision fixes the contract:
a trimmed nonempty nickname wins even when metadata is missing; the
backup flag is the registration-time BS bit and an absent value is
not "Not backed up"; the two-AAGUID ceremony test is not claimed
done. Fresh advise is owed. Authority: Duke said "activate" for this
bead and for `5gh.5` only. Signal API, counter policy, and the domain
monitor stay outside.

## Why

The account page cannot answer which passkey this is. The columns
are already there. Registration drops the authenticator's AAGUID and
backup flag on the floor.

## What

- Store the AAGUID when authenticator data has one, the
  registration-time backup state (the BS bit, not backup
  eligibility), and a nickname when the trimmed value is nonempty.
  Assertion does not refresh the backup bit.
- On `GET /account`, list each passkey. A trimmed nonempty nickname
  is the label even when the metadata list has no entry or cannot
  be read. Otherwise the label is the provider name from the pinned
  list, otherwise "Passkey". A blank nickname is absent. Show the
  list's icon when the entry has one.
- The backup line is that registration snapshot: backed up, or not.
  A missing or legacy backup value is unknown. It is not shown as
  "Not backed up". Show last used.
- The pinned list is the compact public AAGUID file (1Password,
  Google Password Manager, Apple Passwords), source URL recorded,
  pinned 2026-09-27. `GET /account` does not fetch it.
- A missing entry or an unreadable list still renders the row and
  the rest of the page. Assertion and authorization do not accept
  or reject a ceremony from the AAGUID. Registration may read it
  only to store it.
- The claim that a ceremony test already accepts two AAGUIDs is
  withdrawn. That assertion test is still owed.
- Capability: MODIFIED `passkeys`.

## Impact

- Capabilities: MODIFIED `passkeys`
- ADRs: none

## User journey & surfaces

A signed-in person opens `GET /account`. Under the XID and custody
rung they see one row per passkey: a name, an icon when the list has
one, whether it is backed up, and when it was last used. With no
passkeys the page still shows the account and says there is no
passkey. If the metadata list cannot be read, the names fall back to
"Passkey" and the rest of the page still loads. Signed out, the page
stays the signed-out account page and creates nothing.

## Out of scope

- Signal APIs — `identikey-core-5gh.3`
- Counter regression — `identikey-core-5gh.4`
- Hybrid / caBLE — `add-hybrid-transport` (`identikey-core-5gh.5`)
- Using an AAGUID to accept or reject a ceremony
