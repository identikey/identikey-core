# add-passkey-legibility

> **ACTIVE BUILD**

Bead `identikey-core-5gh.2`. Steer 2026-09-26. Activated in chat
2026-09-26.

**Preparation:** still valid. `credentials.aaguid`, `backed_up`,
`nickname`, and `last_used_at` already exist.
`KeysStore::insert_passkey` does not write the first three.
`GET /account` shows a passkey count, not a list. The column comment
already says an AAGUID is a UX hint and never a policy input.
Authority: Duke said "activate" for this bead and for `5gh.5` only.
Signal API, counter policy, and the domain monitor stay outside.

## Why

The account page cannot answer which passkey this is. The columns
are already there. Registration drops the authenticator's AAGUID and
backup flag on the floor.

## What

- Store AAGUID, backed-up, and an optional nickname when a passkey
  is registered.
- On `GET /account`, list each passkey. The label is the nickname,
  otherwise the provider name from a pinned public AAGUID metadata
  list, otherwise "Passkey". Show the list's icon when the entry has
  one. Show backed-up and last used.
- A missing entry or an unreadable list still renders the row as
  "Passkey". Login and registration do not read the AAGUID.
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
