# Design — passkey legibility

**Change:** `add-passkey-legibility`
**Bead:** `identikey-core-5gh.2`

## Store

Registration already receives the authenticator data. Persist
`aaguid` (16 bytes or absent), `backed_up`, and `nickname` when the
client sent one. `insert_passkey` is the write. Assertion keeps
updating `last_used_at` the way it already updates the counter.
Nothing in the assertion or authorization path selects on `aaguid`.

## Names and icons

Use the public passkey-developer AAGUID metadata (names and icon
URLs), pinned in the repo. `GET /account` does not call the network.
No entry, or a pin that will not parse, shows "Passkey" and no icon.
The label is the stored nickname, else the list's name, else
"Passkey".

## Page

`GET /account` keeps the XID, the rung, and the refusal to show key
material. The passkey count becomes a list of those rows.
