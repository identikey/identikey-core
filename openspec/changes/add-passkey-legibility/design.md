# Design — passkey legibility

**Change:** `add-passkey-legibility`
**Bead:** `identikey-core-5gh.2`

## Store

Registration already receives the authenticator data. After the
response verifies, persist `aaguid` (16 bytes or absent), the BS
backup bit from that authenticator data, and a nickname when the
trimmed client value is nonempty. The write is
`insert_passkey_with_metadata`. `insert_passkey` remains the
empty-metadata wrapper. Assertion updates `last_used_at` and the
sign counter. It does not rewrite `backed_up`. Nothing in the
assertion or authorization path accepts or rejects from `aaguid`.
Registration reads the AAGUID only to store it.

`backed_up` is the registration snapshot of BS, not backup
eligibility. A later assertion does not maintain it. NULL, from a
row written before this column was filled, is unknown. The page
must not present unknown as "Not backed up".

## Names and icons

The pin is the public passkey-developer AAGUID list, vendored in
the repo on 2026-09-27 from the source URL in
`passkey_metadata.rs`. The file holds three providers: 1Password,
Google Password Manager, and Apple Passwords. Refreshing it keeps
that source. `GET /account` does not call the network.

The label is the trimmed nonempty nickname, else the list's name,
else "Passkey". The nickname wins when the AAGUID is unknown and
when the pin cannot be read. A blank or whitespace nickname is
absent. No entry, or a pin that will not parse, shows "Passkey"
and no icon only when no nickname is stored.

## Page

`GET /account` keeps the XID, the rung, and the refusal to show key
material. The passkey count becomes a list of those rows.
