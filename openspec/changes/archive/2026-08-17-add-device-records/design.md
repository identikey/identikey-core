# Design — devices are credentials

Schema + auth. The TS design's two mistakes are in the bead; do not
reintroduce them.

## No `devices` table

`credentials` already has `xid`, `kind`, `nickname`, `created_at`,
`last_used_at`, `revoked_at`, passkey fields, and `device_public_key`
for A4. One device key is one credential. A second table would
recreate `is_master`.

## API

- `list_devices(xid)` — rows with `revoked_at IS NULL`, no secret
  material (no `cose_public_key` / `device_public_key` in the list
  DTO if we can avoid it; ids + kind + nickname + last_used are
  enough).
- `revoke_device(xid, credential_id)` — set `revoked_at = now()`.
  Idempotent if already revoked.
- Existing `insert_passkey` stays the registration write. Optional
  nickname argument if it is free; do not block on a rename API.

## What we will not ship

- `device_trust` on any struct this crate serializes.
- `is_master` / `master|temporary`.
- AAGUID as a branch. Still a UX hint.
- Refresh-token sweep (no token table here).

Privilege split lives on the XID document, not on the credential row.
Revoking a credential does not change Elect/Sign on the document —
that is a document update.
