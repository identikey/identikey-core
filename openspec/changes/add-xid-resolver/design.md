# Design — convenience XID resolver (ADR-007 §5)

Security-sensitive HTTP. The OP is a cache, not a root of trust.

## Path and body

- `GET /.well-known/xid/{xid}`
- `{xid}` is 64 lowercase hex characters (32-byte XID). Any other shape
  is 404, not 400 — do not confirm "that looked like an id."
- 200 body is the stored `xid_document` bytes (the CBOR the store
  already persists). Do not re-sign. Do not wrap in JSON.
- `Content-Type: application/cbor`
- No row → 404. Disabled account → 404 (same as missing).
- No other methods. No query-string alternate.

Climb tests currently put `https://auth.identikey.me/.well-known/xid`
(no XID) in `resolution_methods`. That URI cannot name an identity.
This change serves the per-XID path. Updating what we *write* into new
documents is `add-resolver-relocation` / climb follow-up, not a
rewrite of stored C2 rows.

## Freshness

- `Cache-Control: max-age=60, must-revalidate`
- `ETag` is the hex SHA-256 of the body (the document bytes).
- `Last-Modified` from `custody_records.updated_at`.
- `If-None-Match` / `If-Modified-Since` → 304 when unchanged.

Sixty seconds is the short TTL. `must-revalidate` plus ETag is the
revocation signal this change can actually emit: a rotation changes
the bytes, the ETag changes, a conforming cache must revalidate and
sees the new document. Push/webhooks wait for an RP subscriber
registry (`ccf`).

A write (`apply_document_update`, `migrate_c2_to_c3`, later relocation)
already bumps `updated_at`. Do not add a second generation column.

## What this is not

- Not a readiness or key-state leak on `/health`.
- Not a threshold client.
- Not proof the document is current — only that it is what we store.
  An RP that needs assurance uses `add-threshold-resolve`.
