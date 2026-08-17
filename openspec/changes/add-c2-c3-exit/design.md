# Design — C2→C3 ceremony (ADR-011)

Independent read (critic, 2026-08-16): REVISE. Findings absorbed below.
Implemented in `nod-c2-c3-exit`.

## Two write paths, one job each

- `apply_document_update` — C2 stays C2. Refuse a new document that is not
  `is_c2` when the stored rung is `c2`. That closes the hole where a user
  Elect can already persist a C3-shaped document and leave the blob.
- `migrate_c2_to_c3` — the only climb. Calls the private
  `apply_document_update_tx` hook (or equivalent) **inside** one transaction.
  One `UPDATE` sets `xid_document`, `managed_key_blob = NULL`, and
  `rung = 'c3'` together (CHECK is per-statement). Then event + consent.

Do not wrap the *public* `apply_document_update`: it commits its own
transaction.

## What "done" means on the row

1. Stored `rung = c2` and `is_c2(stored)`.
2. New document XID equals the row XID.
3. A signature over the new document bytes verifies against a key that
   holds Elect on the *stored* document. Public-key match is not enough.
4. Signer is not a key we hold (see below).
5. None of the publics we hold retain Sign / Elect / All / Transfer /
   Verify / Update / Delegate / Burn / Revoke on the new document.
6. Some key we do not hold can Sign; some key we do not hold can Elect
   (same or different keys). Some user key has Update.
7. `resolution_methods`: N≥2 distinct hosts; at least one eTLD+1 outside
   `{identikey.me, identikey.io}`; hostless URIs do not count as "not us";
   no CNAME-follow; refuse localhost / RFC1918.
8. If C2 had no provenance mark, C3 has one. Client created it and holds
   the generator. Submitted document carries no generator material.
9. Single UPDATE: blob NULL, `rung = c3`, new document.
10. Consent first (`action = c2_to_c3`, `result = signed` = authorized
    instruction completed, proof A3/A4 only), then `custody_events`
    (`c2` → `c3`, ceremony `c2_to_c3`, `consent_id` set).

Any check failing rolls back. A C3 document with a surviving blob is a
defect, not a retry state.

## "Key we hold"

There is no operational-public column; the blob is opaque. For the climb,
**every Sign+Auth key on the stored C2 document** is a key we hold.
Refuse if any of those publics keep management or Sign privileges on the
new document. Do not add a blob-export API.

## What we refuse to do

- Export `managed_key_blob`.
- Treat `apply_document_update` as a climb.
- Accept our key (Sign, or C1 All) as signer.
- Complete with only our resolvers, or count `btcr:` as "not us."
- Server-generate a provenance mark or persist a generator.
- Infer C3 vs C4 from privileges. Rung is stored.
- C3→C2 or C1→C3 through this function.

## Successor digest

If `successor_digest` is NULL (v1 default), skip. If set, the **client**
checks it (`4qd`) before submit.

## First relocation

This ceremony is the first `cmd`. Later relocation does not change
privilege shape, blob, or rung — so it may use `apply_document_update`
once that path refuses non-`is_c2` docs on a C2 row. After C3, later
relocation is a C3-to-C3 document write (not this function).
