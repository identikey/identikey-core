# add-resolver-relocation

> **ACTIVE BUILD**

Activated from `nod-relocate-resolvers` (`identikey-core-cmd`).

## Why

ADR-007: relocation is a document update the user performs, not a
support request. ADR-011: the first relocation is C2→C3 (already
landed). Later relocation must not change privilege shape, blob, or
rung — and must still refuse a set that is only us. Today
`apply_document_update` Elect-gates and keeps C2 as C2, but a C3 row
can persist any resolver set.

## What

- On a C3/C4 row, `apply_document_update` re-runs the climb's
  resolver rules (N≥2 distinct HTTP(S) hosts, one eTLD+1 outside
  `{identikey.me, identikey.io}`, no hostless-as-not-us, no
  localhost/RFC1918).
- Rung and `managed_key_blob` stay as stored.
- C2 path unchanged (still refuses non-`is_c2`).
- Capability `managed-custody` (ADDED requirement).

## Impact

- Capabilities: ADDED requirement on `managed-custody`
- ADRs: none (implements ADR-007 relocation + ADR-011 §8)

## User journey & surfaces

No new UI because this is the keys-crate write. The account surface
that will start it is `identikey-core-ccf.11`.

Intended path: a C3 user Elects a new document that adds, replaces, or
removes a `resolution_method`; we persist it only if Elect passes and
the remaining set still satisfies the exit-test resolver rules; we
never touch the blob or the rung.

## Out of scope

- First relocation (C2→C3) — already `migrate_c2_to_c3`
- Serving the document — `add-xid-resolver`
- Threshold client — `add-threshold-resolve`
- C3→C2 (I4)
- Account UI (`ccf.11`)
