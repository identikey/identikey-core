# add-c2-c3-exit

> **ACTIVE BUILD**

This activation (`nod-c2-c3-adr`) writes the ADR and the deltas.
Ceremony **code** is `nod-c2-c3-exit` and is not owed here.

## Why

C2 without an exit is rent. After ADR-010 we cannot "hand them our key" and we
cannot authorize the climb ourselves. After ADR-007 we cannot leave resolution
at N=1 on our hosts. The ceremony has to be specified before it is coded, or
the implementer will rebuild the withdrawn zan.2 sentence.

## What

- ADR-011: destroy `managed_key_blob`, do not export it; Elect *signature*
  authorizes; `migrate_c2_to_c3` is the only climb; `apply_document_update`
  must refuse non-`is_c2` docs on a C2 row; resolution N≥2 distinct hosts
  outside our eTLD+1s; same XID; one UPDATE.
- Deltas on `managed-custody` so fold has a requirement to land.
- `identikey-core-cmd` first-relocation is this ceremony.

Capability: `managed-custody` (ADDED requirements; living spec not yet folded
from `add-keys-store`).

## Impact

- Capabilities: ADDED requirements on `managed-custody`
- ADRs: ADR-011 added; ADR-008 "authorised by our key" clause corrected

## User journey & surfaces

No new UI because this node specifies the keys-crate ceremony only. The account
surface that will start it is `identikey-core-ccf.11`.

Intended path, for the implementer: a C2 user chooses leave-managed-custody,
generates a Sign key locally, names at least one resolver we do not operate,
submits the new document; we persist it only if Elect passes and the fail-closed
checks hold; they can stop paying; their XID is unchanged.

## Out of scope

- Ceremony implementation (`nod-c2-c3-exit` / remaining `zan.2` code)
- Serving the document (`identikey-core-998`)
- Threshold reads (`identikey-core-5f3`)
- C3→C2 downward ceremony (I4)
- Export of `managed_key_blob`
- Guardian recovery (`identikey-core-vt4`)
- Pre-rotation on by default (`identikey-core-zan.5`)
- Account UI (`identikey-core-ccf.11`)
