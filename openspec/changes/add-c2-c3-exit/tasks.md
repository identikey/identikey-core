# Tasks

Owed by this activation (`nod-c2-c3-adr`) only:

- [x] ADR-011 in `docs/ARCHITECTURE.md`
- [x] Correct ADR-008 / I3 "hand them our key" / "authorised by our key"
- [x] Deltas for the C2→C3 ceremony on `managed-custody`
- [x] Independent architecture read (critic REVISE; findings absorbed)

- [x] `migrate_c2_to_c3`: Elect signature, one UPDATE, consent then event
- [x] `apply_document_update` refuses a non-`is_c2` document on a C2 row
- [x] Tests: happy path, only-ours resolvers, our Sign key, C1 skip, apply hole

Not owed here (bullets, not boxes):

- Resolver HTTP — `identikey-core-998`
- Threshold client — `identikey-core-5f3`
