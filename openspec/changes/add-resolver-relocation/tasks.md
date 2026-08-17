# Tasks

- [ ] `apply_document_update` on C3/C4 runs `check_resolution` (same rules as climb)
- [ ] C3 resolver-only update persists; rung and blob unchanged
- [ ] Dropping the last not-us host is refused; row unchanged
- [ ] C2 path still refuses a non-`is_c2` document
- [ ] Tests: happy C3 relocate, only-ours refused, C2 unchanged

Not owed here (bullets, not boxes):

- HTTP well-known — `add-xid-resolver`
- Threshold reads — `add-threshold-resolve`
- C3→C2
