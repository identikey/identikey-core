# Tasks

- [x] `GET /.well-known/xid/{xid}` on `identikey-server` returns stored document bytes
- [x] 404 for unknown or malformed XID; `/health` unchanged
- [x] `Cache-Control: max-age=60, must-revalidate` and body SHA-256 ETag
- [x] After a document write, a subsequent GET (or revalidate) returns the new bytes
- [x] Tests against the existing `KeysStore` + axum router

Not owed here (bullets, not boxes):

- Threshold / fail-closed — `add-threshold-resolve`
- Push webhooks
- Rewriting `resolution_methods` URIs already stored on test C2 docs
