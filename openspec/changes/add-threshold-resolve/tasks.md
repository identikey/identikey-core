# Tasks

- [x] `resolve_documents` in `identikey-keys` over already-fetched bytes
- [x] Same-chain: highest provenance mark wins
- [x] Two valid documents, divergent chains: `Duplicity`, no winner
- [x] `ResolutionTier::Consequential` refuses a cached-only input
- [x] Tests: happy chain, duplicity, unmarked identical copies, parse-failure drop

Not owed here (bullets, not boxes):

- HTTP GET of remote `resolution_methods`
- Well-known serve — `add-xid-resolver`
