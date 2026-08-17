# add-threshold-resolve

> **ACTIVE BUILD**

Activated from `nod-threshold-read` (`identikey-core-5f3`).

**Rigor:** change

## Why

ADR-007 (3–4): a resolver cannot forge a document but can serve an old
valid one. Consequential operations must query K of N and take the
highest provenance mark. Two valid documents that are not on the same
chain are duplicity — fail closed, do not pick a winner.

## What

- Pure function in `identikey-keys`: given already-fetched documents,
  pick the highest provenance mark on one chain, or error on duplicity.
- A `ResolutionTier` so consequential ops cannot be fed a cached
  document.
- Capability `xid-resolution` (ADDED requirements; living spec does
  not exist yet — folds alongside `add-xid-resolver`).

## Impact

- Capabilities: ADDED requirements on `xid-resolution`
- ADRs: none (implements ADR-007 §3–4)

## User journey & surfaces

No new UI because this is a library call for relying parties and for
our own consequential writes. HTTP fetch of remote resolvers is not
this change.

Intended path: a caller that has K document byte-strings (fixtures or
later HTTP) asks the library who wins; a stale-but-chained document
loses to a newer mark; two valid unrelated chains error.

## Out of scope

- Serving our copy — `add-xid-resolver` / `identikey-core-998`
- HTTP client that GETs other resolvers
- Push/webhooks
- Enabling pre-rotation (`zan.5`)
