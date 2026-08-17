# add-xid-resolver

> **ACTIVE BUILD**

Activated from `nod-serve-xid` (`identikey-core-998`).

**Rigor:** change

## Why

ADR-007 (5): the OP serves the XID document as an availability service.
It holds no authority the document does not grant it. Freshness is a
security property — a stale valid document after a compromise rotation
presents the attacker's key as current. A well-known GET with a short
TTL and a revalidation signal is the hole the C2→C3 climb assumed.

## What

- `GET /.well-known/xid/{xid}` on `identikey-server` returns the stored
  document bytes for that XID.
- Short documented TTL plus ETag / `must-revalidate` so a rotation is
  visible without waiting out the cache.
- Capability `xid-resolution` (ADDED).

## Impact

- Capabilities: ADDED `xid-resolution`
- ADRs: none (implements ADR-007 §5; no new ADR)

## User journey & surfaces

No new UI because this is an HTTP well-known for relying parties and
other resolvers. `/health` stays liveness-only.

Intended path: an RP that already has the XID (or a user who listed our
URI as a `resolution_method`) GETs the path, receives the current
signed document, and may revalidate with `If-None-Match` after a
rotation instead of honouring a stale cache for the full TTL.

## Out of scope

- Threshold / duplicity reads — `add-threshold-resolve` / `identikey-core-5f3`
- Push webhooks to arbitrary RPs (no subscriber registry yet)
- `/.well-known/webauthn` — `identikey-core-2js`
- Resolver relocation writes — `add-resolver-relocation` / `identikey-core-cmd`
- Pairwise-sub RPs that never see the XID — ADR-009 / `ccf`
