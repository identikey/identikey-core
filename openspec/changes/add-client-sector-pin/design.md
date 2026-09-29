# design add-client-sector-pin

Security-relevant: a wrong sector re-mints every pairwise `sub` at an RP.

## Shape

`ClientJson` gains `sector: Option<String>`; the primary client reads
`IDENTIKEY_CLIENT_SECTOR`. `client_from_spec` takes the sector and:

- pairwise (default) with no or empty sector → error naming the client id;
- public → sector optional; when absent use the client id (never read by
  `sub`, kept non-empty for `Client::new`).

`sector_from_redirect` is removed from the boot path. It survives only in
the backfill helper below, so the one place that still derives a sector is
the place that freezes it.

## Backfill (before deploy, human-gated)

1. Verify the host escrow and the running guest hold the same
   `IDENTIKEY_CLIENTS` (sha256) — the procedure from 2026-09-29.
2. For every pairwise client, set `sector` to today's derived value: host of
   the first entry of `merge_redirects(redirect, redirects)`. Same for the
   primary client via `IDENTIKEY_CLIENT_SECTOR`.
3. Write escrow + guest env, restart the *old* binary (it ignores `sector`),
   confirm login still works.
4. Deploy the new binary. For one known XID, compare the pairwise `sub` at
   taskmaster and Conduit before and after: identical.

Order matters: the new binary must never boot against an escrow without
sectors, or it refuses to start (by design) and every RP loses login.

## Why not keep deriving with a warning

A warning is read after the identities already moved. Refusing to boot is
loud at the only moment the operator is watching.
