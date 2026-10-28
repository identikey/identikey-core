# steer add-client-sector-pin

**When.** 2026-09-29
**Depth.** standard

## Decided
- Backfill procedure: back up, write the derived sector into escrow and guest env, restart, verify Taskmaster/Conduit subs unchanged — human-gated inside this change (auto)
  Why: the only live-identity step; no real alternative survived.
- Epic-level (user): owner-signed records, LISTEN/NOTIFY + 30s TTL, invite tokens first — apply to `.2`–`.4`, not here.

## Skipped
- none

## Feeds change
Make the sector explicit configuration and refuse boot without it for pairwise clients. Freeze today's derived values into escrow before the binary that enforces this ever runs.
