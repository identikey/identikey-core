# add-pairwise-export

> **ACTIVE BUILD**

Activated from `nod-pairwise-export` (`identikey-core-xwk`).

**Rigor:** change

## Why

ADR-009: the exit test for pairwise is export, not cryptography.
Untested export is the failure mode. A successor OP given the
export must reproduce every `sub` the user already has.

## What

- User export includes the pairwise salt (or the derived
  sector → `sub` map) plus enough to identify the XID
- A test feeds that export into the `sub` seam and matches issued
  values
- Capability `oidc-provider` (ADDED)

## Impact

- Capabilities: ADDED requirements on `oidc-provider`
- ADRs: none (implements ADR-009 action 4)

## User journey & surfaces

No new UI because this is an export API / test. Account download
UI is `ccf.11`.

## Out of scope

- Salt generation — `add-pairwise-salt`
- Account UI — `ccf.11`
- Guardian recovery of the salt — not a vt4 obligation (ADR-009)
