# add-sub-seam

> **ACTIVE BUILD**

Activated from `nod-sub-seam` (`identikey-core-duw`).

**Rigor:** change

## Why

ADR-009: every token `sub` must go through one function so
pairwise vs disclosed is a single decision. Inlining at mint sites
is how we accidentally ship a bare XID to a pairwise client.

## What

- One `sub(xid, client)` (name may vary) in `identikey-oidc`.
- Client registration carries `subject_type` (`pairwise` default;
  `public` requires per-RP consent — consent gate may be a flag
  until account UI exists).
- Discovery will advertise both types (the field is owned here;
  publishing it is `add-oidc-endpoints`).
- Capability `oidc-provider` (ADDED).

## Impact

- Capabilities: ADDED requirements on `oidc-provider`
- ADRs: none (implements ADR-009 actions 1–2)

## User journey & surfaces

No new UI because this is a library function. Account consent for
`public` is `ccf.11`.

## Out of scope

- Salt generation — `add-pairwise-salt`
- Discovery HTTP — `add-oidc-endpoints`
- Export proof — `add-pairwise-export`
