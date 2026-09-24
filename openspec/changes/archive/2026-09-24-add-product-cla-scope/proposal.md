# add-product-cla-scope

> **ACTIVE BUILD**

**Rigor:** change
**Capability:** contribution-policy (ADDED)
**Intention:** revisit-contribution-policy

## Why

Commercial dual-licensing needs a grant from contributors, and an
assignment CLA is how a buyer later stops releasing. The burial
analysis already found that `recrypt/CLA.md` is a license, not an
assignment. That CLA still says it covers the permissive core crates.
Protocol contributions should not be under it.

## What

- Keep a licensing CLA for the product tier. The contributor keeps
  copyright. Identikey Inc. remains the commercial licensor.
- Stop applying that CLA to `identikey-protocol` and to other
  permissive protocol crates.
- Do not convert the CLA into an assignment.

## Impact

- Capabilities: ADDED `contribution-policy`
- ADRs: none. The decision is recorded on `identikey-core-ydd.4`
  and in `docs/licensing-and-commons.md` §4 and §6.6.

## User journey & surfaces

No new UI because contribution terms are repository files, not a
screen in the hosted OP.

A person opening a pull request against `identikey-core` is asked
for the product CLA and keeps their copyright. A person opening a
pull request against `identikey-protocol` is not asked for that CLA.

## Preparation — 2026-09-24

Outcome: still valid. Authority: user said "decide for me. activate."
Bounds: licensing CLA for the product tier only. No assignment. No
new revenue line. No SPDX change to crates already set in commons §5c.
Sibling: `add-protocol-dco` in identikey-protocol. Existing text:
`/Users/dukejones/work/IdentiKey/recrypt/CLA.md` (non-assignment;
currently also covers permissive core crates).

## Out of scope

- Developer Certificate of Origin text — `add-protocol-dco`
- Vendor CLAs under `identikey-protocol/vendor/`
- Foundation stewardship — commons doc option (a), not chosen
- Dropping the commercial license — option (c), not chosen
