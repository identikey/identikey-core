# steer add-product-cla-scope

**When.** 2026-09-24
**Depth.** lean

## Decided

- Contribution split: Developer Certificate of Origin for the protocol,
  licensing CLA for the product only (user, decide-for-me).
  Why: an assignment would let a buyer stop releasing, and only
  commercial dual-licensing needs a contributor grant.
- Copyright holder of the commercial right: Identikey Inc. stays the
  licensor (user, decide-for-me). Foundation stewardship was not chosen.

## Skipped

- None on this fork.

## Feeds change

Narrow the product CLA so it does not cover protocol crates. Keep it
a license, not an assignment. Do not draft a new grant beyond what
`recrypt/CLA.md` already gives Identikey Inc. for product code.
