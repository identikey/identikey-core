# add-pairwise-salt

> **ACTIVE BUILD**

Activated from `nod-pairwise-salt` (`identikey-core-88b`).

**Rigor:** change

## Why

ADR-009: pairwise `sub` is `KDF(salt, XID, sector)`. The salt is
per-deploy secret material, same footing as JWT signing keys. A
shipped default or a rotation would break every RP account at once.

## What

- Generate the salt at install / first boot. No value in the tree.
- Store it with the signing keys. Never log it.
- Rotation is unsupported (documented, not implemented).
- Export shape includes enough to recompute pairwise `sub`s.
- Capability `oidc-provider` (ADDED).

## Impact

- Capabilities: ADDED requirements on `oidc-provider`
- ADRs: none (implements ADR-009 action 3). KDF name comes from
  `docs/oidc-implementation-checklist.md` (`ccf.1`).

## User journey & surfaces

No new UI because this is install/secret material. The account export
surface is later (`xwk`); this change only defines the bytes.

## Out of scope

- The `sub()` function — `add-sub-seam`
- Endpoints — `add-oidc-endpoints`
- Proving export round-trips — `add-pairwise-export`
- Checklist file — `ccf.1` / `act nod-oidc-checklist`
