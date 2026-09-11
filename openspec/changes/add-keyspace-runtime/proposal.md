# add-keyspace-runtime

> **PENDING**

**Rigor:** change

Named by `add-guild-keyspaces` / ADR-012. Protocol source is
identikey-protocol `docs/standards/identikey-keyspace-v1.md`. This
change consumes that wire in `identikey-keys`. It does not fork kinds,
genesis id, admin field, or epoch conflict.

Steer residue and C2 mapping live on `identikey-core-trr.1` and
ADR-012. Bead `identikey-core-trr.3`. Advise nits on the architecture
packet (no `keyspace.rewrap`, nest admin is outer roster, no guardian
request-to-bytes API) bind this act.

## Why

ADR-012 decided identikey-keys is a replica/cache of `identikey-keyspace-v1`
ops on `identikey-log`. The crate still has no apply path. Without it,
join cannot happen, Sign can be imagined as a wrap-target, and Postgres
looks like a home.

## What

- Capability `guild-keyspaces` (already ADDED by `add-guild-keyspaces`;
  this change ADDs the apply/cache requirements).
- Git-dep `identikey-log` (rev pin, same pattern as `identikey-auth`).
  Type protocol §9 bodies here. Do not amend the log. Do not import
  recrypt or `identikey-storage-auth`.
- Apply `keyspace.*` ops from holders' replicas. Optional Postgres
  materialization of roster/epoch/wraps. Cache is not the home.
- Refuse IdentiKey Sign+Auth as `Op.actor` and as wrap-target. PUK
  selector is the user's latest identity key. `authorize_elect` stays
  on the member XID path alone.
- Wrap-list change is `keyspace.epoch-begin` then `epoch-commit`.
  Concurrent begins: nack-or-parent; do not merge.

`managed-custody` is not modified.

## Impact

- Capabilities: ADDED requirements on `guild-keyspaces`
- ADRs: none (ADR-012 already decided the mapping)

## User journey & surfaces

No new UI because this is the identikey-keys apply path. Holders present
signed `keyspace.*` ops; the crate applies them to a replica and may
cache roster/epoch/wraps. Login wrap-on-login is `identikey-core-trr.2`.

## Out of scope

- Protocol wire — `identikey-keyspace-v1` (already folded)
- Architecture mapping — `add-guild-keyspaces` / ADR-012
- Access-node wrap-on-login — `identikey-core-trr.2`
- Fleet client SSID — lightning-mesh `client-network-name`
- Lightning Admin SSID knob — `mjolnir-mesh-st1.3`
- Lightning Admin v2 verbs — `add-lightning-admin-guild`
- Recrypt as guild identity — `mjolnir-mesh-6t7`
- Biscuit as membership — `identikey-capability-v1`
- Wallet `"keyspace-membership"` assertion
- HTTP /signup or `/authorize` surfaces
- Amending identikey-log
- A `keyspace.rewrap` kind
- Guardian request-to-bytes API
