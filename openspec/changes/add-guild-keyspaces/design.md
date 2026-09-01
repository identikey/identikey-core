# Design — Guilds as shared keyspaces (ADR-012)

Steer 2026-08-31 / 2026-09-01 is the source. This file does not re-open
those decisions. Independent read is the advise pass (reader Grok 4.6).

## What a guild is

A guild is a **distributed keyspace object**. It is the composition of the
keys that comprise it. It does not live in a place. It is not a document
housed at identikey-core, on one mesh node, or in Postgres.

Anyone holding an admin key keeps it alive: they replicate and sign. If
every admin key is gone or stops participating, the object fades. Holders
replicate a signed artifact (roster, wrap-list, nested ids). That artifact
is evidence of the object, not its home.

XID stays who-I-am. Join/leave is not an Elect rewrite of the member XID.
The root identikey still Elects and rotates its own keys (ADR-001, privilege
split ADR-010). It Elects a keyspace artifact only if it holds an admin key
on that keyspace.

An earlier steer comment (2026-09-01 02:10) said "separate guild document
with XID-shaped inception." The 2026-09-01 correction supersedes that:
distributed object, not a located document.

## Methods (FOKS, not FOKS-the-product)

Source: FOKS whitepaper key hierarchy. Do not run FOKS servers. Do not
replace XID with `user@host`.

| Layer | Name | Role |
|---|---|---|
| Device | device key | per-device; revoke cascades |
| User | PUK | per-identikey user key; latest PUK is the wrap target |
| Keyspace | PTK | per-keyspace (team) key; encrypted to each member's latest PUK |

Clients, not servers, control key management. Rotation of a device or a
member updates the wrap-list. Envelope rewrap (KMS-style): do not rewrite
every blob keyed to the PTK.

## Two words

| Plane | Word |
|---|---|
| Protocol, `ikp-cvu`, `identikey-log` op kinds | `keyspace` (nested keyspace) |
| Lightning Mesh UI and Admin | `guild` |

Op kinds look like `keyspace.join` / `keyspace.leave` /
`keyspace.assign-node` / `keyspace.nest` / `keyspace.epoch-begin` /
`keyspace.epoch-commit`. Not `guild.*`.

No OIDC claim named `guilds`.

## Radio is orthogonal (D1)

Client SSID is a public radio name. Joining Wi-Fi is not membership. Open
⚡ remains a visitor network (`hello.mesh`). A PSK, if any, is a radio
filter, not the keyspace secret. Membership is an identikey ceremony. One
keyspace may later span multiple radio islands because membership is not
the SSID.

Lightning Admin v1 writes fleet client SSID via `mjolnir-apply` only, and
labels it **network name**. That slice is `add-client-network-name` in
lightning-mesh. Apply-to-radio is never a silent dual-write with a
keyspace op.

## Log is transport (D3b)

`identikey-log` already exists in identikey-protocol: signed, actor-
attributed, content-addressed, causally ordered, body opaque, concurrency
surfaced and not merged. That is the right shape.

Ops ride the log among holders. Postgres / identikey-core is a
materialization/cache if it exists at all, not the coordinator and not the
home. Epoch commit is ops on the log (`epoch-begin` / `epoch-commit`). The
keyspace consumer defines the rotation-graph commit rule. The log does not
merge concurrent ops.

`consent_log` in identikey-keys is a different thing: hash-chained C2
*access-credential* proofs for managed custody. Do not reuse it as the
keyspace op log (AGPL/recrypt entanglement is why it was reimplemented
locally; the pattern is not the protocol log).

## Hybrid eviction (D3)

Two layers, both required:

1. **Instant ACL / blacklist** — roster deny on request-to-bytes. A kick
   takes effect without waiting for cryptography.
2. **Cryptographic PTK rotation** — stop decryption. Configurable epoch.
   When it fires: directed graph of member-key rotation and every PTK whose
   wrap-list changed, plus every system holding secrets keyed to this
   keyspace. Commit is all-or-none. Analog: AWS KMS envelope rotation.

Roster-only is not cryptographic eviction. Rotation-only without ACL leaves
a window where the kicked member still decrypts.

## Two profiles, nested

**House / buyer keyspace.** Configurable epoch. Kick can rekey. Secrets
live here.

**Access-node keyspace** (`identikey-core-trr.2`, not this act). Inner
guild, created after Lightning Admin assigns the node to an outer
keyspace. High churn, long epoch, lower assurance. Identikey login wraps
the caller's latest PUK to that node's PTK. Used for local service-mesh
broadcast/comms (`.mesh`, mDNS-class), not house secrets, not Recrypt
data-groups. Roster/blacklist updates immediately; PTK does not rotate on
each join.

Verbs: join/change, assign node, nest. Not rename.

## Three layers stay uncollapsed

From `identikey-capability-v1`:

| Layer | Question | This work |
|---|---|---|
| Identity | Who is this? | XID + keyspace membership (this capability) |
| Agency | What may they do? | Biscuit. Not membership. |
| Data access | Who can read this ciphertext? | Recrypt. Not a guild. |

Mixing any two is a protocol error. `mjolnir-mesh-6t7` (Recrypt group
overlay) stays deferred.

## What identikey-keys does later

Runtime (`add-keyspace-runtime`) wraps and unwraps against holders'
`identikey-log` replicas. It may materialize roster/epoch in Postgres as a
cache. It must not become the source of truth. `authorize_elect` continues
to gate the member's own XID document. Keyspace ops are signed by an admin
key of that keyspace, not by IdentiKey's Sign key.

## Factory and mesh

Factory client SSID ⚡ can ship without identikey. Buyers set the network
name. That is radio. Guild join is later, on identikey login.
