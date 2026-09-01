# add-guild-keyspaces

> **ACTIVE BUILD**

Steer residue is on `identikey-core-trr.1` (2026-08-31 / 2026-09-01).
This change is the architecture node. Runtime is `add-keyspace-runtime`
after advise accept. Protocol landing is `ikp-cvu` / `add-keyspace-spec`.

## Why

Several identikeys need to hold keys in one space. Lightning Mesh wants a
public radio name; a household wants a house keyspace; a node wants a
shabbier inner keyspace for local `.mesh` comms. Recrypt is data access.
Biscuit is agency. XID is who-I-am. None of those is a shared keyspace.
FOKS-the-product (servers, `user@host`) is not the identity plane. Without
this layer, mesh "guild" talk collapses into Recrypt groups or Wi-Fi join.

## What

- Name the capability `guild-keyspaces` (product). Protocol word is
  `keyspace`. One object, two words (steer D5).
- ADR-012: a guild is a distributed object — the keys that comprise it.
  FOKS methods (device → PUK → PTK). Root identikey still Elects (ADR-001,
  ADR-010). `identikey-log` moves ops among holders; Postgres is an optional
  materialization, not the home.
- Deltas on the new capability so fold has a place to land.
- Record the two profiles (house / access-node) and Lightning Admin slices
  so later nodes do not re-litigate steer.

Capabilities: `guild-keyspaces` (ADDED). `managed-custody` is not modified:
join/leave is not an Elect rewrite of the member XID.

## Impact

- Capabilities: ADDED `guild-keyspaces`
- ADRs: ADR-012 will amend `docs/ARCHITECTURE.md` (act after advise)

## User journey & surfaces

No new UI because this node specifies the identikey-keys / identikey-log
architecture only.

Intended path, for later act: a buyer names a network (SSID, radio slice
`add-client-network-name`); members join the house keyspace by identikey
login, not by associating to Wi-Fi; a node assigned to that house then
gains an inner access-node keyspace whose PTK wraps on login for local
service-mesh comms. Lightning Admin v2 verbs (join/change, assign node,
nest) are a later mesh node. This change does not ship those surfaces.

## Out of scope

- FOKS servers, `user@host`, encrypted git, FOKS KV
- Recrypt as guild identity (`mjolnir-mesh-6t7` stays deferred)
- Biscuit as membership (`identikey-capability-v1` stays agency)
- Group crypto in mjolnir-mesh
- OIDC claim named `guilds`; Keycloak rename (leftover mapper, if any,
  is `legacy_groups`; live TS `user.guilds` is Keycloak-era CLI/MCP only)
- Authoritative membership on the member XID (wallet
  `"keyspace-membership"` stays a later non-authoritative pointer)
- `hello.mesh` / `bf7` as this surface
- Silent dual-write of SSID and keyspace
- `rename-guild` verb
- Protocol spec file (`ikp-cvu`)
- Runtime wrap/rotate (`add-keyspace-runtime`)
- Access-node wrap (`identikey-core-trr.2`)
- Lightning Admin v2 (`add-lightning-admin-guild`)
