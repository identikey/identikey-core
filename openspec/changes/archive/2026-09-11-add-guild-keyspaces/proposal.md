# add-guild-keyspaces

> **ACTIVE BUILD**

**Rigor:** architecture

Steer residue is on `identikey-core-trr.1`. Send-back 2026-09-01
(`reviews/2026-09-01-advise.md`). Other-family send-back 2026-09-11
(`reviews/2026-09-11-advise.md`, `fable-5.1-arch-review`): C2 PUK is
the X25519 encapsulation half on the stored document, not
Ed25519-via-X25519; Schnorr cannot be `Op.actor`; signup drops the
user private so unwrap is inert until Elect export/wallet.
Protocol source is identikey-protocol
`docs/standards/identikey-keyspace-v1.md` (folded `add-keyspace-spec`).
This change does not fork kinds, genesis id, admin field, or epoch
conflict. Runtime is `add-keyspace-runtime` after advise accept.

## Why

Several identikeys need to hold keys in one space. Recrypt is data
access. Biscuit is agency. XID is who-I-am. None of those is a shared
keyspace. FOKS-the-product is not the identity plane. identikey-keys
must consume the protocol keyspace without turning join into an Elect
rewrite or putting radio SHALLs in this crate.

## What

- Capability `guild-keyspaces` (product word **guild**). Protocol word
  **keyspace**. One object, two words (D5).
- ADR-012: identikey-keys is a replica/cache of `identikey-keyspace-v1`
  ops on `identikey-log`. Postgres is optional materialization, not the
  home. Root identikey still Elects its own XID (ADR-001, ADR-010).
- Map C2: wrap-target is the user's X25519 encapsulation half on the
  stored `PublicKeys`; Schnorr is Elect-only; IdentiKey Sign+Auth is
  not a wrap-target; devices are `credentials` rows, not PTK wrap
  targets. Today's C2 rows are wrap-target-only until a user-held
  Ed25519 actor exists. Unwrap waits on Elect export or a wallet.
- Two profiles (house / access-node) as protocol `profile` strings.
  Access-node wrap-on-login is `trr.2`.

`managed-custody` is not modified.

## Impact

- Capabilities: ADDED `guild-keyspaces`
- ADRs: ADR-012 will amend `docs/ARCHITECTURE.md` (act after advise)

## User journey & surfaces

No new UI because this node specifies the identikey-keys mapping onto
`identikey-keyspace-v1` only.

Intended path, for later act: a member joins a house keyspace by
identikey ceremony; `authorize_elect` is unchanged on their XID;
keyspace ops are signed by a keyspace admin Ed25519 actor. Radio name
and Lightning Admin verbs are other repos.

## Out of scope

- FOKS servers, `user@host`, encrypted git, FOKS KV
- Recrypt as guild identity (`mjolnir-mesh-6t7` stays deferred)
- Biscuit as membership (`identikey-capability-v1` stays agency)
- Group crypto in mjolnir-mesh
- Keycloak rename (leftover mapper, if any, is `legacy_groups`)
- Authoritative membership on the member XID (wallet
  `"keyspace-membership"` later)
- `hello.mesh` / `bf7` as this surface
- Silent dual-write of SSID and keyspace
- `rename-guild` verb
- Protocol wire (`identikey-keyspace-v1` already folded)
- Runtime wrap/rotate (`add-keyspace-runtime`)
- Access-node wrap-on-login (`identikey-core-trr.2`)
- Fleet client SSID (`lightning-mesh` `client-network-name`)
- Lightning Admin v1 SSID knob (`mjolnir-mesh-st1.3`) and v2 verbs
  (`add-lightning-admin-guild` / `mjolnir-mesh-st1.5`)
