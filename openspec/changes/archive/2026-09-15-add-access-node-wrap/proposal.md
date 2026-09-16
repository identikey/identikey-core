# add-access-node-wrap

> **ACTIVE BUILD**

**Rigor:** change

Named by `identikey-core-trr.2`. Architecture is ADR-012 / folded
`add-guild-keyspaces`. Apply path is folded `add-keyspace-runtime`.
This change is wrap-on-login for the access-node profile.

## Why

Protocol §10: identikey login wraps the caller's latest PUK to the
access-node PTK. Join/leave must not rotate that PTK. The replica
already nests an access-node keyspace, but a subsequent `keyspace.join`
ignored wraps on that profile, so login could not add a recipient.

## What

- Capability `guild-keyspaces`: access-node subsequent join merges
  wraps and does not change epoch.
- `KeyspaceReplica::wrap_login` applies that join. Wrap-target is
  `c2_wrap_recipient`: the user's X25519 encapsulation half, never
  IdentiKey Sign+Auth.
- No new HTTP surface. Login already exists; the node that holds the
  access-node replica calls `wrap_login` after assertion. Loading that
  replica at OP boot is Lightning Admin assign/nest (`mjolnir-mesh-st1.5`).

## Impact

- Capabilities: ADDED / MODIFIED on `guild-keyspaces`
- ADRs: none (ADR-012 already decided replica/cache and PUK)

## User journey & surfaces

No new UI because `/authorize/passkey` is already the login. After a
successful assertion, identikey-keys applies a `keyspace.join` on the
access-node replica the node holds: roster/blacklist update, wrap list
gains the caller's PUK, epoch unchanged.

## Out of scope

- House/buyer kick-rekey — already on the living spec
- Lightning Admin assign/nest verbs — `mjolnir-mesh-st1.5`
- Fleet client SSID — `client-network-name`
- Protocol `PublicKey.alg` `x25519` roster — `ikp-2l8`
- Persisting identikey-log ops (replica remains home)
- Wrapping to `managed_key_blob`
