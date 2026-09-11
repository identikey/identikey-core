## ADDED Requirements

### Requirement: Consume identikey-keyspace-v1

identikey-keys SHALL treat identikey-protocol
`docs/standards/identikey-keyspace-v1.md` as the wire for shared
keyspaces. It SHALL NOT invent a second keyspace identifier, an eighth
op kind, a `guild.*` kind, or a merge rule for concurrent
`epoch-begin` ops. The keyspace id SHALL be the identikey-log
`content_hash` of the genesis op (outer: first admin `keyspace.join`;
inner: `keyspace.nest`). Postgres, if present, SHALL be a cache of
applied ops, not the source of truth.

#### Scenario: Genesis id is the join hash

- GIVEN a first `keyspace.join` whose body lists an `admin: true`
  roster entry and a PTK wrap-list
- WHEN identikey-keys applies that op
- THEN the keyspace id equals that op's identikey-log `content_hash`

#### Scenario: Postgres cache is not the home

- GIVEN holders of a keyspace and an optional identikey-core
  materialization
- WHEN the materialization is deleted
- THEN holders who still have `admin: true` keys can continue the
  keyspace from their log replicas

### Requirement: Join does not Elect the member XID

Join and leave SHALL NOT rewrite the member XID document.
`authorize_elect` SHALL continue to gate XID document writes only.
Keyspace ops SHALL be accepted only from an Ed25519 `Op.actor` that
is `admin: true` on the applied roster, except outer genesis where
the actor SHALL appear as `admin: true` in that same join body.

#### Scenario: Join leaves the stored XID bytes unchanged

- GIVEN an identikey whose XID document is stored
- WHEN that identikey is added to a keyspace roster
- THEN the stored member XID document bytes are unchanged

#### Scenario: IdentiKey Sign cannot author a keyspace op

- GIVEN a stored C2 identity
- WHEN IdentiKey's Sign key is used as `Op.actor` on a `keyspace.*` op
- THEN the op is refused and the roster is unchanged

### Requirement: Wrap-target is the user's X25519 encapsulation key

On a C2 document built by `c2_native` from `PrivateKeyBase::new()`, the
PTK SHALL be wrapped to the user's X25519 encapsulation public (the
encapsulation half of that `PublicKeys`), using protocol §7
`x25519-xchacha20poly1305`. identikey-keys SHALL NOT treat the Schnorr
signing half as a wrap-target, SHALL NOT apply protocol §7.2
(Ed25519→X25519) to Schnorr, SHALL NOT wrap to IdentiKey Sign+Auth,
`managed_key_blob`, or a `credentials` passkey, and SHALL NOT list a
C1 row as a member. A row whose user private is not held by the user
MAY be named as a protocol §7 `Wrap.recipient`; unwrap SHALL fail until
that private is user-held (inert on purpose; not a reason to wrap to
`managed_key_blob`). Until identikey-protocol `ikp-2l8` adds
`PublicKey.alg` `x25519`, that row SHALL NOT be written as a protocol
§6 `RosterEntry`. PUK rotation of that encapsulation key SHALL
be an Elect-gated XID document write, then `keyspace.epoch-begin` /
`epoch-commit`.

#### Scenario: C2 Sign key is absent from wraps

- GIVEN a C2 identity joining a house keyspace
- WHEN wraps for the current epoch are applied
- THEN no wrap recipient is IdentiKey's Sign+Auth public

#### Scenario: C2 wrap recipient is the X25519 encapsulation half

- GIVEN a stored C2 document from `c2_native` + `PrivateKeyBase::new()`
- WHEN wraps for the current epoch are applied
- THEN each wrap recipient for that member is that document's user
  X25519 encapsulation public and not the Schnorr signing public

#### Scenario: C1 cannot be a member

- GIVEN a stored C1 identity (no user key)
- WHEN a `keyspace.join` lists that identikey as a wrap-target
- THEN the op is refused

#### Scenario: C2 wrap is named and inert until user-held private

- GIVEN a C2 row whose user `PrivateKeyBase` was dropped at signup
- WHEN a wrap lists that row's X25519 encapsulation public as recipient
- THEN the wrap is stored as protocol §7 `Wrap.recipient` and unwrap
  by that member fails until Elect export or a wallet holds the private

#### Scenario: C2 is not a §6 RosterEntry until ikp-2l8

- GIVEN a stored C2 document whose only user PUK is native X25519
- WHEN identikey-keys is asked to encode a protocol §6 `RosterEntry`
  for that member
- THEN it refuses rather than mint `alg: "x25519"`; join that needs
  that entry waits on identikey-protocol `ikp-2l8`

#### Scenario: Schnorr cannot author a keyspace op

- GIVEN a C2 member whose only user signing key is Schnorr and who
  has no Ed25519 `actor`
- WHEN that Schnorr public is used as `Op.actor`
- THEN the op is refused

### Requirement: Device revoke is not a keyspace op

Devices SHALL remain `credentials` rows. Revoking a device SHALL NOT
by itself remove a PTK wrap. The cascade SHALL be: device revoke,
then PUK rotation, then rewrap of the PTK to the latest PUK.

#### Scenario: Device revoke does not edit the PTK wrap-list

- GIVEN a member with two `credentials` rows and a PUK wrap of the PTK
- WHEN one credential is revoked and the PUK is not rotated
- THEN the PTK wrap-list is unchanged and the member XID still Elects
  (a passkey never holds PUK material; revoke does not start a PUK rotate)

#### Scenario: PUK rotate then rewrap

- GIVEN a member whose device was revoked and whose PUK then rotates
- WHEN a keyspace admin commits an epoch (or a rewrap to latest PUK)
- THEN the PTK wrap-list targets the new PUK and not the old one

### Requirement: Fade is administering, not remaining wraps

When the last `admin: true` roster entry leaves, identikey-keys SHALL
refuse further administering ops. Ciphertext keyed to the last PTK
SHALL remain unwrap-able until a committed epoch replaces that PTK.

#### Scenario: Last admin leave stops new ops

- GIVEN a keyspace whose roster has one `admin: true` entry
- WHEN that entry leaves
- THEN a subsequent `keyspace.join` is refused

#### Scenario: Last PTK still unwraps after fade

- GIVEN that keyspace after the last admin left, with no epoch commit
- WHEN a remaining member unwraps a blob keyed to the last PTK
- THEN unwrap succeeds

### Requirement: Hybrid eviction follows protocol §8

A kick SHALL take effect on roster/blacklist immediately. Cryptographic
eviction SHALL be `keyspace.epoch-begin` then `keyspace.epoch-commit`
with the matching begin in parent hashes. identikey-keys SHALL NOT
merge concurrent `epoch-begin` ops and SHALL NOT apply either until an
admin nacks one or a later begin parents exactly one.

#### Scenario: Kick without waiting for rotation

- GIVEN a member on the roster
- WHEN an admin leaves or blacklists that member
- THEN subsequent request-to-bytes for that member is denied before
  epoch-commit

#### Scenario: Concurrent epoch-begin is a conflict

- GIVEN two `keyspace.epoch-begin` ops where neither is an ancestor
  of the other
- WHEN a holder applies the log
- THEN neither begin is applied until an admin nacks one or a later
  begin parents exactly one

### Requirement: Two profiles, no OIDC guilds claim

A house keyspace SHALL use protocol profile `"house"` (configurable
epoch; kick MAY begin an epoch). An access-node keyspace SHALL use
`"access-node"` (long epoch; join/leave SHALL NOT rotate the PTK on
each event) and SHALL be nested after `keyspace.assign-node` then
`keyspace.nest`. identikey-oidc SHALL NOT emit a claim named `guilds`.
`keyspace.assign-node`'s `node` field SHALL be stored as opaque 32
bytes.

#### Scenario: Access-node join does not rotate PTK

- GIVEN an access-node keyspace at a long epoch
- WHEN identikeys join and leave during that epoch
- THEN the roster/blacklist updates and the PTK epoch is unchanged

#### Scenario: No guilds claim on a token

- GIVEN an identikey-oidc ID token or userinfo body
- WHEN a relying party inspects claims
- THEN there is no claim named `guilds`

#### Scenario: Assign-node id is opaque

- GIVEN a `keyspace.assign-node` body with a 32-byte `node` field
- WHEN identikey-keys applies it
- THEN the bytes are stored as given and not interpreted as an XID
