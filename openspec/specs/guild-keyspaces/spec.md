# guild-keyspaces

Living truth for identikey-keys mapping onto identikey-protocol
`identikey-keyspace-v1` (product word **guild**, protocol word
**keyspace**). Folded from `add-guild-keyspaces` (2026-09-11) and
`add-keyspace-runtime` (2026-09-15). Protocol `PublicKey.alg`
`x25519` is identikey-protocol `ikp-2l8`.

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

### Requirement: Apply typed keyspace bodies from identikey-log

identikey-keys SHALL depend on identikey-log and SHALL type `Op.body`
per identikey-keyspace-v1 §9 for kinds `keyspace.join`,
`keyspace.change`, `keyspace.leave`, `keyspace.assign-node`,
`keyspace.nest`, `keyspace.epoch-begin`, and `keyspace.epoch-commit`.
It SHALL NOT amend identikey-log, SHALL NOT add an eighth kind, and
SHALL NOT import recrypt or identikey-storage-auth for this log.

#### Scenario: Genesis join becomes the keyspace id

- GIVEN a first `keyspace.join` whose body lists an `admin: true`
  roster entry and a PTK wrap-list
- WHEN identikey-keys applies that verified op
- THEN the keyspace id equals that op's identikey-log `content_hash`

#### Scenario: Unknown kind is refused

- GIVEN a verified op whose kind is not one of the seven protocol
  `keyspace.*` kinds
- WHEN identikey-keys is asked to apply it
- THEN the replica is unchanged

### Requirement: Admin check is protocol §6.1, Sign cannot author

After outer genesis, identikey-keys SHALL accept administering ops only
when `Op.actor` is `admin: true` on the applied roster. Outer genesis
SHALL be valid iff that actor appears as `admin: true` in the same join
body. Inner genesis (`keyspace.nest`) SHALL require `Op.actor` to be
`admin: true` on the applied **outer** roster, not the nest body's
inner roster. The C2 IdentiKey Sign+Auth public SHALL NOT be accepted
as `Op.actor`. Join SHALL NOT call `authorize_elect` on the member XID.

#### Scenario: Nest is authorized on the outer roster

- GIVEN an outer house keyspace with an applied admin
- WHEN that admin signs `keyspace.nest` whose inner roster lists a
  different actor as `admin: true`
- THEN the nest applies and the inner keyspace id is the nest op's
  `content_hash`

#### Scenario: Sign key as actor is refused

- GIVEN a stored C2 identity
- WHEN IdentiKey's Sign public is used as `Op.actor` on any
  `keyspace.*` op
- THEN the op is refused and the replica is unchanged

### Requirement: Wrap-target selector excludes Sign+Auth

When applying wraps, identikey-keys SHALL treat wrap `recipient` as
the member PUK named by ADR-012: on a `c2_native` + `PrivateKeyBase`
document, the user's X25519 encapsulation half on the stored
`PublicKeys`. It SHALL NOT use protocol §7.2, SHALL NOT select
Schnorr, Sign+Auth, `managed_key_blob`, or a passkey, and SHALL NOT
call that selector "the latest identity key". Members whose document
actually carries Ed25519 or P-256 identity keys MAY use those as PUK
per protocol §5; that is not the C2 constructor this crate ships.
Wrap-list change SHALL be `keyspace.epoch-begin` then
`keyspace.epoch-commit` only. A `keyspace.join` that needs a §6
`RosterEntry` for a C2 row of this store SHALL wait on identikey-protocol
`ikp-2l8`; until then that row is a §7 `Wrap.recipient` only.

#### Scenario: Epoch begin retargets wraps to the new PUK

- GIVEN a member whose PUK rotated after a device revoke
- WHEN an admin commits `keyspace.epoch-begin` then `epoch-commit`
  whose wraps list the new PUK
- THEN the applied wrap-list targets the new PUK and not the old one

#### Scenario: ChangeBody cannot carry wraps

- GIVEN an applied keyspace
- WHEN a `keyspace.change` body includes a wraps field
- THEN the op is refused

### Requirement: Optional Postgres cache is not the home

identikey-keys MAY materialize applied roster, epoch, wraps, and
blacklist in Postgres. Deleting that materialization SHALL NOT prevent
holders who still have `admin: true` keys from continuing the keyspace
from their log replicas. `consent_log` SHALL NOT store keyspace ops.

#### Scenario: Cache delete leaves replicas authoritative

- GIVEN holders of a keyspace and a Postgres materialization
- WHEN the materialization is deleted
- THEN a subsequent apply from a holder replica with `admin: true`
  succeeds

### Requirement: Concurrent epoch-begin is not merged

identikey-keys SHALL NOT merge concurrent `keyspace.epoch-begin` ops
and SHALL NOT apply either until an admin nacks one or a later begin
parents exactly one. Access-node profile join and leave SHALL update
roster/blacklist and SHALL NOT rotate the PTK.

#### Scenario: Two concurrent begins wait

- GIVEN two `keyspace.epoch-begin` ops where neither is an ancestor
  of the other
- WHEN a holder applies the log
- THEN neither begin is applied until an admin nacks one or a later
  begin parents exactly one

#### Scenario: Access-node join does not rotate PTK

- GIVEN an access-node keyspace at a long epoch
- WHEN identikeys join and leave during that epoch
- THEN the roster/blacklist updates and the PTK epoch is unchanged

