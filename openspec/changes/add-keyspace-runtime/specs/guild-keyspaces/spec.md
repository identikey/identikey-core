## ADDED Requirements

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
