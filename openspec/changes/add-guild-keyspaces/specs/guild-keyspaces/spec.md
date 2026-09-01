## ADDED Requirements

### Requirement: A keyspace is a distributed object

A guild (product word) SHALL be a shared keyspace: the composition of the
keys that comprise it. It SHALL NOT be housed at identikey-core, on a
single mesh node, or in Postgres as source of truth. Admin-key holders
SHALL keep it alive by replicating and signing. If no admin key continues
to participate, the keyspace SHALL fade. The member XID SHALL remain
who-I-am. Join and leave SHALL NOT be an Elect rewrite of the member XID.

#### Scenario: Join does not rewrite the member XID

- GIVEN an identikey whose XID document is stored
- WHEN that identikey joins a keyspace
- THEN the stored member XID document bytes are unchanged

#### Scenario: Postgres is not the home

- GIVEN holders of a keyspace and an optional identikey-core materialization
- WHEN the materialization is deleted
- THEN holders who still have admin keys can continue the keyspace from
  their replicas

### Requirement: FOKS methods, identikey root

The key hierarchy SHALL be device key → per-user key (PUK) → per-keyspace
key (PTK). The PTK SHALL be encrypted to each member's latest PUK. Clients
SHALL control key management. The system SHALL NOT run a FOKS server and
SHALL NOT replace XID with `user@host`. A root identikey SHALL still Elect
and rotate its own keys under ADR-001 and ADR-010.

#### Scenario: Device revoke cascades the wrap-list

- GIVEN a member with two device keys wrapping a PUK that wraps a PTK
- WHEN one device is revoked
- THEN the PTK wrap-list no longer includes that device's path, and the
  member XID still Elects

#### Scenario: IdentiKey Sign cannot Elect the member

- GIVEN a stored C2 identity
- WHEN IdentiKey's Sign key is used as signer on that member's XID document
- THEN Elect is denied and the member document is unchanged

### Requirement: Radio join is not membership

Client SSID SHALL be a public radio name. Associating to that SSID SHALL
NOT mint keyspace membership. Membership SHALL require an identikey
ceremony. A radio PSK, if any, SHALL NOT be the keyspace secret.

#### Scenario: Open visitor network

- GIVEN factory client SSID ⚡, open
- WHEN a phone associates
- THEN it is not a keyspace member

#### Scenario: Identikey login is the ceremony

- GIVEN a phone already associated to the client SSID
- WHEN the holder completes identikey login
- THEN that identikey may be wrapped into the relevant keyspace, and the
  association event is not that wrap

### Requirement: Hybrid eviction

A kick SHALL take effect on an ACL/blacklist immediately. Cryptographic
eviction SHALL be PTK rotation on a configurable epoch. Rotation SHALL
rewrap envelopes (not rewrite every blob) and SHALL commit all-or-none as
epoch ops on `identikey-log`. `identikey-log` SHALL surface concurrency
and SHALL NOT merge. Postgres SHALL NOT be the coordinator of the epoch.

#### Scenario: Kick without waiting for rotation

- GIVEN a member on the roster
- WHEN an admin kicks that member
- THEN subsequent request-to-bytes for that member is denied before the
  PTK epoch commits

#### Scenario: Epoch rotation is all-or-none

- GIVEN a wrap-list change that requires PTK rotation
- WHEN epoch-commit is applied
- THEN either every affected wrap in that epoch is committed or none is

#### Scenario: Concurrent epoch ops are not merged by the log

- GIVEN two concurrent `identikey-log` ops at the same HLC
- WHEN a holder reads both
- THEN the log reports them concurrent and does not pick a winner

### Requirement: Protocol says keyspace, product says guild

Op kinds and the protocol spec SHALL use the word `keyspace` (and nested
keyspace). Lightning Mesh UI and Admin SHALL use the word `guild` for the
same object. The system SHALL NOT emit an OIDC claim named `guilds`.

#### Scenario: Op kind is keyspace.join

- GIVEN a join op on `identikey-log`
- WHEN the op is encoded
- THEN its kind is a `keyspace.*` string, not `guild.*`

#### Scenario: No guilds claim on a token

- GIVEN an identikey-oidc ID token or userinfo body
- WHEN a relying party inspects claims
- THEN there is no claim named `guilds`

### Requirement: Nested profiles

A house/buyer keyspace SHALL use a configurable rotation epoch. An
access-node keyspace SHALL be an inner keyspace created after a node is
assigned to an outer keyspace, SHALL use a long epoch, SHALL accept high
churn, and SHALL wrap on identikey login for local service-mesh comms
rather than house secrets. Lightning Admin SHALL expose join/change,
assign-node, and nest, and SHALL NOT expose rename. Apply-to-radio SHALL
remain an explicit radio write.

#### Scenario: Inner keyspace after assign

- GIVEN a node assigned to an outer house keyspace
- WHEN an access-node keyspace is created
- THEN it is nested under that outer keyspace and has its own PTK epoch

#### Scenario: Access-node wrap does not rotate per join

- GIVEN an access-node keyspace with a long epoch
- WHEN identikeys login and leave during the epoch
- THEN the roster/blacklist updates and the PTK does not rotate on each
  join or leave

#### Scenario: No silent dual-write

- GIVEN an admin changing a guild
- WHEN that change is committed on the log
- THEN client SSID is unchanged unless a separate `mjolnir-apply` radio
  write runs
