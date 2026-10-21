## MODIFIED Requirements

### Requirement: Wrap-target is the user's X25519 encapsulation key
<!-- base: 5f10cd605d5388ce6ffec58c2d902014fc933855 openspec/specs/guild-keyspaces/spec.md -->

On a C2 document built by `c2_native` from `PrivateKeyBase::new()`, the
PTK SHALL be wrapped to the user's X25519 encapsulation public (the
encapsulation half of that `PublicKeys`), using protocol §7
`x25519-xchacha20poly1305`. identikey-keys SHALL NOT treat the Schnorr
signing half as a wrap-target, SHALL NOT apply protocol §7.2
(Ed25519→X25519) to Schnorr, SHALL NOT wrap to IdentiKey Sign+Auth,
`managed_key_blob`, or a `credentials` passkey, and SHALL NOT list a
C1 row as a member. A row whose user X25519 private is neither sealed
nor held by the user MAY be named as a protocol §7 `Wrap.recipient`;
unwrap SHALL fail (inert on purpose; not a reason to wrap to
`managed_key_blob`). A C2 row with a held encapsulation seal SHALL
unwrap that PTK under the managed-custody consent for
`encapsulation_unwrap`. That open is custodial: IdentiKey, holding the
managed wrap key and a valid consent, can read a data key wrapped to
that member, including a house keyspace PTK. The held X25519 SHALL NOT
be an `Op.actor`, an admin, or a signer. A protocol §6 `RosterEntry`
for that row SHALL name `PublicKey.alg` `x25519` and the 32-byte
u-coordinate (identikey-protocol `ikp-2l8`). That key is a wrap-target.
`admin: true` still requires an Ed25519 `actor`. PUK rotation of that
encapsulation key SHALL be an Elect-gated XID document write, then
`keyspace.epoch-begin` / `epoch-commit`.

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

#### Scenario: A C2 row with no seal stays inert

- GIVEN a C2 row whose user `PrivateKeyBase` was dropped at signup and
  whose encapsulation seal is null
- WHEN a wrap lists that row's X25519 encapsulation public as recipient
- THEN the wrap is stored as protocol §7 `Wrap.recipient` and unwrap
  by that member fails

#### Scenario: A held C2 seal can open a house PTK

- GIVEN a C2 row with a held encapsulation seal and a valid
  `encapsulation_unwrap` consent
- WHEN a house PTK is wrapped to that row's X25519
- THEN the library unwrap returns the PTK
- AND IdentiKey can perform that open because it holds the managed wrap
  key
- AND the X25519 key was not `Op.actor`

#### Scenario: C2 roster entry names native X25519

- GIVEN a stored C2 document whose user PUK is native X25519
- WHEN identikey-keys encodes a protocol §6 `RosterEntry` for that member
- THEN `PublicKey.alg` is `x25519` and `key` is the 32-byte u-coordinate
- AND apply accepts the entry
- AND that X25519 key is not `Op.actor`

#### Scenario: Unknown roster alg is refused

- WHEN a roster `PublicKey.alg` is other than `ed25519`, `x25519`, or `p256`
- THEN encode and apply refuse the body

#### Scenario: Schnorr cannot author a keyspace op

- GIVEN a C2 member whose only user signing key is Schnorr and who
  has no Ed25519 `actor`
- WHEN that Schnorr public is used as `Op.actor`
- THEN the op is refused
