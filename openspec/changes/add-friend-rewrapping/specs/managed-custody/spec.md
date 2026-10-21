## MODIFIED Requirements

### Requirement: Held user X25519 encapsulation private
<!-- base: 64395f6adc83a2c8dc5316c61befed4fd313c4e6 openspec/specs/managed-custody/spec.md -->

For a C2 identity created by hosted signup after this change, the system
SHALL seal the 32-byte X25519 scalar from `PrivateKeyBase::x25519_private_key()`
whose public is `c2_wrap_recipient` of the stored document. The system
SHALL NOT seal the `PrivateKeyBase` bytes. The seal SHALL be an `IKEK`
version-1 AEAD envelope under the same managed wrap key as `IKMK`, with
no rotation of that key. Associated data SHALL be the bytes
`identikey-encapsulation-key-v1\n`, then the 32-byte XID, then the
32-byte recipient. That tag SHALL NOT be `identikey-managed-key-v1\n`.
The magic is outside the AEAD. The seal SHALL be stored outside
`managed_key_blob`. Each opener SHALL reject the other's magic. The
system SHALL NOT seal the user's Elect private. A C2 row created before
this change SHALL keep a null seal. Unwrap and export of a null,
malformed, swapped-account, or swapped-recipient seal SHALL fail closed
and SHALL NOT report a data key.

Unwrap SHALL implement identikey-keyspace-v1 `x25519-xchacha20poly1305`
for a 32-byte data key, inside the library only. Unwrap has no HTTP
caller. Tests call it. The production open of that data key is the
friend rewrap in the requirement Friend rewrap of a held data key.
That rewrap returns a new wrap and SHALL NOT return the data key.
The library function SHALL take the A3 assertion or A4 signature. In one
transaction it SHALL verify that proof against the stored begin row,
recheck expiry, purpose `unwrap`, and unused, recheck the credential row
and the custody row under the same `FOR UPDATE` locks that `revoke_device`
and climb take, mark the row used, open the seal, unwrap, and write the
audit. There SHALL be no finished-but-unconsumed consent row. The inputs
SHALL NOT include the user `PrivateKeyBase`. The data key SHALL NOT be
written to an HTTP response. Unwrap SHALL refuse, before decrypt, a wrap
whose SHA-256 differs from the digest stored at begin. Unwrap SHALL reject
a small-order ephemeral public and an all-zero DH output before it returns
a data key. The held X25519 SHALL NOT be an `Op.actor`, an admin, or a
signer.

Opening the seal is policy enforced by this service. The operator holds
the managed wrap key, so consent is not a cryptographic absence of the
scalar. Hosted signup drops the Elect private, so the live path is A3.
A4 remains a signature by the user's Elect key on the current document
over this attempt's transcript. The managed operational key SHALL NOT
count as A4.

`POST /account/encapsulation/begin` SHALL require an account session only
to name the XID. That session SHALL NOT open the seal. Begin SHALL accept
purpose `export`, `unwrap`, or `rewrap` and SHALL reject any other purpose
before inserting a row. For `unwrap` and `rewrap`, begin SHALL also require
the wrap bytes and SHALL store SHA-256 of those exact bytes. For `rewrap`,
begin SHALL also store the friend XID and the 32-byte recipient taken from
that friend's current document, as the Friend rewrap requirement states.
Begin SHALL store a fresh WebAuthn challenge and a 5-minute expiry. The
transcript SHALL be, in order: the bytes
`identikey-encapsulation-consent-v1\n`; a u8 length and the ASCII purpose
(`export`, `unwrap`, or `rewrap`); the 32-byte XID; the attempt id as 16
raw UUID bytes; a u16 big-endian length and the WebAuthn challenge bytes;
`iat` as u64 big-endian; `exp` as u64 big-endian; and, for `unwrap` and
`rewrap`, the 32-byte wrap digest. Export SHALL omit that digest. For
`rewrap` only, the transcript SHALL then append the 32-byte recipient.
That domain tag SHALL NOT be `identikey-managed-consent-v1\n`. The SHA-256
of the fixed export transcript (purpose `export`, XID thirty-two `0x11`
bytes, attempt id sixteen `0x22` bytes, challenge thirty-two `0x33` bytes,
`iat` 1700000000, `exp` 1700000300) SHALL be
`7d93d9c193c5a60338be4d9b646c1429bfc62718da3e67c2954673627a6d2061`. The
SHA-256 of that same transcript with purpose `unwrap` and wrap digest
thirty-two `0x44` bytes SHALL be
`b18286bad604fc6da5425928d1f0892201b137bdcc9633e90b00bb93af0a558f`. The
SHA-256 of that same transcript with purpose `rewrap`, that wrap digest,
and recipient thirty-two `0x55` bytes SHALL be
`c5266850c16f4ed35cbddb4a37a4bbac6faf6a421690dc7c110c3c876302caa7`.

Export finish is `POST /account/encapsulation/export`. In one transaction
it SHALL verify the A3 assertion or A4 signature against the stored row,
recheck expiry, purpose `export`, and unused, recheck the credential row
and the custody row under the same `FOR UPDATE` locks that `revoke_device`
and climb take, mark the row used, open the seal, and write the audit.
It SHALL return the 32-byte scalar as unpadded base64url, SHALL leave the
server copy stored until a climb that follows a logged export, and SHALL
NOT render HTML. A second finish SHALL fail before decrypt. A proof whose
transcript uses the managed-challenge domain or a different purpose SHALL
fail before decrypt. Begin, export, and rewrap SHALL send
`Cache-Control: no-store`. A registered SPA origin SHALL NOT receive
`Access-Control-Allow-Origin` on begin, export, or rewrap. There SHALL be
no hosted unwrap route. There is no hosted export page in this change. A
same-origin test calls export. A later change adds the account-page button.

A successful export or unwrap SHALL, in the same transaction as the key
use, write a consent-log entry carrying the A3 or A4 proof with `action`
`encapsulation_export` or `encapsulation_unwrap`, and a custody event.
An `encapsulation_unwrap` entry SHALL also record the wrap digest.

#### Scenario: A restarted process unwraps a data key

- GIVEN a new C2 account whose user `PrivateKeyBase` has been dropped, a
  data key wrapped with `x25519-xchacha20poly1305` to that account's
  published X25519, and a begin row whose purpose is `unwrap` and whose
  digest is that wrap
- WHEN the library unwrap is given the A3 assertion or A4 signature for
  that row
- THEN one transaction verifies the proof, marks the row used, and returns
  the data key to that library caller
- AND the unwrap call was not given the user `PrivateKeyBase`
- AND no HTTP response contains the data key
- AND no consent row is left finished and unused

#### Scenario: Consent for one wrap does not open another

- GIVEN an `unwrap` begin whose stored digest is wrap W
- WHEN the library is asked to open wrap W′ with that attempt's proof
- THEN it fails before the seal is decrypted

#### Scenario: Revocation wins the export race

- GIVEN an encapsulation begin for `export` and a concurrent revoke of
  that passkey
- WHEN revoke commits first
- THEN export fails and the seal is not decrypted

#### Scenario: Account cookie cannot unwrap or export

- GIVEN a valid account session and no fresh encapsulation consent
- WHEN unwrap or `POST /account/encapsulation/export` is called
- THEN both are refused
- AND the seal is not decrypted

#### Scenario: The owner can export the scalar

- GIVEN a new C2 account and a consumed encapsulation consent whose
  purpose is `export`
- WHEN `POST /account/encapsulation/export` finishes
- THEN the body is the unpadded base64url of the 32-byte X25519 scalar
- AND the stored seal is still present
- AND a consent-log entry `encapsulation_export` and a custody event exist

#### Scenario: A managed-challenge consent cannot export

- GIVEN a completed consent whose transcript domain is
  `identikey-managed-consent-v1\n`
- WHEN that proof is presented to `POST /account/encapsulation/export`
- THEN export is refused before the seal is decrypted

#### Scenario: Unwrap writes an audit and returns the key only in-process

- GIVEN a consumed encapsulation consent whose purpose is `unwrap`
- WHEN the library unwraps a data key
- THEN the caller receives the data key
- AND a consent-log entry `encapsulation_unwrap` and a custody event exist
- AND no HTTP response contains the data key

#### Scenario: An older C2 row cannot unwrap

- GIVEN a C2 row whose encapsulation seal is null
- WHEN unwrap is called with valid `unwrap` consent
- THEN it fails closed

#### Scenario: The pinned export transcript digests match

- GIVEN the fixed export transcript in this requirement
- WHEN SHA-256 is taken
- THEN the digest is
  `7d93d9c193c5a60338be4d9b646c1429bfc62718da3e67c2954673627a6d2061`

#### Scenario: A registered SPA origin cannot read export

- GIVEN a registered SPA origin
- WHEN it requests `POST /account/encapsulation/begin`,
  `POST /account/encapsulation/export`, or
  `POST /account/encapsulation/rewrap`
- THEN the response has no `Access-Control-Allow-Origin`

#### Scenario: A small-order ephemeral is not a successful unwrap

- GIVEN a wrap whose ephemeral public is a small-order Montgomery
  u-coordinate, or whose DH output is all zeros
- WHEN unwrap is called with valid `unwrap` consent
- THEN it fails closed and no data key is returned

## ADDED Requirements

### Requirement: Friend rewrap of a held data key

The system SHALL rewrap one 32-byte data key from the owner's sealed
X25519 to one friend's published X25519. The friend SHALL be named by
XID. Begin SHALL read `c2_wrap_recipient` from that friend's stored
document and SHALL NOT accept a recipient supplied by the client. Begin
SHALL reject, before insert, a friend XID equal to the owner, a friend
with no stored document, a friend with no `c2_wrap_recipient`, and a
small-order recipient.

`POST /account/encapsulation/rewrap` SHALL, in one transaction, verify
the A3 assertion or A4 signature against the stored row, recheck expiry,
purpose `rewrap`, and unused, recheck the credential row and the owner's
custody row under the same `FOR UPDATE` locks that `revoke_device` and
climb take, reload the friend's document, and mark the row used only
when the rewrap proceeds. If the friend's current `c2_wrap_recipient`
is missing or differs from the recipient stored at begin, finish SHALL
fail before the seal is decrypted and SHALL leave the row unused. A wrap
whose SHA-256 differs from the stored digest SHALL fail before decrypt.
The call SHALL NOT receive the user `PrivateKeyBase`. The seal SHALL
remain. The data key SHALL be zeroized before the function returns. The
HTTP body SHALL be the new `x25519-xchacha20poly1305` wrap as unpadded
base64url, `text/plain`, and SHALL NOT be the data key or the X25519
scalar. The body SHALL NOT be HTML.

Rewrap SHALL NOT write a keyspace op, a roster entry, or an epoch. A
wrap of a house PTK is still a §7 wrap: rewrap consent on those bytes
shares that data key with the named friend.

A successful rewrap SHALL, in the same transaction, write a consent-log
entry with action `encapsulation_rewrap` and result `signed`, audience
the friend's base58btc XID, purpose the lowercase hex of the source wrap
digest, and a custody event. A second finish SHALL fail before decrypt.
A cookie with no A3 assertion and no A4 signature SHALL be refused
before decrypt. A null, malformed, or swapped seal SHALL fail closed and
SHALL NOT return a wrap.

#### Scenario: A restarted process returns a friend wrap

- GIVEN a new C2 owner whose `PrivateKeyBase` has been dropped, a friend
  document with a published X25519, a data key wrapped to the owner, and
  a `rewrap` begin bound to that wrap and that friend
- WHEN `POST /account/encapsulation/rewrap` is given the A3 assertion or
  A4 signature for that row
- THEN the body is a wrap of that same data key to the friend's X25519
- AND the call was not given the owner's `PrivateKeyBase`
- AND the body is not the data key and not the scalar
- AND the owner's seal is still present
- AND a consent-log entry `encapsulation_rewrap` and a custody event exist

#### Scenario: Consent for one wrap does not rewrap another

- GIVEN a `rewrap` begin whose stored digest is wrap W
- WHEN finish is asked to rewrap wrap W′
- THEN it fails before the seal is decrypted

#### Scenario: A rotated friend key fails before open

- GIVEN a `rewrap` begin that stored the friend's then-current recipient
- WHEN that friend's document now publishes a different X25519
- THEN finish fails before the seal is decrypted
- AND the attempt is still unused

#### Scenario: A small-order friend is rejected at begin

- GIVEN a friend whose published X25519 is a small-order Montgomery
  u-coordinate
- WHEN begin is asked to rewrap to that friend
- THEN no attempt row is inserted

#### Scenario: An account cookie cannot rewrap

- GIVEN a valid account session and no fresh `rewrap` consent
- WHEN `POST /account/encapsulation/rewrap` is called with only that session
- THEN it is refused
- AND the seal is not decrypted

#### Scenario: An older C2 row cannot rewrap

- GIVEN an owner whose encapsulation seal is null
- WHEN rewrap is called with valid `rewrap` consent
- THEN it fails closed and no wrap is returned

#### Scenario: The pinned rewrap transcript digest matches

- GIVEN the fixed rewrap transcript in the held-key requirement
- WHEN SHA-256 is taken
- THEN the digest is
  `c5266850c16f4ed35cbddb4a37a4bbac6faf6a421690dc7c110c3c876302caa7`
