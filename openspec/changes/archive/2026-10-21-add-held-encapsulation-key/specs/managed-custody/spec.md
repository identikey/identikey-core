## MODIFIED Requirements

### Requirement: Durable managed-custody store
<!-- base: c90ab97864d02f9dda90b78b3c4b6a8417fbe961 openspec/specs/managed-custody/spec.md -->

The system SHALL persist accounts, passkey credentials, custody records
(including the current XID document and, when a C2 row was created with a
held user X25519 key, the sealed encapsulation private), consent-log
entries, and custody events in Postgres via sqlx.

#### Scenario: A new C2 identity survives a new connection

- GIVEN a C2-native XID document and a managed-key blob
- WHEN `KeysStore` creates the managed identity and a new store is opened
  on the same database
- THEN `get_custody` returns the same XID, rung `c2`, and a document that
  `is_c2`

#### Scenario: The encapsulation seal survives a new connection

- GIVEN a C2-native XID document and a sealed user X25519 private whose
  public is that document's wrap recipient
- WHEN `KeysStore` creates the managed identity and a new store is opened
  on the same database
- THEN the sealed encapsulation private is still present
- AND those bytes are not the `managed_key_blob`

### Requirement: Elect-gated document updates
<!-- base: c90ab97864d02f9dda90b78b3c4b6a8417fbe961 openspec/specs/managed-custody/spec.md -->

The system SHALL apply a key-graph document update only when
`authorize_elect` succeeds against the document currently stored for that
XID. A denied update SHALL leave the stored document and the encapsulation
seal unchanged. When the update changes `c2_wrap_recipient`, the same write
SHALL set the encapsulation seal to NULL and SHALL NOT install a replacement
seal. A later open against the new public SHALL fail closed.

#### Scenario: IdentiKey's Sign key cannot persist a rotation

- GIVEN a stored C2 identity
- WHEN `apply_document_update` is called with IdentiKey's Sign key as signer
- THEN the call fails with Elect denied and the stored document bytes are
  identical to before the call

#### Scenario: The user's Elect key can persist a rotation

- GIVEN a stored C2 identity
- WHEN `apply_document_update` is called with the user's Elect key as signer
  and a new document for the same XID
- THEN the stored document bytes change to the new document

#### Scenario: Rotating the wrap recipient nulls the seal

- GIVEN a stored C2 identity with an encapsulation seal
- WHEN `apply_document_update` changes `c2_wrap_recipient`
- THEN the stored seal is NULL
- AND unwrap to the new public fails closed

### Requirement: C2 to C3 exit ceremony
<!-- base: c90ab97864d02f9dda90b78b3c4b6a8417fbe961 openspec/specs/managed-custody/spec.md -->

The system SHALL provide `migrate_c2_to_c3` as the only C2→C3 write. It
SHALL keep the same XID, SHALL destroy `managed_key_blob` and the sealed
user X25519 encapsulation private (and SHALL NOT export either), SHALL
require a signature over the new document by a key that holds Elect on the
stored C2 document, SHALL persist a document in which no public key that
was Sign+Auth on the stored C2 document retains Sign or management
privileges, SHALL require that some key we do not hold can Sign and some
key we do not hold can Elect (same or different keys), and SHALL set
`resolution_methods` to N≥2 distinct hosts with at least one eTLD+1
outside `{identikey.me, identikey.io}`. Hostless URIs SHALL NOT count as
"not us." The write SHALL be one transaction (one UPDATE of document +
NULL blob + NULL encapsulation seal + `rung = c3`) plus a consent-log
entry (A3/A4 proof, `action = c2_to_c3`) and a custody event. Export is
the exit path for the encapsulation key and SHALL happen before climb.
When the encapsulation seal is present and this XID has no consent-log
entry with `action = encapsulation_export`, climb SHALL fail and the
row SHALL stay unchanged.

#### Scenario: Climb leaves the same XID and no server Sign material

- GIVEN a stored C2 identity with a managed-key blob
- WHEN the user submits a C3 document signed by their Elect private key,
  with a second resolver whose eTLD+1 is not ours
- THEN the stored XID is unchanged, `rung` is `c3`, `managed_key_blob` is
  NULL, and none of the previous Sign+Auth publics retain Sign

#### Scenario: Climb with only our resolvers is refused

- GIVEN a stored C2 identity
- WHEN the submitted document's resolver hosts are only under
  `identikey.me` or `identikey.io`
- THEN the ceremony fails and the row is unchanged (still C2, blob present)

#### Scenario: Our Sign key cannot complete the climb

- GIVEN a stored C2 identity
- WHEN the ceremony is invoked with IdentiKey's Sign key as signer
- THEN the ceremony fails and the row is unchanged

#### Scenario: General document write cannot drop our Sign key

- GIVEN a stored C2 identity
- WHEN `apply_document_update` is called with a document that is not `is_c2`
- THEN the call fails and the blob and rung are unchanged

#### Scenario: C1 cannot skip to C3 through this ceremony

- GIVEN a stored C1 identity
- WHEN `migrate_c2_to_c3` is invoked
- THEN the ceremony fails and the row is unchanged

#### Scenario: XID change is refused

- GIVEN a stored C2 identity
- WHEN the submitted document's XID differs
- THEN the ceremony fails and the row is unchanged

#### Scenario: Climb destroys the encapsulation private

- GIVEN a stored C2 identity whose user X25519 private is sealed
- AND a consent-log entry `encapsulation_export` for that XID
- WHEN the user completes the climb
- THEN the encapsulation seal is NULL, `managed_key_blob` is NULL, and the
  ceremony does not return the X25519 scalar

#### Scenario: Climb without a prior export is refused

- GIVEN a stored C2 identity whose encapsulation seal is present
- AND no `encapsulation_export` consent-log entry for that XID
- WHEN `migrate_c2_to_c3` is invoked
- THEN the ceremony fails and the seal, blob, and rung are unchanged

### Requirement: Managed operational Sign+Auth is Ed25519
<!-- base: c90ab97864d02f9dda90b78b3c4b6a8417fbe961 openspec/specs/managed-custody/spec.md -->

New C2 identities SHALL place an identikey-auth Ed25519 public key on
the XID document with Sign and Auth, and SHALL store that private in
`managed_key_blob` in a form the identikey-auth software signer can
load. The operational key SHALL NOT be BIP-340 secp256k1 Schnorr and
SHALL NOT be P-256. The user's Elect key and X25519 wrap-target SHALL
remain distinct from this operational key. `managed_key_blob` SHALL
NOT be a wrap-target. The operational companion X25519 private SHALL
be discarded at generation and SHALL NOT be persisted. The user's
X25519 encapsulation private SHALL NOT be written into
`managed_key_blob`.

#### Scenario: New signup signs identikey-auth Challenges

- GIVEN a new C2 identity created by hosted signup
- WHEN the operational public is used as an identikey-auth v1 signer
- THEN it verifies as Ed25519
- AND it holds Sign+Auth on the stored document
- AND it does not hold Elect

#### Scenario: Schnorr operational key is not minted

- GIVEN hosted signup
- WHEN `create_managed` persists `managed_key_blob`
- THEN the blob is not a bc-components Schnorr `PrivateKeyBase`

#### Scenario: Operational companion X25519 is not the wrap recipient

- GIVEN a new C2 identity created by hosted signup
- WHEN the document's wrap recipient is compared with the operational
  key's encapsulation public
- THEN they differ
- AND `managed_key_blob` still opens as the Ed25519 operational seed

## ADDED Requirements

### Requirement: Held user X25519 encapsulation private

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
for a 32-byte data key, inside the library only. This change has no live
unwrap caller. Tests call it. The first production caller is the later
change `add-recrypt-proxy-vm`, when the owner mints a recryption key.
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
purpose `export` or `unwrap` and SHALL reject any other purpose before
inserting a row. For `unwrap`, begin SHALL also require the wrap bytes and
SHALL store SHA-256 of those exact bytes. Begin SHALL store a fresh
WebAuthn challenge and a 5-minute expiry. The transcript SHALL be, in
order: the bytes `identikey-encapsulation-consent-v1\n`; a u8 length and
the ASCII purpose (`export` or `unwrap`); the 32-byte XID; the attempt id
as 16 raw UUID bytes; a u16 big-endian length and the WebAuthn challenge
bytes; `iat` as u64 big-endian; `exp` as u64 big-endian; and, only for
`unwrap`, the 32-byte wrap digest. Export SHALL omit that digest. That
domain tag SHALL NOT be `identikey-managed-consent-v1\n`. The SHA-256 of
the fixed export transcript (purpose `export`, XID thirty-two `0x11`
bytes, attempt id sixteen `0x22` bytes, challenge thirty-two `0x33` bytes,
`iat` 1700000000, `exp` 1700000300) SHALL be
`7d93d9c193c5a60338be4d9b646c1429bfc62718da3e67c2954673627a6d2061`. The
SHA-256 of that same transcript with purpose `unwrap` and wrap digest
thirty-two `0x44` bytes SHALL be
`b18286bad604fc6da5425928d1f0892201b137bdcc9633e90b00bb93af0a558f`.

Export finish is `POST /account/encapsulation/export`. In one transaction
it SHALL verify the A3 assertion or A4 signature against the stored row,
recheck expiry, purpose `export`, and unused, recheck the credential row
and the custody row under the same `FOR UPDATE` locks that `revoke_device`
and climb take, mark the row used, open the seal, and write the audit.
It SHALL return the 32-byte scalar as unpadded base64url, SHALL leave the
server copy stored until a climb that follows a logged export, and SHALL
NOT render HTML. A second finish SHALL fail before decrypt. A proof whose
transcript uses the managed-challenge domain or a different purpose SHALL
fail before decrypt. Begin and export SHALL send `Cache-Control: no-store`.
A registered SPA origin SHALL NOT receive `Access-Control-Allow-Origin` on
either route. There SHALL be no hosted unwrap route. There is no hosted
export page in this change. A same-origin test calls export. A later
change adds the account-page button.

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
- WHEN it requests `POST /account/encapsulation/begin` or
  `POST /account/encapsulation/export`
- THEN the response has no `Access-Control-Allow-Origin`

#### Scenario: A small-order ephemeral is not a successful unwrap

- GIVEN a wrap whose ephemeral public is a small-order Montgomery
  u-coordinate, or whose DH output is all zeros
- WHEN unwrap is called with valid `unwrap` consent
- THEN it fails closed and no data key is returned
