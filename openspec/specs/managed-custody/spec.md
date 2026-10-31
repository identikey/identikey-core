# managed-custody

Living truth for the user store and managed custody in `identikey-keys`.
Folded from `add-keys-store`, `add-c2-c3-exit`,
`add-resolver-relocation` (2026-08-16), `add-device-records`
(2026-08-17), `add-managed-challenge-responder` (2026-09-24),
`add-held-encapsulation-key` (2026-10-21),
`add-friend-rewrapping` (2026-10-21), and
`add-account-key-model` (2026-10-31).

### Requirement: Durable managed-custody store

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

### Requirement: Server boot migrates

`identikey-server` SHALL require `DATABASE_URL`, SHALL run the
`identikey-keys` migrator before serving, and SHALL fail closed if the
URL is missing or not a usable Postgres target. `/health` SHALL remain a
liveness signal and SHALL NOT report pool or key state.

#### Scenario: Missing DATABASE_URL fails at boot

- GIVEN `DATABASE_URL` is unset
- WHEN the server resolves its database configuration
- THEN boot fails with an error that names `DATABASE_URL`

### Requirement: C2 to C3 exit ceremony

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

### Requirement: Post-climb resolver relocation

On a stored C3 or C4 row, `apply_document_update` SHALL persist a new
document for the same XID when `authorize_elect` succeeds and the new
document's `resolution_methods` satisfy the same host rules as the
C2→C3 ceremony (N≥2 distinct HTTP(S) hosts, at least one eTLD+1
outside `{identikey.me, identikey.io}`, hostless URIs do not count as
"not us", localhost and RFC1918 refused). The write SHALL NOT change
`rung` or `managed_key_blob`. A refused update SHALL leave the stored
document, rung, and blob unchanged. A C2 row SHALL still refuse a
document that is not `is_c2`.

#### Scenario: C3 user can replace a resolver

- GIVEN a stored C3 identity with our host and `resolver.example`
- WHEN `apply_document_update` is called with the user's Elect key and
  a document that replaces `resolver.example` with `backup.example`
  and still includes one of our hosts
- THEN the stored document bytes change, `rung` is still `c3`, and
  `managed_key_blob` is still NULL

#### Scenario: Dropping the last not-us host is refused

- GIVEN a stored C3 identity whose only not-us host is `resolver.example`
- WHEN `apply_document_update` is called with a document whose
  resolver hosts are only under `identikey.me` or `identikey.io`
- THEN the call fails and the stored document bytes are unchanged

#### Scenario: C2 still cannot leave is_c2 this way

- GIVEN a stored C2 identity
- WHEN `apply_document_update` is called with a document that is not
  `is_c2`
- THEN the call fails and the blob and rung are unchanged

### Requirement: Devices are listable, revocable credentials

The system SHALL treat a `credentials` row as the device record. It
SHALL list non-revoked credentials for a XID and SHALL revoke a
credential by setting `revoked_at`. A revoked credential SHALL NOT
appear in a subsequent list. The list type SHALL NOT include
`device_trust`, `is_master`, or a master/temporary enum.

#### Scenario: Register then list

- GIVEN a stored account
- WHEN a passkey credential is inserted and `list_devices` is called
- THEN the list contains that credential id and not a trust claim

#### Scenario: Revoke hides the device

- GIVEN a listed credential C
- WHEN `revoke_device` is called for C and `list_devices` is called
  again
- THEN C is absent from the list

### Requirement: Managed operational Sign+Auth is Ed25519

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

### Requirement: Consent-gated canonical challenge responder

C2 SHALL answer an identikey-auth Challenge only after a fresh A3
WebAuthn assertion or user-held A4 proof committed to a
domain-separated digest of the exact canonical Challenge bytes and
request id. A long-lived account session SHALL NOT authorize signing.
The endpoint SHALL accept only identikey-auth v1 Challenge bytes
whose round-trip `to_bytes` equals the input (extra map keys
rejected). Algorithm SHALL be validated on the stored operational
key, not as a Challenge field. Admission SHALL enforce `v=1`, nonce
length, body cap, a canonical base58btc edge `aud`, TTL/skew, current C2 Sign+Auth, and
a post-consent expiry recheck before decrypt. The ceremony SHALL be
begin/consent/finish/retrieve with immutable account, challenge,
request id, PKCE verifier commitment, session public key, operation,
resource, and channel. A holder-public retrieval
proof SHALL fail closed. A3 SHALL bind by a server row that stores the
library WebAuthn challenge with that attempt. A4 SHALL be a signature
by an Elect key on the account's current XID document, not the managed
operational key, over the server-returned consent Challenge. The
transcript encoding, domain tag, and the fixed digest vector in the
design SHALL be the bytes both sides hash. Finish SHALL rebuild that
Challenge from the stored attempt and reject any other bytes.
Immediately before decrypt, A3 SHALL recheck the credential row and
A4 SHALL recheck Elect on the current document. A4 SHALL NOT require a
passkey row. An unrelated key, a caller-supplied XID, or the
managed key SHALL NOT count as A4. Consent SHALL expire at the earlier
of the edge Challenge `exp` and five minutes after consent `iat`.
The attempt row SHALL bind request id, digest, account, client
commitment, and terminal state. A crash after the key-use claim and
before a durable result SHALL be terminal `indeterminate`: retrieve
SHALL NOT sign again. A crash before the claim SHALL allow one later
claim. The Response SHALL be stored in the same commit as the
completion audit and SHALL NOT be released before that commit.
Immediately before decrypt, finish SHALL recheck the custody row and
the credential row under one lock pair that `revoke_device` also takes.
Revocation or exit that wins that recheck SHALL prevent key use. A
recheck that wins SHALL allow the signature to complete, and that
completed Response SHALL stay retrievable. `managed_key_blob` SHALL
be a v1 AEAD envelope over an Ed25519 seed bound to account XID and
operational public. Legacy, malformed, swapped-account, and
wrong-key envelopes SHALL fail closed. This delivery is C2 only.

The Challenge this ceremony answers SHALL name the edge in `aud` as base58btc of the 32-byte edge XID. Begin SHALL admit that audience only when it decodes to 32 bytes and re-encodes to the same string. A 64-hex audience SHALL be refused before the row is stored. The A4 consent Challenge SHALL keep `aud` as the account XID in 64 lowercase hex. That consent Challenge SHALL NOT be rewritten to base58.

The same attempt SHALL also carry a session bind. Begin SHALL require a session public key, an operation, a resource, and a channel, and SHALL reject a request that omits any of them before an attempt row is stored. The session public key SHALL be an Ed25519 ClassicalPublicKey, a declared subset of the edge's Ed25519 or P-256 keys: map `{alg, key}` with `alg` text `ed25519` and `key` the 32 raw bytes. Begin SHALL refuse P-256. Operation and resource SHALL be CanonicalTuple arrays of non-empty printable ASCII components (`0x21` through `0x7e`). Begin SHALL NOT split a string on `:`. `["vms","stop"]` and `["vms:stop"]` SHALL be different tuples. Begin SHALL refuse an empty tuple, a component outside that charset, more than 8 components, or a component longer than 64 bytes, before the row is stored. The channel SHALL be exactly 32 bytes. Any other length SHALL be refused before the row is stored.

The consent transcript SHALL keep the domain tag `identikey-managed-consent-v1\n` and the existing six fields, then append the ClassicalPublicKey map bytes, the operation as a uint32 big-endian component count followed by each component as a uint32 big-endian length and bytes, the resource the same way, and the channel as exactly 32 raw bytes with no length prefix. The pinned digest for the design's fixed inputs SHALL be `7efc1d284ac45ec66c928a750c701ed266ce28e3dab0e306588928c79dce8c03`. An attempt stored before these columns exist SHALL fail closed at finish. Finish SHALL NOT complete it by hashing empty bind fields.

No hosted page renders this ceremony. Begin SHALL return the stored session key, operation, resource, and channel beside `consent_challenge`. An A3 caller renders those returned bytes. An A4 wallet SHALL recompute the digest from them and SHALL refuse a mismatch before it signs. A malicious caller can misrender those bytes. The hosted OP SHALL sign the stored channel bytes and SHALL NOT check them against a Mjolnir connection. The OP SHALL NOT apply Mjolnir authorization policy and SHALL NOT consume the edge nonce. The edge's channel check and its policy check are the backstop.

The bind signing bytes SHALL be a port of Mjolnir `696fb00` `bind_signing_bytes`, pinned by the joint vector. identikey-core SHALL NOT take a dependency on `mjolnir_biscuit` for this change. The text `identikey-mjolnir/v1` SHALL be the encoding version. The later shared home of that encoder SHALL be `identikey-auth`. The bytes are: a canonical CBOR array of seven items, text `identikey-mjolnir/v1`, text `bind`, the stored Challenge as a byte string, the ClassicalPublicKey map, the operation CanonicalTuple, the resource CanonicalTuple, and the channel as a 32-byte byte string. The joint vector in the design SHALL be those bytes. The identikey-auth signing payload SHALL be a different array with its own domain. A unit assertion SHALL show that payload is not the bind bytes. One key-use claim SHALL sign both with the same operational key. Finish SHALL NOT take bind fields from the client. An A4 signature over a consent Challenge whose digest used a different tuple SHALL be rejected before decrypt. Retrieve, when completed and the PKCE verifier matches, SHALL return the Response and the bind together, or neither. The completed JSON SHALL be `state` `completed`, `response` as unpadded base64url of the identikey-auth Response, `bind` as unpadded base64url of the 64 raw Ed25519 signature bytes (the client wraps them as `{ "alg": "ed25519", "sig" }` for the edge), `session_public_key` as `{ "alg": "ed25519", "key": <unpadded base64url of 32 bytes> }`, `operation` and `resource` as the stored component arrays, and `channel` as unpadded base64url of the 32 bytes. The echoed fields SHALL come from the stored row. A missing or wrong verifier SHALL return neither signature. A failed bind signature SHALL NOT release the Response. The completion audit commit SHALL store both signatures, the operation, the resource, and `ClassicalPublicKey::fingerprint`.

#### Scenario: Fresh consent signs the exact Challenge

- GIVEN a C2 row with an Ed25519 operational key and a fresh A3 proof
  bound to Challenge `C`, request `R`, session key `S`, operation
  `["vms","stop"]`, resource `["vm","A"]`, and a 32-byte channel `H`
- WHEN the initiating client retrieves the result
- THEN the body is an identikey-auth Response that verifies for `C`
- AND the Response public key is the stored Sign+Auth key
- AND the same body carries the bind over those stored fields

#### Scenario: Session cookie alone cannot sign

- GIVEN a valid 24-hour account session and no fresh A3/A4 for this
  Challenge
- WHEN a sign request is made
- THEN it is rejected
- AND the blob is not decrypted

#### Scenario: Noncanonical or replayed Challenge is rejected before key access

- GIVEN a C2 row
- WHEN the body is not a canonical identikey-auth Challenge, or a
  Challenge that already completed, or an expired Challenge
- THEN the call fails before `managed_key_blob` is decrypted

#### Scenario: Response is not stealable by a second client

- GIVEN a completed sign for request `R` bound to client verifier `V`
- WHEN a different client presents `R` without `V`
- THEN neither the Response nor the bind is released

#### Scenario: Extra Challenge map keys are rejected

- GIVEN canonical Challenge bytes plus an extra canonical map field
- WHEN begin or finish is invoked
- THEN the call fails before key access

#### Scenario: Same Challenge two request ids

- GIVEN Challenge digest `D` already begun as request `R1`
- WHEN begin is called for `D` as `R2`
- THEN it is rejected

#### Scenario: Exit wins the race

- GIVEN an in-flight finish and a concurrent `migrate_c2_to_c3`
- WHEN exit commits first
- THEN finish fails and no Response is produced

#### Scenario: Legacy Schnorr blob is not a seed

- GIVEN a pre-switch Schnorr `managed_key_blob`
- WHEN finish is invoked
- THEN it fails closed
- AND the bytes are not passed to `from_ed25519_seed`

#### Scenario: Crash before the claim

- GIVEN consent committed as `authorized` and no claim
- WHEN the process crashes and finish is retried
- THEN one claim may sign
- AND the audit that survives is that single completion or a definite failure

#### Scenario: Crash after the claim

- GIVEN the claim committed and no result transaction committed
- WHEN the process restarts and retrieve or finish runs
- THEN the state is `indeterminate`
- AND no second signature is produced

#### Scenario: Unrelated A4 key

- GIVEN a valid user-held key that is not Elect on this account's document
- WHEN it signs the consent Challenge
- THEN finish rejects it before decrypt

#### Scenario: Managed key is not A4

- GIVEN the managed operational key signs the consent Challenge
- WHEN finish checks the signer
- THEN it rejects the consent

#### Scenario: Expired consent, live edge Challenge

- GIVEN an edge Challenge that is still unexpired and a consent older than five minutes
- WHEN finish runs
- THEN it rejects the consent before decrypt

#### Scenario: Revocation wins

- GIVEN finish has not yet passed the pre-decrypt recheck
- WHEN `revoke_device` commits first
- THEN finish does not sign

#### Scenario: Signing wins before revocation

- GIVEN the pre-decrypt recheck committed while the credential was active
- WHEN revocation commits during signing
- THEN the completed Response remains retrievable

#### Scenario: Signing wins before exit

- GIVEN the pre-decrypt recheck committed while the row was still C2
- WHEN exit commits during signing
- THEN the completed Response remains retrievable
- AND the blob is then destroyed

#### Scenario: Restart loads the signup envelope

- GIVEN hosted signup persisted an envelope and the process restarted
- WHEN the seed is loaded and signs a Challenge
- THEN an independent verifier accepts it under the document's operational public

#### Scenario: Fixed consent vector

- GIVEN the design's fixed transcript inputs, including the ClassicalPublicKey map, operation `["vms","stop"]`, resource `["vm","A"]`, and 32 bytes of `0x22`
- WHEN client and server hash them
- THEN both get `7efc1d284ac45ec66c928a750c701ed266ce28e3dab0e306588928c79dce8c03`
- AND the pre-bind digest `13ef62b41aa5240b246aec4d4bbb240fe5c94bb4a423c24898e2dee6a6844e35` is not that digest

#### Scenario: Fresh consent returns the Response and the bind

- GIVEN a C2 row and a fresh A3 proof bound to Challenge `C`, request `R`, session key 32 bytes of `0x11`, operation `["vms","stop"]`, resource `["vm","A"]`, and channel 32 bytes of `0x22`
- WHEN the initiating client retrieves with the original verifier
- THEN `state` is `completed`
- AND `response` is the identikey-auth Response for `C`
- AND `bind` is the 64-byte signature over `bind_signing_bytes` for those stored fields
- AND `operation` is `["vms","stop"]` and `resource` is `["vm","A"]`
- AND omitting the verifier returns neither signature

#### Scenario: Begin returns the stored bind fields

- GIVEN a begin body whose operation is `["vms","stop"]`, resource is `["vm","A"]`, channel is 32 bytes, and session key is Ed25519
- WHEN begin runs
- THEN the response carries those stored fields beside `consent_challenge`
- AND an A4 wallet that recomputes a different digest refuses to sign

#### Scenario: Challenge-only begin is refused

- GIVEN a begin body with a canonical Challenge and no operation
- WHEN begin runs
- THEN it is rejected
- AND no attempt row is stored

#### Scenario: Substituted bind is refused

- GIVEN an attempt whose consent digest used operation `["vms","stop"]`
- WHEN finish presents an A4 Elect signature over a consent Challenge whose digest used `["vms","start"]`
- THEN it is rejected before decrypt

#### Scenario: Pre-migration attempt fails closed

- GIVEN an attempt stored before bind columns existed
- WHEN finish runs
- THEN it fails closed
- AND it does not hash empty bind fields
- AND it does not decrypt

#### Scenario: Admission rejects a bind the edge cannot sign

- GIVEN a begin body whose session key is P-256, or whose channel is not 32 bytes, or whose operation has 9 components
- WHEN begin runs
- THEN it is rejected
- AND no attempt row is stored

#### Scenario: Edge audience is canonical base58

- GIVEN a canonical v1 Challenge whose `aud` is base58btc of a 32-byte edge XID and whose re-encode equals that text, plus the bind fields
- WHEN begin runs
- THEN admission accepts the audience
- AND a 64-hex audience is refused before the row is stored
- AND a base58 string that decodes to 32 bytes but does not re-encode to itself is refused before the row is stored

#### Scenario: Consent audience stays account hex

- GIVEN a stored attempt
- WHEN the server builds the A4 consent Challenge
- THEN its `aud` is the account XID as 64 lowercase hex
- AND that value is not the edge Challenge `aud`

#### Scenario: Auth payload is not the bind payload

- GIVEN the design's joint vector
- WHEN the identikey-auth signing payload and `bind_signing_bytes` are built for that attempt
- THEN the two byte strings differ

#### Scenario: Channel is not checked here

- GIVEN the 32-byte channel binding the client derived for its edge connection (a v1 Challenge has no channel field)
- WHEN begin records them and the edge is not contacted
- THEN the attempt is stored
- AND the signature covers those bytes

#### Scenario: A4 retrieval with the original verifier

- GIVEN an Elect key on the document and no passkey row
- WHEN it signs the server-returned consent Challenge and finish completes
- THEN retrieve with the original PKCE verifier returns the Response and the bind

#### Scenario: Substituted consent Challenge

- GIVEN a valid Elect signature over a Challenge that is not the server's bytes
- WHEN finish runs
- THEN it rejects before decrypt

#### Scenario: Elect removed before the A4 recheck

- GIVEN an A4 attempt whose Elect key is removed before the pre-decrypt recheck
- WHEN finish reaches that recheck
- THEN it does not decrypt

#### Scenario: A4 recheck wins

- GIVEN the A4 recheck committed while that public still held Elect
- WHEN the key is removed during signing
- THEN the completed Response remains retrievable

#### Scenario: Operational key removed before recheck

- GIVEN exit or key removal commits before the pre-decrypt recheck
- WHEN finish reaches that recheck
- THEN it does not sign

#### Scenario: Swapped or malformed envelope

- GIVEN an envelope that is truncated, or whose AAD names another account, or whose wrapping key is missing
- WHEN finish tries to load it
- THEN it fails closed before signing

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

### Requirement: Email is an account channel, not a device

`accounts.email` SHALL be the A1 recovery destination for that
account. It SHALL NOT be a `credentials` kind. `list_devices` SHALL
NOT return it. Writing the column SHALL NOT insert a credential.
The existing unique index on `lower(email)` SHALL remain the rule
for which accounts may store the same address.

#### Scenario: Setting the address adds no device

- GIVEN an account with no email
- WHEN a verified A1 ceremony stores an address on `accounts.email`
- THEN `list_devices` for that XID is unchanged
- AND no credentials row was inserted

### Requirement: The managed Sign key is not a device record

`managed_key_blob` SHALL NOT appear in `list_devices`. `revoke_device`
SHALL NOT clear or rotate it. An A0 password proof and an A1 email
or SMS proof SHALL NOT decrypt `managed_key_blob`, SHALL NOT sign an
identikey-auth Challenge with that key, and SHALL NOT mint an Elect
key.

#### Scenario: Revoking a passkey leaves the operational key

- GIVEN a C2 account with a passkey and a `managed_key_blob`
- WHEN `revoke_device` revokes that passkey
- THEN the passkey is absent from `list_devices`
- AND `managed_key_blob` is unchanged

#### Scenario: Mailbox proof does not sign with the operational key

- GIVEN a C2 account whose A1 email is verified
- WHEN the caller presents only that A1 proof
- THEN the server does not decrypt `managed_key_blob` and does not produce an identikey-auth signature or an Elect key

### Requirement: Provider keys and discarded Elect are not account devices

The OP signing key and the pairwise salt SHALL NOT be stored as
credentials rows. An Elect private key discarded at hosted signup
SHALL NOT be reconstructed from the account session cookie or from
`accounts.email`.

#### Scenario: A cookie does not restore Elect

- GIVEN a hosted C2 account whose Elect private key was discarded at signup
- WHEN the caller presents that account's session cookie
- THEN no Elect private key is returned
- AND no credentials row is created for the OP signing key or the pairwise salt

### Requirement: Surviving access is an account login

A non-revoked credential SHALL count as account access only when its
kind is `passkey`, `oidc_apple`, `oidc_google`, or `identikey_auth`,
or a password kind when that credentials row exists. `ssh_git` SHALL
NOT count. `accounts.email` and `managed_key_blob` SHALL NOT count.

`revoke_device` SHALL remain an unconditional soft-revoke of the
addressed credential on that XID. It SHALL NOT evaluate surviving
access and SHALL NOT require confirmation. The living scenario
"Revoke hides the device" stays the rule for that primitive,
including when the addressed row is the only passkey. This
requirement does not claim that today's store enforces surviving
access.

Account-access revocation SHALL be a separate kind-generic
operation. It is the only operation that enforces this rule, for
every counted kind. `add-passkey-account-management`
(`identikey-core-zlf.6`) owns that operation and its verification,
including the passkey confirmation surface and the same operation
for `oidc_apple`, `oidc_google`, `identikey_auth`, and a password
row when that kind exists. Later nodes SHALL call it rather than
add a second policy. The operation and its revocation SHALL be one
atomic decision for the XID, under the account lock, with the
custody row locked before the credential row. While another counted
credential remains, the operation SHALL revoke the addressed row.
When the addressed row is the last counted credential and an
explicit last-access confirmation is absent, the operation SHALL
leave that row active. An `ssh_git` row, the mailbox, and the
managed Sign key SHALL NOT supply that confirmation. This rule
becomes living behavior when `identikey-core-zlf.6` lands the
operation. Folding this model SHALL NOT be read as that landing.

#### Scenario: The primitive still revokes a sole passkey

- GIVEN one non-revoked passkey and no other credential
- WHEN `revoke_device` revokes that passkey
- THEN the passkey is absent from a subsequent list

#### Scenario: Another account login keeps account-access revocation ordinary

- GIVEN a non-revoked passkey and a non-revoked `oidc_apple` credential
- WHEN account-access revocation revokes the passkey without a last-access confirmation
- THEN the passkey is revoked
- AND the `oidc_apple` credential remains

#### Scenario: A password row counts when it exists

- GIVEN a non-revoked passkey and a non-revoked password credential
- WHEN account-access revocation revokes the passkey without a last-access confirmation
- THEN the passkey is revoked
- AND the password credential remains

#### Scenario: ssh_git does not keep the last passkey ordinary

- GIVEN a non-revoked passkey, a non-revoked `ssh_git` credential, and no other counted credential
- WHEN account-access revocation is asked to revoke the passkey without a last-access confirmation
- THEN the passkey remains listed
- AND `revoke_device` for that same passkey still revokes it

#### Scenario: The last account login requires confirmation

- GIVEN one non-revoked passkey and no other counted credential
- WHEN account-access revocation is asked to revoke it without a last-access confirmation
- THEN the passkey remains listed

#### Scenario: Two concurrent unconfirmed revokes cannot clear the account

- GIVEN two non-revoked counted credentials and no last-access confirmation
- WHEN two account-access revocations for those two credentials run concurrently
- THEN one credential remains listed
- AND the revocation that would have removed the last counted credential leaves that row active
- AND both decisions used one account-scoped lock with the custody row before the credential row
