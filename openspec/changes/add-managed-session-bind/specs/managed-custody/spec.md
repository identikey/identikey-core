# managed-custody delta

## MODIFIED Requirements

### Requirement: Consent-gated canonical challenge responder
<!-- base: 992e9aac9421799dfa1d79bf620227b2ba0ed36b openspec/specs/managed-custody/spec.md -->

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
