## ADDED Requirements

### Requirement: Managed operational Sign+Auth is Ed25519

New C2 identities SHALL place an identikey-auth Ed25519 public key on
the XID document with Sign and Auth, and SHALL store that private in
`managed_key_blob` in a form the identikey-auth software signer can
load. The operational key SHALL NOT be BIP-340 secp256k1 Schnorr and
SHALL NOT be P-256. The user's Elect key and X25519 wrap-target SHALL
remain distinct from this operational key. `managed_key_blob` SHALL
NOT be a wrap-target.

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

### Requirement: Consent-gated canonical challenge responder

C2 SHALL answer an identikey-auth Challenge only after a fresh A3
WebAuthn assertion or user-held A4 proof committed to a
domain-separated digest of the exact canonical Challenge bytes and
request id. A long-lived account session SHALL NOT authorize signing.
The endpoint SHALL accept only identikey-auth v1 Challenge bytes
whose round-trip `to_bytes` equals the input (extra map keys
rejected). Algorithm SHALL be validated on the stored operational
key, not as a Challenge field. Admission SHALL enforce `v=1`, nonce
length, body cap, 64-hex `aud`, TTL/skew, current C2 Sign+Auth, and
a post-consent expiry recheck before decrypt. The ceremony SHALL be
begin/consent/finish/retrieve with immutable account, challenge,
request id, and a PKCE verifier commitment. A holder-public retrieval
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

#### Scenario: Fresh consent signs the exact Challenge

- GIVEN a C2 row with an Ed25519 operational key and a fresh A3 proof
  bound to Challenge `C` and request `R`
- WHEN the initiating client retrieves the result
- THEN the body is an identikey-auth Response that verifies for `C`
- AND the Response public key is the stored Sign+Auth key

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
- THEN the Response is not released

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

- GIVEN the design's fixed transcript inputs
- WHEN client and server hash them
- THEN both get `13ef62b41aa5240b246aec4d4bbb240fe5c94bb4a423c24898e2dee6a6844e35`

#### Scenario: A4 retrieval with the original verifier

- GIVEN an Elect key on the document and no passkey row
- WHEN it signs the server-returned consent Challenge and finish completes
- THEN retrieve with the original PKCE verifier returns the Response

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

