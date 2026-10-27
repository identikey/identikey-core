## ADDED Requirements

### Requirement: State record commits the XID and its control key

The system SHALL represent post-quantum authority for a XID as a versioned record whose unsigned canonical dCBOR commits a version, the XID, a sequence number, the digest of the previous record when one exists, the post-quantum control keys and their threshold, and the operational authentication keys with privileges and validity. Version 1 SHALL be exactly one ML-DSA-65 control key with threshold 1. Any other version, threshold, or control profile SHALL be rejected. The record digest SHALL be SHA-256 of that unsigned encoding. A detached signature SHALL cover a domain-separated context naming this protocol and the version, then the unsigned record. The XID SHALL remain SHA-256 of the inception public key's CBOR. A reference that depends on current authority SHALL cite the digest rather than embed the keys.

#### Scenario: Head names one control key

- GIVEN an accepted chain head for a XID with one ML-DSA-65 control key
- WHEN a verifier resolves that digest
- THEN the control key is that ML-DSA-65 key and the XID is unchanged

#### Scenario: A cited digest repeats no key bytes

- GIVEN a message that depends on current authority
- WHEN the message names the authority
- THEN it carries the 32-byte digest and does not carry the control public key

### Requirement: Migration checkpoint is accepted only while classical signatures are sound, or when already stored

Verifier trust state SHALL be local to the verifier and keyed by XID. It SHALL hold at most one anchor digest and one head. Resolver bytes and a server-supplied digest SHALL NOT write that state. The caller supplies the records.

For an existing classical XID with no head, the first record SHALL carry a signature by a key that holds Elect on the current classical document and a signature by the new post-quantum control key, both over the same unsigned record. A verifier that treats classical signatures as sound MAY accept that pair and SHALL retain the digest as both the anchor and the head. A verifier that does not treat classical signatures as sound SHALL accept that first record only when the digest is already the stored anchor. Accepting or rechecking the anchor SHALL NOT move an existing head. A different first record SHALL NOT replace an established chain. If the trust state is lost after classical signatures are out of policy, the verifier SHALL accept no record for that XID. A classical signature alone SHALL NOT create a checkpoint.

#### Scenario: Sound classical verification accepts the pair

- GIVEN a verifier that treats Ed25519 signatures as sound, a document whose Elect key is Ed25519, and a first record signed by that key and by a new ML-DSA-65 control key
- WHEN the verifier checks the record
- THEN it accepts the record and retains the digest

#### Scenario: Unsound classical verification does not invent a checkpoint

- GIVEN a verifier that does not treat classical signatures as sound and does not already retain a digest
- WHEN it is shown a first record with a classical Elect signature and an ML-DSA-65 countersignature
- THEN it rejects the record

#### Scenario: A second genesis does not replace the head

- GIVEN an accepted head past the anchor, and classical signatures still treated as sound
- WHEN a different sequence-1 record arrives, signed by the Elect key and by another ML-DSA-65 key
- THEN the head is unchanged

#### Scenario: Replaying the anchor does not rewind the head

- GIVEN an accepted head past the anchor, and a verifier that no longer treats classical signatures as sound
- WHEN the original anchor record is submitted again
- THEN the historical record may still check and the head stays where it is

### Requirement: A new identity may use a post-quantum inception key

A new identity MAY use a post-quantum public key as its inception signing key. The XID SHALL be SHA-256 of that key's canonical CBOR. The first record's control key SHALL be that inception key, and no classical checkpoint is required.

#### Scenario: Inception key is the control key

- GIVEN a new ML-DSA-65 inception key and a first record whose control key is that key
- WHEN the XID equals SHA-256 of the key's canonical CBOR and the record is signed by that key
- THEN the verifier accepts the record without a classical signature

### Requirement: Rotation checks the previous head

A record after the first SHALL set `prev` to the previous accepted digest, set `seq` to the previous sequence plus one, and keep the same XID. A threshold of the previous control keys SHALL sign the unsigned record. Each control key that was not in the previous head SHALL also sign it. The verifier SHALL evaluate those signatures against the previous accepted head.

#### Scenario: Previous control key rotates

- GIVEN an accepted head and a successor signed by that head's control key and by the new control key
- WHEN `prev`, `seq`, and `xid` match the head
- THEN the successor becomes the head

#### Scenario: Successor declares its own authority

- GIVEN an accepted head and a successor signed only by a key named in the successor
- WHEN the previous control key did not sign the successor
- THEN the verifier rejects it and the head is unchanged

### Requirement: A classical signature does not move the head

A signature that verifies only under a classical key SHALL NOT change the control keys, the threshold, the sequence, or the previous digest. An update to the classical XID document that does not carry a valid post-quantum control signature SHALL leave the accepted head where it is.

#### Scenario: Elect signs a replacement control key

- GIVEN an accepted head and a new record whose control key differs, signed only by the classical Elect key
- WHEN the verifier checks the record
- THEN the head is unchanged

### Requirement: Two valid successors are not a winner

When two different records are both valid successors of the same head, with the same previous digest and the same sequence, the verifier SHALL return no authority for that XID. The order of arrival SHALL NOT choose a head. A byte-identical repeat of an already accepted record SHALL NOT be a second branch. A record whose signature fails SHALL NOT count as a branch. The verifier SHALL NOT claim to notice a successor that was never supplied.

#### Scenario: Either order is duplicity

- GIVEN a head H and two different valid successors A and B of H
- WHEN the verifier has been given both, in either order
- THEN it returns no authority for that XID

#### Scenario: A repeat is not a fork

- GIVEN an accepted head
- WHEN the same record bytes are submitted again
- THEN the head is unchanged and authority still resolves

#### Scenario: A bad signature is not a second branch

- GIVEN an accepted successor A of head H and another record B with the same previous digest and sequence whose signature does not verify
- WHEN both have been supplied
- THEN A remains the head

### Requirement: The caller supplies the records

The well-known XID document response SHALL remain the stored document bytes. This capability SHALL verify records the caller supplies and SHALL NOT define a new resolver tier or a new well-known body. A cited digest SHALL resolve only against the verifier's accepted head. Carrying the chain inside resolver responses is follow-up work outside this change.

#### Scenario: Well-known body is unchanged

- GIVEN a published XID document and a post-quantum head for the same XID
- WHEN a client fetches `/.well-known/xid/{xid}`
- THEN the body is the stored XID document and does not contain the post-quantum record
