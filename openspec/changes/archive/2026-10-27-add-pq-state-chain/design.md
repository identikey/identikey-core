# add-pq-state-chain

## Record

The unsigned record is a canonical dCBOR map with an explicit version. v1 is the only accepted profile: exactly one ML-DSA-65 control key and threshold 1. Any other version, threshold, or control profile is rejected, not read as v1. The digest is SHA-256 of those unsigned bytes. Signatures sit outside the hashed bytes. Each signature covers a domain-separated context that names this protocol and the version, then the unsigned record. The XID inside the record is not recomputed from the control key unless this record is a new identity whose inception key is that control key.

Fields: `v`, `xid`, `seq` (starts at 1), `prev` (32 bytes, absent on the first record), `control`, `operational` (algorithm-tagged public keys, privileges, and a validity window).

An ordinary reference cites the digest. It does not repeat the keys.

## Verifier state

Trust state is the verifier's, keyed by XID. It holds at most one migration anchor digest and one head. Bytes from a resolver, including a digest the server names, do not write that state. The caller supplies candidate records. The verifier updates trust state only by the rules below.

The first record initializes an XID that has no head. Revalidating the anchor later may show that the historical record still checks. It does not move the head. A different first record does not replace an established chain. Losing the trust state after classical signatures are out of policy leaves the verifier with nothing to accept.

## First record

Two entrances, and only when that XID has no head.

Migration, for an XID that already has a classical document. The Elect key on that document signs the record, and the new control key signs the same bytes. A verifier that still treats classical signatures as sound may accept the pair, store the digest as both anchor and head. A verifier that does not treat them as sound accepts that record only when the digest is already the stored anchor. A later classical signature is not a way to create the missing checkpoint.

New identity. The inception signing key is the post-quantum control key. The XID is SHA-256 of that key's canonical CBOR, which is the existing formula with a different algorithm. No classical checkpoint is required. The challenge spec's "PQ implies classical" rule is unchanged for challenge proofs; this entrance is the state record, not a classical-free challenge response.

## Later records

The verifier checks the new record against the previous accepted head, not against authority declared only in the new record. `prev` equals the previous digest. `seq` is the previous sequence plus one. `xid` is unchanged. At least a threshold of the previous control keys sign the new record. Each newly introduced control key also signs it.

A signature that verifies only under a classical key does not change `control`, the threshold, `seq`, or `prev`. Classical Elect may still update the classical XID document's non-control keys. Those updates do not move the post-quantum head.

Successor precommitment stays optional. Requiring a post-quantum signature is not the same rule as pre-rotation.

## Duplicity

Two different records that are both valid successors of the same head, with the same `prev` and `seq`, are a fork. Once both have been supplied, verification returns no authority for that XID. The order they arrived does not pick a winner. An identical repeat of the head, or of a record already in the chain, is not a fork. A signature that fails is not a second branch.

This matches the living xid-resolution rule that diverging valid documents have no winner. It does not detect a branch nobody supplied. Withholding a later record is still the ADR-007 problem. This change does not add a resolver and does not change the well-known response body. The caller passes the records in.

## What this does not authenticate

A stored control key does not make a classical challenge proof, a passkey assertion, or an OIDC token signature post-quantum sound. Those stay on their current rules until a later change cites this digest.
