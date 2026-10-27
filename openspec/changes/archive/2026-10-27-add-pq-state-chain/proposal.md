# add-pq-state-chain

> **ACTIVE BUILD**

## Why

A XID is the hash of an inception key, and keys rotate under it. The challenge proof still names the speaker by the classical public key alone. Requiring some ML-DSA signature does not bind that key to the XID. Putting an ML-DSA signature on every object is the wrong cost. This change adds the state a later session proof can cite: one current post-quantum control key per XID, committed in a chain, replaceable only by that key.

## What

- Add capability `pq-state-chain`.
- A versioned record commits the unchanged XID, a sequence, the previous record's digest, the post-quantum control keys, and the operational authentication keys.
- The first record for an existing XID is a migration checkpoint: the current Elect key signs it and the new control key countersigns it. A verifier keeps that digest. After classical signatures are not treated as sound, the same bytes are accepted only when that digest is already kept.
- A later record replaces control only with a signature from the previous control key, plus possession of the new key.
- A classical signature cannot change control, threshold, sequence, or the previous digest.
- New identities may use a post-quantum inception key. The XID is still SHA-256 of that key's CBOR.

## Impact

- Capabilities: ADDED `pq-state-chain`
- ADRs: none in this change. ADR-001 (stable XID) and ADR-008 (Elect is not Sign; pre-rotation stays optional) stay as they are. ADR-007 freshness is not re-specified.

## User journey & surfaces

No new UI because the outcome is a verifier's decision about records the caller already supplied. This change does not put the chain in the well-known XID document body. How a resolver carries the bytes is follow-up work, named and not started here. The passkey page, `/authorize`, and `/token` do not change.

Working: a verifier with the chain head names one control key for the XID. Empty: an unknown XID has no head. Failed: a classical-only update, a broken previous-digest link, or a migration record whose digest was never kept. Off: a verifier that has not accepted post-quantum state still resolves the classical document as it does today.

## Out of scope

- Session establishment and symmetric follow-up proofs (`add-pq-session-proof`, `identikey-core-pgz.2`). The ML-KEM spike stays on that node.
- A proof log or a Merkle batch of ordinary objects.
- Changing the URN grant, the passkey login, or classical OIDC token signatures.
- The pre-break hybrid splice (`ikp-2u4`).
- Making IdentiKey the only store of the control key.

## Preparation

- Upstream: no closed node. Anchors: ADR-001 (XID is SHA-256 of the inception key), ADR-007 (a stale signed document is a freshness problem this change does not solve), ADR-008 (Elect rotates; pre-rotation is optional), `identikey-auth` `verify_response` returns the classical fingerprint, living requirement "URN grant accepts only identikey-auth Response" left unmodified.
- Outcome: revised after `reviews/2026-10-27-advise.md` (send-back, astra-arch-review). Bootstrap is one-time verifier state. Two valid successors are duplicity with no winner. Delivery is a caller-supplied codec, not a change to the well-known body.
- Authority: `identikey-core-pgz` grant "activate and run", bounds are the epic non-goals. This node is dependency-ready. `identikey-core-pgz.2` is not activated. Fresh advise is owed on this revision.
