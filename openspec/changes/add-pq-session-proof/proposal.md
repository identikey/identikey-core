# add-pq-session-proof

> **PENDING**

Bead `identikey-core-pgz.2`. Depends on `add-pq-state-chain`.

**Preparation:** 2026-10-28. Upstream artifact is the v1 state-chain
verifier in identikey-protocol `0ff2dea`, living spec
`openspec/specs/pq-state-chain/spec.md`, folded `922b188`.
`Trust::resolve` returns the head only when the cited digest is that
head and the chain is not forked. Outcome: new contract, not a
revision of an accepted one. Authority: the `identikey-core-pgz`
grant covers this node once that artifact exists. Activation stays
off. `pq-session-secret` is an unresolved hypothesis, and campaign
authority does not bypass it. The key-source menu is not asked again.

## Why

A post-quantum control key is already committed in the state chain.
Signing every later proof with ML-DSA repeats that cost. One
signature should open a session bound to the XID and the cited
digest. Later proofs in that session are short symmetric checks.
They are not a log, and they are not evidence that anyone but a
holder of the session key produced them.

## What

- Add capability `session-proof`.
- Opening a session is one ML-DSA-65 signature by the control key of
  the cited state digest. The signed opening names the XID, that
  digest, an audience, and a fresh challenge.
- A later proof verifies with a MAC under the session key and no
  second public-key signature. A different audience or a different
  state digest fails.
- The proof names the XID. It does not name the classical
  fingerprint.
- No proof is appended to a log.
- How the session key is established is not decided. See the spike
  in `design.md`.

## Impact

- Capabilities: ADDED `session-proof`
- ADRs: none

## User journey & surfaces

No new UI because the outcome is a verifier's decision about an
opening and a follow-up proof the caller already holds. The passkey
page, `/authorize`, and `/token` do not change.

Working: an opening under the current head's control key starts a
session, and a follow-up MAC for that audience and digest checks.
Empty: a XID with no authority has no session. Failed: a classical
signature as the opener, a forked chain, the wrong audience, or an
older digest. Off: a verifier that has not accepted a state head
still treats classical documents as it does today.

## Out of scope

- Implementing ML-KEM or a classical Diffie-Hellman. `pq-session-secret` stays unverified.
- A proof log or a Merkle batch of ordinary objects.
- Changing the state-chain record, the well-known XID body, the URN grant, passkey login, or classical OIDC token signatures.
- The pre-break hybrid splice (`ikp-2u4`).
