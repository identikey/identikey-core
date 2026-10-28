# add-pq-session-proof

> **ACTIVE BUILD**

Bead `identikey-core-pgz.2`. Depends on `add-pq-state-chain`.

**Preparation:** 2026-10-28. Upstream artifact is the v1 state-chain
verifier in identikey-protocol `0ff2dea`, living spec
`openspec/specs/pq-state-chain/spec.md`, folded `922b188`.
`Trust::resolve` returns the head only when the cited digest is that
head and the chain is not forked. Outcome: new contract, not a
revision of an accepted one. The human activated this change on
2026-10-28. Astra sent the first contract back
(`reviews/2026-10-27-advise.md`). The delta now pins challenge
consumption, the external key-binding precondition, current-head
checks on follow-ups, and the canonical bytes. Fresh advise from
`astra-arch-review` is still owed. `pq-session-secret` stays
unverified. Activation does not mark the spike skipped and does not
include key establishment. The key-source menu is not asked again.

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
- The verifier holds the expected audience and challenge. Success
  consumes the challenge. Failure does not. A signature without a
  caller-supplied key is not a session.
- The MAC names the opening id, so two openings do not share proofs.
  Each follow-up still requires that digest to be the current
  unforked head. A repeated MAC is not a fresh action.
- The opening and the MAC are canonical dCBOR, domain-separated the
  same way as `identikey-pq-state/v1`. One vector is in the delta.
- How the session key is established is not decided. The caller
  supplies a key that establishment outside this change has bound to
  that opening. See the spike in `design.md`.

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
