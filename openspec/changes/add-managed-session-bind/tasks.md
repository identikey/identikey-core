# Tasks

- [ ] Begin requires session public key, operation, resource, and channel, and stores them on the attempt
- [ ] Consent transcript appends those fields; the pinned digest is `88265dc6cca649d6aae7f1e73b92a402b143d9cbfe4fcbb059a543053d124edc`
- [ ] One key-use claim signs the v1 Response and the bind; retrieve returns both or neither
- [ ] Tests: challenge-only begin refused, substituted operation refused before decrypt, second client gets neither, channel accepted without contacting an edge
- [ ] Advise — architecture. Fresh reader after this contract. Do not implement while PENDING.

## Owed from preparation — 2026-10-19

- [ ] Fresh advise after preparation

## Owed from advise — 2026-10-20 (opus-arch-review, send-back)

- [ ] B1: operation and resource are CanonicalTuple component arrays (printable ASCII `0x21..=0x7e`, non-empty), hashed with component boundaries; the OP builds Mjolnir `696fb00` `bind_signing_bytes` exactly; a joint vector reproduces `direct_challenge_canonical_bind_vector`; re-pin the consent digest
- [ ] B2: the session key is signed as the ClassicalPublicKey map (Ed25519-only declared as a subset); the channel is exactly 32 bytes; begin caps component count and length before storing the row
- [ ] B3: name who renders consent and from what bytes (begin returns the stored bind fields; A4 wallet recomputes the digest), or replace "show" with "commits to"; add a scenario and test
- [ ] N1: fold or amend the bind-less "Fresh consent signs the exact Challenge" scenario; record "bind mandatory, bare responder withdrawn" as a decision with why
- [ ] N2: the bind signature is stored in the completion-audit commit; the audit records operation, resource, and the session-key fingerprint
- [ ] N3: pre-migration attempts without bind fields fail closed at finish; test
- [ ] N4: state and assert the separation between the identikey-auth payload and the bind payload
- [ ] N5: pin the retrieve wire shape for the bind
- [ ] N6: the substituted-operation test is A4 consent over a different tuple, rejected before decrypt
- [ ] N7: reconcile the "Banner stays PENDING" preparation note with the ACTIVE BUILD banner
