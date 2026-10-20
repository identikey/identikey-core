# Tasks

- [ ] Begin requires an Ed25519 ClassicalPublicKey, CanonicalTuple operation and resource, and a 32-byte channel; refuses P-256, bad tuples, the admission caps, and any other channel length before storing the row
- [ ] Consent transcript appends the map bytes, counted components, and the raw channel; the pinned digest is `7efc1d284ac45ec66c928a750c701ed266ce28e3dab0e306588928c79dce8c03`
- [ ] One key-use claim signs the v1 Response and `bind_signing_bytes`; retrieve returns both or neither in the pinned JSON; the audit commit stores both signatures, operation, resource, and the session-key fingerprint
- [ ] Tests: challenge-only begin refused; pre-migration row fails closed; A4 over `["vms","start"]` refused before decrypt; second client gets neither; channel stored without contacting an edge; begin echoes the stored bind fields; auth payload bytes differ from the bind bytes; joint vector matches `direct_challenge_canonical_bind_vector`

Do not implement until a fresh accepting reader records `READER:` on this contract.

## Owed from preparation — 2026-10-19

- [ ] Fresh advise after preparation

## Owed from advise — 2026-10-20 (opus-arch-review, send-back)

Contract amended 2026-10-20. These boxes are the amendment, not the code.

- [x] B1: operation and resource are CanonicalTuple component arrays (printable ASCII `0x21..=0x7e`, non-empty), hashed with component boundaries; the OP builds Mjolnir `696fb00` `bind_signing_bytes` exactly; a joint vector reproduces `direct_challenge_canonical_bind_vector`; re-pin the consent digest
- [x] B2: the session key is signed as the ClassicalPublicKey map (Ed25519-only declared as a subset); the channel is exactly 32 bytes; begin caps component count and length before storing the row
- [x] B3: name who renders consent and from what bytes (begin returns the stored bind fields; A4 wallet recomputes the digest), or replace "show" with "commits to"; add a scenario and test
- [x] N1: fold or amend the bind-less "Fresh consent signs the exact Challenge" scenario; record "bind mandatory, bare responder withdrawn" as a decision with why
- [x] N2: the bind signature is stored in the completion-audit commit; the audit records operation, resource, and the session-key fingerprint
- [x] N3: pre-migration attempts without bind fields fail closed at finish; test
- [x] N4: state and assert the separation between the identikey-auth payload and the bind payload
- [x] N5: pin the retrieve wire shape for the bind
- [x] N6: the substituted-operation test is A4 consent over a different tuple, rejected before decrypt
- [x] N7: reconcile the "Banner stays PENDING" preparation note with the ACTIVE BUILD banner
