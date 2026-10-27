# Tasks

- [x] Encode version 1 as exactly one ML-DSA-65 control key at threshold 1, with a domain-separated signing context, the unsigned record, the detached signatures, and the SHA-256 digest in `identikey-protocol`. Verify migration, new-identity inception, rotation, and classical-only rejection there.
- [x] Fresh advise after preparation
- [x] Reject a migration record when the verifier has no stored digest and is not treating classical signatures as sound.
- [x] Keep the URN grant, passkey login, and classical document updates outside this chain. Add a test that a classical Elect signature does not advance the head.

## Owed from advise — astra-arch-review, 2026-10-27

- [x] R1: Specify verifier-owned checkpoint/head state and one-time bootstrap; an old retained checkpoint must not rewind an accepted head, a different genesis must not replace it, and resolver-supplied digests must not establish trust. Add cases for replay after PQ rotation, alternate genesis, and lost trust state after classical cutoff. See `reviews/2026-10-27-advise.md`.
- [x] R2: Specify PQ-chain duplicity handling when two valid successors share a predecessor, including a branch discovered after one was accepted; return no successful authority winner for the observed fork. Cover both orders, identical duplicates, and invalid competing signatures. See `reviews/2026-10-27-advise.md`.
- [x] R3: Define how the PQ record, cited digest, and predecessor chain are supplied through or alongside the existing XID-document resolver without changing its body contract or resolution tiers; alternatively scope this node explicitly to a caller-supplied codec/verifier and name follow-up delivery work. See `reviews/2026-10-27-advise.md`.
