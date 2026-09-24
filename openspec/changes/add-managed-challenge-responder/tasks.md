# Tasks

- [x] New C2 Sign+Auth operational keys are Ed25519; blob loads into identikey-auth `SoftwareSigner`
- [x] Signup / `c2_native` no longer uses `PrivateKeyBase::new()` for IdentiKey's Sign+Auth key
- [x] Canonical Challenge signer only (reject noncanonical, wrong version/alg, bad aud, oversize, TTL/skew, expiry, wrong rung, stale key) before key access
- [x] Fresh A3 or user-held A4 bound to exact challenge digest + request id; 24h cookie is not enough
- [x] Durable `signing_instruction_authorized` before sign; completed/failed after with same request id
- [x] Response released only to the initiating client (state + PKCE-like verifier or holder-key proof)
- [x] Envelope-encrypted blob; zeroize plaintext after use; no blob getter
- [x] Tests: exact-challenge bind, substitution, stale session, replay, concurrency, pre-sign log failure, rotation races, response theft, C3/C4 Response-shape equivalence
- [x] Docs: hosted availability; recommend short-lived holder-bound edge Biscuits
- [ ] Advise — reader Fable 5.1, second family Grok

## Owed from 2026-09-24 Astra advise

Review: `reviews/2026-09-24-advise.md` (send-back; banner remains PENDING).

- [x] R1: Reconcile pinned v1 fields, exact-byte roundtrip rejection, admission limits, and post-consent expiry checks; add extra-canonical-field acceptance case
- [x] R2: Specify begin/consent/finish/retrieve messages, immutable account/challenge/client binding, A3/A4 authority and revocation checks, and substitution acceptance cases
- [x] R3: Specify durable request/replay states, atomic authorization use, audit request correlation, and crash/log-failure/retry outcomes
- [x] R4: Specify signing versus exit/key-removal/revocation ordering and completed-response retrieval behavior; add both race orderings to acceptance
- [x] R5: Specify authenticated encrypted blob format and wrapping-key lifecycle, seed/PublicKeysProvider seams, legacy rejection, and explicit C1/C2 support; add restart and malformed/swapped-blob acceptance cases
- [x] Fresh advise after preparation
- [ ] Fresh independent advise after R1–R5 contract reconciliation; acceptance does not activate the PENDING change

## Owed from 2026-09-24 Astra re-advise

Review: `reviews/2026-09-24-advise-2.md` (send-back; banner remains PENDING).

- [x] R6: Reconcile unknown key-use crash outcomes with retry policy; specify durable result/completion and integrity-bound request/audit correlation; add crash-before/after-sign, log-failure/restart, and concurrent-finish acceptance outcomes
- [x] R7: Pin A4 account-key authority, encoded consent transcript and consent Challenge, A3 instruction binding, freshness, and client messages/retrieval proof; add unrelated-key, managed-key, account/client substitution, wrong-ceremony, and stale-consent cases
- [x] R8: Specify authorization/key-use transaction boundaries and serialization with credential revocation and operational-key removal; add both revocation orderings and signing-before-exit retrieval acceptance
- [x] Complete accepted envelope coverage: hosted signup → restart → load → independently verified Response, malformed/swapped blobs, and missing/wrong wrapping key
- [x] Fresh independent advise after R6–R8 reconciliation; acceptance still does not activate the PENDING change

## Owed from 2026-09-24 fresh Astra review

Review: `reviews/2026-09-24-re-advise.md` (send-back of the current contract; proposal banner remains ACTIVE BUILD).

- [x] R9: Pin domain-tagged consent transcript encoding/types, verifier commitment, server-owned times, and exact A4 consent-Challenge matching; add a reproducible vector, successful A4 retrieval, and substitution cases
- [x] R10: Define proof-specific pre-use authority checks for A3 credentials versus A4 Elect document membership; add A4 without a passkey row, Elect removal/recheck orderings, and operational Sign+Auth removal acceptance cases
