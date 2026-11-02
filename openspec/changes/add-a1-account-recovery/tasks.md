# Tasks

- [ ] Begin issues an email factor (32-byte secret) and an SMS factor (6 digits) and stores only SHA-256 of the challenge id concatenated with the secret
- [ ] Finish accepts the matching secret in constant time, consumes the factor, and returns `AccountRecoveryProof` tagged bootstrap or recover
- [ ] A wrong, expired, unknown, or consumed factor returns no proof; five wrong SMS attempts kill that factor
- [ ] `accept_bootstrap` runs only for a bootstrap proof and neither takes nor returns key bytes
- [ ] `accept_recover` runs only for a recover proof of a directory C1/C2 XID, and refuses C3/C4
- [ ] A bootstrap proof refuses recover, a recover proof refuses bootstrap, and `restore_key` still refuses `AccountRecoveryProof`
- [ ] `AccountRecoveryProof::granted` is not a successful factor check
- [ ] In-memory ports cover the cases; `identikey-server` gains no route

## Out of scope

- Mail and SMS transport, HTTP, and pages.
- Social re-verification, guardian recovery, and pre-rotation.

## Owed from architecture advise — 2026-11-02

Review: `reviews/2026-11-02-advise.md` (astra-arch-review, send-back). Reconcile these contracts in design/delta/tasks before implementation; preserve the library-only email-and-SMS scope.

- [x] R1: Specify atomic factor-store consumption and SMS attempt transitions, committed-success/error behavior, and tests for concurrent successes, wrong attempts, fifth-failure/success ordering, and store failures.
- [x] R2: Specify trusted directory lookup and immutable channel/destination/purpose/XID binding, target delivery to acceptance callbacks, rebinding policy, bootstrap destination provenance, and mismatch/substitution tests.
- [x] R3: Specify proof reuse/lifetime and callback-failure semantics; reconcile `restore_access` with purpose/XID/current-custody authorization; require removal of unchecked public proof construction and tests for duplicate acceptance and alternate-path bypasses.
- [x] R4: Require cryptographically secure email/SMS generation, unbiased six-digit sampling, collision-safe challenge IDs, unambiguous hash encoding, fail-closed issuance errors, and focused coverage.
- [x] Obtain fresh architecture advise on the reconciled R1–R4 contracts before act.

## Owed from architecture advise — 2026-11-02, second pass

Review: `reviews/2026-11-02-advise-2.md` (astra-arch-review, send-back). R1, R3, and R4 contracts are answered; finish the remaining R2 acceptance policy before act.

- [x] R2 follow-up: Specify whether destination unbinding/rebinding after finish revokes an outstanding recover proof at acceptance or whether finish freezes that authority; reconcile design/delta/tasks, including proof disposition on refusal and the retained current-custody check.
- [x] R2 follow-up: Add contract scenarios and an implementation-test obligation for destination removal and reassignment after finish but before acceptance, asserting callback count, bound target, and proof disposition under the chosen policy.
