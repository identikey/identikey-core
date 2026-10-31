# Tasks

- [x] Hosted assertion, managed assertion, and the encapsulation verifier share one counter rule
- [x] A positive counter below the stored value succeeds, is logged, and leaves the stored value
- [x] Counter 0 succeeds and is not logged as a regression
- [x] An equal positive counter still fails and leaves the stored value
- [x] A higher counter still updates the stored value
- [x] Tests cover the drop, the zero, the equal reject, and the increase on each of the three sites

Owed from advise 2026-10-30 (`reviews/2026-10-30-advise.md`). The contract chooses (a): zero the `Passkey` counter webauthn-rs sees. Do not raise `passkey_json`.

- [x] Counter 0 never lowers a positive stored counter. Delta scenario: stored 10, presents 0, succeeds, stays 10, no drop log. design.md no longer says writing 0 is harmless.
- [x] The stored-counter write is monotonic at all three sites (`GREATEST(sign_counter, $2)`) and still bumps `last_used_at` on a drop or a zero. Test that a drop leaves the counter and advances `last_used_at`. Regenerate `.sqlx/`.
- [x] Set the `Passkey` counter to 0 before webauthn-rs sees it, in `load_passkeys`, on the discoverable key, and in the state stored for managed and encapsulation ceremonies. Do not call `Passkey::update_credential`. Test a credential registered at a positive counter: a lower presented counter succeeds, the column stays, and the drop is logged.

Out of scope: Signal APIs, a user-visible investigation of the log, and webauthn-rs signature checks.
