# add-passkey-counter-policy

> **ACTIVE BUILD**

Bead `identikey-core-5gh.4`. `sign_counter` is the column on
the passkey `credentials` row. Provider diagnostics are
`identikey-core-5gh.7`, not this change.
Preparation 2026-10-30: living `openspec/specs/passkeys/spec.md`
still names this as a later slice (`5gh.3`–`5gh.4`). The three
verifiers still reject a positive counter that does not increase:
`finish_assert` and `finish_managed_assert` in
`crates/identikey-server/src/ceremonies.rs`, and the passkey check
in `crates/identikey-keys/src/encapsulation.rs`. Counter 0 already
passes those guards. Outcome: revised. Amended 2026-10-30 after `reviews/2026-10-30-advise.md`
(send-back, `opus-arch-review`): counter 0 must not lower a positive
stored value; every accepted assertion bumps `last_used_at` and
writes `GREATEST(sign_counter, presented)`; the `Passkey` webauthn-rs
sees has its counter set to 0 so the library check is not a second
policy. Authority: the account-keys first-wave grant on
`identikey-core-zlf` ("activate first wave"). It covers this node
and does not include act. It supersedes the 2026-10-28 note that
the post-quantum grant left activation off.

## Why

Synced platform passkeys often report a counter that does not climb.
Rejecting that locks the person out. A counter that repeats a
positive value is the clone signal, and this slice keeps that
reject. A single-use challenge already stops replay of one assertion.

## What

- Capability `passkeys`.
- A counter of 0 is accepted and is not logged as a regression,
  even when the stored counter is already positive. The stored
  value does not fall.
- A positive counter below the stored value is logged, the assertion
  is accepted, and the stored value stays where it is.
  `last_used_at` still advances.
- A positive counter equal to the stored value still fails.
- A higher counter still replaces the stored value.
- The same rule covers hosted assertion, managed assertion, and the
  encapsulation verifier. The `Passkey` handed to webauthn-rs has
  its counter set to 0 first, so the library's counter check is not
  a second policy. `passkey_json` is not rewritten.

## Impact

- Capabilities: MODIFIED `passkeys` (one added requirement).
- ADRs: none.

## User journey & surfaces

No new UI because the person still uses `/authorize/passkey`, signup,
device approval, and the managed challenge. The result is whether
the ceremony succeeds.

Working: a synced passkey whose counter dropped still signs the
person in, and the account page still loads. A higher counter still
updates as it does now.

Empty: a first assertion stored at 0 stays 0, with no regression log.

Failed: the same positive counter presented again still fails with
the existing counter error. An unknown credential still fails as
`credential not found`.

Off: there is no switch. The rule is the verifier's.

## Out of scope

- Signal APIs (`add-passkey-signal-api`).
- A product surface that investigates the log line.
- Treating counter 0 as a clone.
- Changing webauthn-rs signature checks.
