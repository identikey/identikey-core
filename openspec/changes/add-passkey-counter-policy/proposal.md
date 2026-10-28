# add-passkey-counter-policy

> **PENDING**

Bead `identikey-core-5gh.7`, extracted from `identikey-core-5gh.4`.
Preparation 2026-10-28: the living passkeys spec names this as a
later slice. Three verifiers reject a positive counter that is less
than or equal to the stored value: `finish_assert`,
`finish_managed_assert`, and the encapsulation passkey check.
Counter 0 already passes those guards. Outcome: new contract.
Authority: none. The post-quantum campaign grant does not cover this
node. Activation stays off.

## Why

Synced platform passkeys often report a counter that does not climb.
Rejecting that locks the person out. A counter that repeats a
positive value is still the replay signal, and this slice keeps that
reject.

## What

- Capability `passkeys`.
- A counter of 0 is accepted and is not logged as a regression.
- A positive counter below the stored value is logged, the assertion
  is accepted, and the stored value stays where it is.
- A positive counter equal to the stored value still fails.
- A higher counter still replaces the stored value.
- The same rule covers hosted assertion, managed assertion, and the
  encapsulation verifier.

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
