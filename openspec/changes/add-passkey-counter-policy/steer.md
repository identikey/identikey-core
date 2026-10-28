# steer add-passkey-counter-policy

**When.** 2026-10-28
**Depth.** standard

## Decided

- A counter that stays 0 or goes backwards is logged and accepted (user, 2026-09-26, on `identikey-core-5gh.4`)
  Why: synced platform passkeys do this, and rejecting it locks people out.
- Zero is not a regression log (auto)
  Why: counter 0 means the authenticator is not counting. It already succeeds today.
- An equal positive counter still fails (auto)
  Why: "goes backwards" is a drop, not a repeat. The repeat is the replay signal the 2026-09-26 note did not waive.
- The stored counter stays at the high-water mark (auto)
  Why: writing the lower value would make a later replay of the old counter look like an increase.

## Skipped

- None.

## Feeds change

Scaffold PENDING. Do not activate. The post-quantum grant does not cover this node. Do not change Signal API work in the same edit.
