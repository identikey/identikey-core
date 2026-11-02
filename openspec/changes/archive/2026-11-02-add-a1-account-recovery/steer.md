# steer add-a1-account-recovery

**When.** 2026-10-30
**Depth.** standard

## Decided
- First landing: email and SMS together (user)
  Why: one proof type, one acceptance surface. A later split would repeat the ceremony.
- Who it creates: bootstrap and recovery (user)
  Why: matches `identikey-core-vt4.4`. C3/C4 still refuse, and the proof still carries no key bytes.
- Home: library only (user)
  Why: the account rule can land and be tested without a route or a carrier.

## Skipped
- None of the three menus.

## Feeds change
The ceremony lives in `identikey-recovery`. Email and SMS are both in this change. Success is an `AccountRecoveryProof` for either a new managed account or passkey enrollment on an existing C1/C2 XID. No page, no HTTP route, no carrier client. Transport is a later change.

## Auto
- Email secret is 32 bytes. SMS secret is 6 digits and dies after 5 wrong attempts.
- The store keeps SHA-256(challenge id || secret). Compare in constant time. Success consumes.
- The directory port reports the rung. The request does not.
- Social re-verification stays `identikey-core-ccf.6`.
