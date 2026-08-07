//! Managed custody — the C2 rung, and the store everything else sits on.
//!
//! # What belongs here
//!
//! Accounts, credentials, XID documents, custody records, the consent log, and
//! the C2 → C3 migration ceremony.
//!
//! # The line this crate exists to hold
//!
//! C1 means we can sign without you. C2 means we **cannot** sign without an
//! authenticated instruction that we log and you can audit. That line is the
//! product's integrity, and it is enforced here or nowhere.
//!
//! Two mechanisms make it real rather than a promise:
//!
//! - **Privilege separation** (ADR-008, `identikey-core-av9`). At C2 the user's
//!   key holds `Elect` and `Transfer`; IdentiKey's key holds `Sign` and `Auth`.
//!   A breach of IdentiKey therefore yields the ability to sign *now* but not to
//!   take over the identity — and exit is unilateral, because the user can rotate
//!   our key out without our cooperation. This is the exit test enforced
//!   cryptographically instead of by policy.
//! - **The migration ceremony ships with C2, not after it** (invariant I3,
//!   `identikey-core-zan.2`). A managed-custody product without an exit is the
//!   thing this project exists to oppose, and it is far harder to retrofit than
//!   to design in.
//!
//! # Invariant I2, which is a release blocker
//!
//! Account recovery (email, SMS, social re-verification) and key recovery
//! (guardian quorum, Shamir, MPC) are different systems and must never merge.
//! If an email link can reach a key, the email provider is the real root of
//! trust and the whole ladder silently collapses to C1.
//!
//! # Not implemented yet
//!
//! Nothing here is built. The schema is `identikey-core-zan.1` and is the
//! prerequisite for most of the rest of the board. See `docs/custody-ladder.md`
//! for the normative rung definitions.
