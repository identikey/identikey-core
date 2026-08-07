//! Assisted key recovery — what makes C3 survivable for people who are not
//! cryptographers.
//!
//! # Why this crate is load-bearing
//!
//! C3, not C4, is the destination the ladder nudges toward. The difference
//! between them is entirely this crate: C4 is "be your own bank, lose the key and
//! lose the identity," which is deliberately available and deliberately not the
//! default. Without a recovery story that ordinary people will actually complete,
//! self-custody is a rung nobody climbs, and the product collapses back to
//! managed custody by attrition rather than by choice.
//!
//! # What belongs here
//!
//! Guardian quorum, secret sharing, and the MPC ceremony. `bc-components` ships
//! **SSKR** (Sharded Secret Key Reconstruction) and is already in the dependency
//! graph via `bc-xid`, so evaluate that before reaching for a separate Shamir
//! implementation (ADR-001).
//!
//! # The boundary that must not be crossed
//!
//! This is **key** recovery. It is a different system from **account** recovery
//! and the two must never merge (invariant I2, `identikey-core-vt4.1`). No path
//! through an email magic link, an SMS code, or a social re-verification may
//! terminate in key material. Those are access level A1/A2, available at C1 and
//! C2 only, and they restore access to a managed account — never the key itself.
//!
//! # The unsolved problem
//!
//! Guardian *selection* UX (`identikey-core-vt4.3`) is the hardest open question
//! on the ladder, and the one that determines whether anyone reaches C3 at all.
//! It is a design problem, not an implementation one, and it is not solved by
//! writing this crate.
//!
//! # Not implemented yet
//!
//! Nothing here is built. See `identikey-core-vt4` for the epic.
