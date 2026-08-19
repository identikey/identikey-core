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
//! The type system holds that line: [`AccountRecovery`] and [`KeyRecovery`] are
//! uninhabited markers with no conversion. [`restore_access`] does not return
//! key bytes. [`restore_key`] does not accept [`AccountRecoveryProof`]. Email,
//! SMS, and guardian ceremonies are not implemented here; this crate currently
//! exists to make a merge unrepresentable.
//!
//! # The unsolved problem
//!
//! Guardian *selection* UX (`identikey-core-vt4.3`) is the hardest open question
//! on the ladder, and the one that determines whether anyone reaches C3 at all.
//! It is a design problem, not an implementation one, and it is not solved by
//! writing this crate.

use std::fmt;
use std::marker::PhantomData;

/// Account recovery (A1/A2: email, SMS, social re-verification).
///
/// Restores **access** to a managed account at C1/C2 only. Uninhabited — a
/// type-system tag, not a value. There is no conversion to [`KeyRecovery`].
pub enum AccountRecovery {}

/// Key recovery (guardian quorum / SSKR).
///
/// Restores **the key** at C3. Uninhabited — a type-system tag, not a value.
/// There is no conversion to [`AccountRecovery`].
pub enum KeyRecovery {}

/// Proof that an A1/A2 account-recovery check succeeded.
///
/// Restores access to a managed account at C1/C2. Carries no key material.
/// There is no conversion to [`KeyRecoveryProof`] and no API to key bytes.
///
/// ```compile_fail
/// fn account_proof_must_not_restore_key(
///     proof: identikey_recovery::AccountRecoveryProof,
/// ) -> identikey_recovery::RecoveredKey {
///     identikey_recovery::restore_key(proof)
/// }
/// ```
///
/// ```compile_fail
/// fn account_proof_must_not_become_key_bytes(
///     proof: identikey_recovery::AccountRecoveryProof,
/// ) -> Vec<u8> {
///     proof.into()
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AccountRecoveryProof {
    _kind: PhantomData<AccountRecovery>,
}

impl AccountRecoveryProof {
    /// Mark that an A1/A2 check succeeded.
    ///
    /// Email, SMS, and social verification are not implemented. This
    /// constructor exists so the access-restore path can be typed without
    /// ever mentioning a key.
    #[must_use]
    pub const fn granted() -> Self {
        Self { _kind: PhantomData }
    }
}

/// Access to a managed account at C1/C2. Not a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ManagedAccess {
    _private: (),
}

/// Restore access to a managed account. Does not yield key material.
#[must_use]
pub fn restore_access(_proof: AccountRecoveryProof) -> ManagedAccess {
    ManagedAccess { _private: () }
}

/// Proof that a C3 key-recovery reconstruction succeeded.
///
/// The only typed path to [`RecoveredKey`]. Does not accept
/// [`AccountRecoveryProof`]. Guardian quorum / SSKR issuance is not
/// implemented; [`KeyRecoveryProof::from_reconstructed_key`] is the
/// stand-in so the restore path can be typed.
pub struct KeyRecoveryProof {
    _kind: PhantomData<KeyRecovery>,
    bytes: Vec<u8>,
}

impl KeyRecoveryProof {
    /// Wrap already-reconstructed key material.
    ///
    /// This is not SSKR and does not take an [`AccountRecoveryProof`].
    #[must_use]
    pub fn from_reconstructed_key(bytes: Vec<u8>) -> Self {
        Self {
            _kind: PhantomData,
            bytes,
        }
    }
}

impl fmt::Debug for KeyRecoveryProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRecoveryProof")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// Key material produced only by [`restore_key`].
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveredKey {
    bytes: Vec<u8>,
}

impl RecoveredKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Debug for RecoveredKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredKey")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// Restore the key itself. Accepts only a [`KeyRecoveryProof`].
#[must_use]
pub fn restore_key(proof: KeyRecoveryProof) -> RecoveredKey {
    RecoveredKey { bytes: proof.bytes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_recovery_restores_access_not_a_key() {
        let proof = AccountRecoveryProof::granted();
        let access = restore_access(proof);
        assert_eq!(access, ManagedAccess { _private: () });
        // There is no proof.as_bytes(), proof.into_bytes(), or
        // restore_key(proof). The compile-fail doctests on
        // AccountRecoveryProof are the type-system check.
    }

    #[test]
    fn key_recovery_restores_key_bytes() {
        let proof = KeyRecoveryProof::from_reconstructed_key(vec![1, 2, 3]);
        let recovered = restore_key(proof);
        assert_eq!(recovered.as_bytes(), &[1, 2, 3]);
        assert_eq!(recovered.into_bytes(), vec![1, 2, 3]);
    }

    #[test]
    fn recovered_key_debug_redacts() {
        let proof = KeyRecoveryProof::from_reconstructed_key(vec![0xaa; 32]);
        let recovered = restore_key(proof);
        let shown = format!("{recovered:?}");
        assert!(shown.contains("[redacted]"));
        assert!(!shown.contains("170"));
        assert!(!shown.contains("aa"));
    }

    #[test]
    fn key_recovery_proof_debug_redacts() {
        let proof = KeyRecoveryProof::from_reconstructed_key(vec![0xaa; 32]);
        let shown = format!("{proof:?}");
        assert!(shown.contains("[redacted]"));
        assert!(!shown.contains("170"));
        assert!(!shown.contains("aa"));
    }
}
