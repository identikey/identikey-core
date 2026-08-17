//! The account primary key: a XID, not a fingerprint and not a pairwise `sub`.

use std::fmt;

use sha2::{Digest, Sha256};

/// 32-byte XID: SHA-256 of the CBOR encoding of the inception public signing key.
///
/// This is the canonical internal identity (ADR-001). Pairwise subject identifiers
/// (ADR-009) are a projection at the token boundary and must never appear here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, sqlx::Type)]
#[sqlx(transparent)]
pub struct Xid(pub(crate) [u8; Xid::LEN]);

impl Xid {
    pub const LEN: usize = 32;

    /// Construct from exactly 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Construct from a slice, rejecting any other length.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, XidError> {
        let bytes: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|_| XidError::InvalidLength { got: bytes.len() })?;
        Ok(Self(bytes))
    }

    /// Derive a XID from the CBOR encoding of an inception public signing key.
    ///
    /// The caller is responsible for producing the canonical CBOR; this function
    /// only hashes. That split keeps this crate from taking a dCBOR dependency
    /// just to own the column type.
    #[must_use]
    pub fn from_inception_cbor(cbor: &[u8]) -> Self {
        let digest = Sha256::digest(cbor);
        let mut bytes = [0u8; Self::LEN];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl From<bc_components::XID> for Xid {
    fn from(value: bc_components::XID) -> Self {
        Self::from_bytes(*value.data())
    }
}

impl AsRef<[u8]> for Xid {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Xid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XidError {
    #[error("XID must be {} bytes, got {got}", Xid::LEN)]
    InvalidLength { got: usize },
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_length() {
        assert!(matches!(
            Xid::try_from_slice(&[0u8; 16]),
            Err(XidError::InvalidLength { got: 16 })
        ));
    }

    #[test]
    fn from_inception_cbor_is_sha256() {
        let xid = Xid::from_inception_cbor(b"not-real-cbor");
        let expected = Sha256::digest(b"not-real-cbor");
        assert_eq!(xid.as_bytes().as_slice(), expected.as_slice());
    }

    #[test]
    fn display_is_hex() {
        let xid = Xid::from_bytes([0xab; 32]);
        assert_eq!(xid.to_string(), "ab".repeat(32));
    }
}
