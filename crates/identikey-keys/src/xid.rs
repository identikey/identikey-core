//! The account primary key: a XID, not a fingerprint and not a pairwise `sub`.

use std::fmt;
use std::str::FromStr;

use sha2::{Digest, Sha256};

/// 32-byte XID: SHA-256 of the CBOR encoding of the inception public signing key.
///
/// This is the canonical internal identity (ADR-001). Pairwise subject identifiers
/// (ADR-009) are a projection at the token boundary and must never appear here.
///
/// Text form is **base58btc** (encoding-conventions: short stable IDs). [`Display`]
/// and [`FromStr`] are that form. Hex is diagnostics only ([`Self::to_hex`] /
/// [`Self::from_hex`]).
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

    /// Canonical text form: base58btc of the 32 bytes.
    pub fn parse(s: &str) -> Result<Self, XidError> {
        Self::from_base58(s)
    }

    /// Human-facing encoding (encoding-conventions: short stable IDs are base58btc).
    #[must_use]
    pub fn to_base58(self) -> String {
        bs58::encode(self.as_bytes()).into_string()
    }

    /// Parse a base58btc XID (Bitcoin alphabet). Wrong alphabet or length is
    /// [`XidError::InvalidBase58`].
    pub fn from_base58(s: &str) -> Result<Self, XidError> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|_| XidError::InvalidBase58)?;
        Self::try_from_slice(&bytes).map_err(|_| XidError::InvalidBase58)
    }

    /// Diagnostic dump. Not the identifier form.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(Self::LEN * 2);
        for byte in self.as_bytes() {
            let _ = fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
        }
        out
    }

    /// Parse 64 lowercase hex characters. Diagnostics / tests only.
    pub fn from_hex(hex: &str) -> Result<Self, XidError> {
        if hex.len() != Self::LEN * 2
            || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(XidError::InvalidHex);
        }
        let mut bytes = [0u8; Self::LEN];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let slot = bytes.get_mut(i).ok_or(XidError::InvalidHex)?;
            let text = std::str::from_utf8(chunk).map_err(|_| XidError::InvalidHex)?;
            *slot = u8::from_str_radix(text, 16).map_err(|_| XidError::InvalidHex)?;
        }
        Ok(Self(bytes))
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
        f.write_str(&self.to_base58())
    }
}

impl FromStr for Xid {
    type Err = XidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XidError {
    #[error("XID must be {} bytes, got {got}", Xid::LEN)]
    InvalidLength { got: usize },
    #[error("XID hex must be 64 lowercase characters")]
    InvalidHex,
    #[error("XID must be 32 bytes of base58btc")]
    InvalidBase58,
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
    fn display_is_base58() {
        let xid = Xid::from_bytes([0xab; 32]);
        assert_eq!(xid.to_string(), xid.to_base58());
        assert_ne!(xid.to_string(), xid.to_hex());
        assert_eq!(xid.to_hex(), "ab".repeat(32));
    }

    #[test]
    fn from_hex_round_trips() {
        let xid = Xid::from_bytes([0xab; 32]);
        assert_eq!(Xid::from_hex(&xid.to_hex()).unwrap(), xid);
    }

    #[test]
    fn from_hex_rejects_uppercase_and_short() {
        assert!(matches!(
            Xid::from_hex(&"AB".repeat(32)),
            Err(XidError::InvalidHex)
        ));
        assert!(matches!(Xid::from_hex("dead"), Err(XidError::InvalidHex)));
    }

    #[test]
    fn parse_is_base58_and_rejects_hex() {
        let xid = Xid::from_bytes([0xab; 32]);
        let encoded = xid.to_string();
        assert_eq!(Xid::parse(&encoded).unwrap(), xid);
        assert_eq!(encoded.parse::<Xid>().unwrap(), xid);
        assert!(!encoded.chars().any(|c| matches!(c, '0' | 'O' | 'I' | 'l')));
        assert!(matches!(
            Xid::parse("not-a-xid"),
            Err(XidError::InvalidBase58)
        ));
        assert!(matches!(
            Xid::parse(&xid.to_hex()),
            Err(XidError::InvalidBase58)
        ));
    }
}
