//! Exit payload for pairwise `sub` (ADR-009 action 4).

use std::fmt;

use identikey_keys::Xid;

use crate::salt::PairwiseSalt;
use crate::subject::{Client, subject};

/// What a successor OP needs to recompute every pairwise `sub`.
///
/// `Debug` redacts the salt. Callers that print this must not log
/// [`PairwiseExport::salt_hex`]. `xid` is the canonical base58btc text form.
#[derive(Clone)]
pub struct PairwiseExport {
    pub xid: String,
    pub salt_hex: String,
    pub kdf: &'static str,
}

impl PairwiseExport {
    #[must_use]
    pub fn for_xid(salt: &PairwiseSalt, xid: Xid) -> Self {
        Self {
            xid: xid.to_string(),
            salt_hex: salt.export_hex(),
            kdf: "HKDF-SHA-256",
        }
    }

    pub fn salt(&self) -> Result<PairwiseSalt, crate::SaltError> {
        PairwiseSalt::from_hex(&self.salt_hex)
    }

    pub fn xid(&self) -> Result<Xid, identikey_keys::XidError> {
        Xid::parse(&self.xid)
    }

    /// Recompute `sub` the way a successor OP must.
    pub fn subject(&self, client: &Client) -> Result<String, crate::SubjectError> {
        let salt = self.salt().map_err(|_| crate::SubjectError::Hkdf)?;
        let xid = self.xid().map_err(|_| crate::SubjectError::Hkdf)?;
        subject(&salt, xid, client)
    }
}

impl fmt::Debug for PairwiseExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairwiseExport")
            .field("xid", &self.xid)
            .field("salt_hex", &"[redacted]")
            .field("kdf", &self.kdf)
            .finish()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;
    use crate::subject;

    fn salt() -> PairwiseSalt {
        PairwiseSalt::from_hex(&"cd".repeat(32)).unwrap()
    }

    fn xid() -> Xid {
        Xid::from_bytes([0x44; 32])
    }

    #[test]
    fn export_reproduces_issued_sub() {
        let client = Client::new("rp", "rp.example");
        let issued = subject(&salt(), xid(), &client).unwrap();
        let export = PairwiseExport::for_xid(&salt(), xid());
        assert_eq!(export.kdf, "HKDF-SHA-256");
        assert_eq!(export.subject(&client).unwrap(), issued);
        let other = Client::new("other", "other.example");
        assert_ne!(export.subject(&other).unwrap(), issued);
    }

    #[test]
    fn debug_does_not_print_salt() {
        let export = PairwiseExport::for_xid(&salt(), xid());
        let shown = format!("{export:?}");
        assert!(shown.contains("[redacted]"));
        assert!(!shown.contains(&export.salt_hex));
        assert!(!shown.contains(&salt().export_hex()));
    }
}
