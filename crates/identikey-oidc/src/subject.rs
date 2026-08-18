//! The only place a token `sub` is computed (ADR-009).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use identikey_keys::Xid;
use sha2::Sha256;

use crate::salt::PairwiseSalt;

const INFO_PREFIX: &[u8] = b"identikey-oidc-sub-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubjectType {
    #[default]
    Pairwise,
    Public,
}

/// Registered client. New clients default to pairwise.
#[derive(Debug, Clone)]
pub struct Client {
    pub id: String,
    pub subject_type: SubjectType,
    pub sector_identifier: String,
    pub redirect_uris: Vec<String>,
}

impl Client {
    #[must_use]
    pub fn new(id: impl Into<String>, sector_identifier: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            subject_type: SubjectType::Pairwise,
            sector_identifier: sector_identifier.into(),
            redirect_uris: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_redirect(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uris.push(uri.into());
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SubjectError {
    #[error("HKDF expand failed")]
    Hkdf,
}

/// One seam. Pairwise is HKDF-SHA-256 as in `docs/oidc-implementation-checklist.md`.
pub fn subject(salt: &PairwiseSalt, xid: Xid, client: &Client) -> Result<String, SubjectError> {
    match client.subject_type {
        SubjectType::Public => Ok(xid.to_string()),
        SubjectType::Pairwise => {
            let hk =
                Hkdf::<Sha256>::new(Some(client.sector_identifier.as_bytes()), salt.as_bytes());
            let mut info = Vec::with_capacity(INFO_PREFIX.len() + Xid::LEN);
            info.extend_from_slice(INFO_PREFIX);
            info.extend_from_slice(xid.as_bytes());
            let mut out = [0u8; 32];
            hk.expand(&info, &mut out).map_err(|_| SubjectError::Hkdf)?;
            Ok(URL_SAFE_NO_PAD.encode(out))
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;

    fn salt() -> PairwiseSalt {
        let hex = "ab".repeat(32);
        PairwiseSalt::from_hex(&hex).unwrap()
    }

    fn xid() -> Xid {
        Xid::from_bytes([0x11; 32])
    }

    #[test]
    fn new_client_defaults_pairwise() {
        let client = Client::new("smoke", "127.0.0.1");
        assert_eq!(client.subject_type, SubjectType::Pairwise);
    }

    #[test]
    fn two_sectors_differ() {
        let a = Client::new("a", "rp-one.example");
        let b = Client::new("b", "rp-two.example");
        let sa = subject(&salt(), xid(), &a).unwrap();
        let sb = subject(&salt(), xid(), &b).unwrap();
        assert_ne!(sa, sb);
        assert_ne!(sa, xid().to_string());
        assert_ne!(sb, xid().to_string());
    }

    #[test]
    fn same_sector_is_stable() {
        let client = Client::new("smoke", "127.0.0.1");
        let first = subject(&salt(), xid(), &client).unwrap();
        let second = subject(&salt(), xid(), &client).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn public_is_the_xid() {
        let mut client = Client::new("disclosed", "stack.example");
        client.subject_type = SubjectType::Public;
        assert_eq!(subject(&salt(), xid(), &client).unwrap(), xid().to_string());
        assert_eq!(xid().to_string().len(), 64);
    }
}
