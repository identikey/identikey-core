//! The only place a token `sub` is computed (ADR-009).

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use identikey_keys::Xid;
use sha2::{Digest, Sha256};

use crate::salt::PairwiseSalt;

const INFO_PREFIX: &[u8] = b"identikey-oidc-sub-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubjectType {
    #[default]
    Pairwise,
    Public,
}

/// How this client authenticates at `/token` (RFC 6749 §2.3, RFC 7591).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TokenEndpointAuthMethod {
    #[default]
    None,
    ClientSecretBasic,
    ClientSecretPost,
}

impl TokenEndpointAuthMethod {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "none" => Ok(Self::None),
            "client_secret_basic" => Ok(Self::ClientSecretBasic),
            "client_secret_post" => Ok(Self::ClientSecretPost),
            other => Err(format!("unknown token_endpoint_auth_method {other}")),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
        }
    }

    #[must_use]
    pub const fn is_confidential(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Registered client. New clients default to pairwise and `none`.
#[derive(Clone)]
pub struct Client {
    pub id: String,
    pub subject_type: SubjectType,
    pub sector_identifier: String,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    secret_hash: Option<[u8; 32]>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("id", &self.id)
            .field("subject_type", &self.subject_type)
            .field("sector_identifier", &self.sector_identifier)
            .field("redirect_uris", &self.redirect_uris)
            .field(
                "token_endpoint_auth_method",
                &self.token_endpoint_auth_method,
            )
            .field(
                "secret_hash",
                &self.secret_hash.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl Client {
    #[must_use]
    pub fn new(id: impl Into<String>, sector_identifier: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            subject_type: SubjectType::Pairwise,
            sector_identifier: sector_identifier.into(),
            redirect_uris: Vec::new(),
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
            secret_hash: None,
        }
    }

    #[must_use]
    pub fn with_redirect(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uris.push(uri.into());
        self
    }

    /// Hash `secret` (SHA-256) and remember only the digest.
    #[must_use]
    pub fn with_secret(mut self, method: TokenEndpointAuthMethod, secret: &str) -> Self {
        self.token_endpoint_auth_method = method;
        self.secret_hash = Some(hash_client_secret(secret));
        self
    }

    pub(crate) fn secret_hash(&self) -> Option<[u8; 32]> {
        self.secret_hash
    }
}

pub(crate) fn hash_client_secret(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
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
        assert_eq!(
            client.token_endpoint_auth_method,
            TokenEndpointAuthMethod::None
        );
        assert!(client.secret_hash().is_none());
    }

    #[test]
    fn secret_is_hashed_and_debug_redacts() {
        let client = Client::new("basic-1", "127.0.0.1")
            .with_secret(TokenEndpointAuthMethod::ClientSecretBasic, "s3cret");
        assert_eq!(client.secret_hash(), Some(hash_client_secret("s3cret")));
        let debug = format!("{client:?}");
        assert!(
            !debug.contains("s3cret"),
            "Debug leaked the secret: {debug}"
        );
        assert!(debug.contains("[redacted]"));
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
