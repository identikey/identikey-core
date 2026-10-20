//! The only place a token `sub` is computed (ADR-009).

use std::fmt;

use hkdf::Hkdf;
use identikey_keys::Xid;
use sha2::{Digest, Sha256};

use crate::salt::PairwiseSalt;

const INFO_PREFIX: &[u8] = b"identikey-oidc-sub-v1\0";

/// Grants a client receives when its registration does not list any.
pub const GRANT_AUTHORIZATION_CODE: &str = "authorization_code";
pub const GRANT_REFRESH_TOKEN: &str = "refresh_token";
/// RFC 8628. Opt-in. A client without this grant cannot start or redeem a device code.
pub const GRANT_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// identikey-auth Response grant. Opt-in. Same string as [`crate::CHALLENGE_RESPONSE_GRANT`].
pub const GRANT_CHALLENGE_RESPONSE: &str =
    "urn:identikey:params:oauth:grant-type:challenge-response";

pub const KNOWN_GRANTS: &[&str] = &[
    GRANT_AUTHORIZATION_CODE,
    GRANT_REFRESH_TOKEN,
    GRANT_DEVICE_CODE,
    GRANT_CHALLENGE_RESPONSE,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubjectType {
    #[default]
    Pairwise,
    Public,
}

impl SubjectType {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "public" => Ok(Self::Public),
            "pairwise" => Ok(Self::Pairwise),
            other => Err(format!("unknown subject_type {other}")),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Pairwise => "pairwise",
        }
    }
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
    pub display_name: String,
    pub subject_type: SubjectType,
    pub sector_identifier: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    secret_hash: Option<[u8; 32]>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field("subject_type", &self.subject_type)
            .field("sector_identifier", &self.sector_identifier)
            .field("redirect_uris", &self.redirect_uris)
            .field("grant_types", &self.grant_types)
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
        let id = id.into();
        Self {
            display_name: id.clone(),
            id,
            subject_type: SubjectType::Pairwise,
            sector_identifier: sector_identifier.into(),
            redirect_uris: Vec::new(),
            grant_types: vec![GRANT_AUTHORIZATION_CODE.into(), GRANT_REFRESH_TOKEN.into()],
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
            secret_hash: None,
        }
    }

    #[must_use]
    pub fn with_redirect(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uris.push(uri.into());
        self
    }

    #[must_use]
    pub fn with_subject_type(mut self, subject_type: SubjectType) -> Self {
        self.subject_type = subject_type;
        self
    }

    #[must_use]
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    /// Replace the default grant set. Use this for a device-only client.
    #[must_use]
    pub fn with_grants(mut self, grants: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.grant_types = grants.into_iter().map(Into::into).collect();
        self
    }

    /// Add one grant to the default set.
    #[must_use]
    pub fn with_grant(mut self, grant: impl Into<String>) -> Self {
        let grant = grant.into();
        if !self.grant_types.iter().any(|existing| existing == &grant) {
            self.grant_types.push(grant);
        }
        self
    }

    #[must_use]
    pub fn allows_grant(&self, grant: &str) -> bool {
        self.grant_types.iter().any(|existing| existing == grant)
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
            Ok(bs58::encode(out).into_string())
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
        assert!(client.allows_grant(GRANT_AUTHORIZATION_CODE));
        assert!(client.allows_grant(GRANT_REFRESH_TOKEN));
        assert!(!client.allows_grant(GRANT_DEVICE_CODE));
        assert_eq!(client.display_name, "smoke");
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
        assert_eq!(bs58::decode(&sa).into_vec().unwrap().len(), 32);
        assert!(
            !sa.chars()
                .any(|c| matches!(c, '0' | 'O' | 'I' | 'l' | '-' | '_'))
        );
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
        let client =
            Client::new("disclosed", "stack.example").with_subject_type(SubjectType::Public);
        assert_eq!(subject(&salt(), xid(), &client).unwrap(), xid().to_string());
        assert_ne!(xid().to_string(), xid().to_hex());
    }

    #[test]
    fn parse_subject_type() {
        assert_eq!(SubjectType::parse("public").unwrap(), SubjectType::Public);
        assert_eq!(
            SubjectType::parse("pairwise").unwrap(),
            SubjectType::Pairwise
        );
        assert!(SubjectType::parse("pairwise_legacy").is_err());
    }
}
