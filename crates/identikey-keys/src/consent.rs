//! C2 consent-log hashing.
//!
//! Postgres stores the chain (`seq`, `prev_hash`, `entry_hash`) and refuses
//! UPDATE/DELETE. The hash itself is computed here so we do not take a
//! `pgcrypto` dependency and so the encoding is one function, not a SQL
//! expression that will drift.
//!
//! The proof that goes in the log is an *access* credential (WebAuthn
//! assertion or `identikey-auth` Response). Hashing a signature we produced
//! with the managed Sign key would make C2 self-certifying theatre.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::rung::AccessLevel;
use crate::xid::Xid;

/// Version byte for [`hash_consent_entry`]. Bump when the encoding changes;
/// existing rows keep the hash they were stored with.
pub const CONSENT_HASH_V1: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum ProofKind {
    WebauthnAssertion,
    IdentikeyAuthResponse,
    Password,
    EmailLink,
    SmsOtp,
    OidcAssertion,
}

impl ProofKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WebauthnAssertion => "webauthn_assertion",
            Self::IdentikeyAuthResponse => "identikey_auth_response",
            Self::Password => "password",
            Self::EmailLink => "email_link",
            Self::SmsOtp => "sms_otp",
            Self::OidcAssertion => "oidc_assertion",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum ConsentResult {
    Signed,
    Refused,
    Error,
}

impl ConsentResult {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::Refused => "refused",
            Self::Error => "error",
        }
    }
}

/// Inputs committed by a consent-log entry. Display-only fields (`purpose`)
/// are included so they cannot be rewritten independently of the hash —
/// the table is append-only either way, but the chain should describe the
/// row the user will actually see.
#[derive(Clone, Debug)]
pub struct ConsentHashInput<'a> {
    pub xid: Xid,
    pub seq: u64,
    pub prev_hash: Option<[u8; 32]>,
    pub action: &'a str,
    pub audience: Option<&'a str>,
    pub purpose: Option<&'a str>,
    pub access_level: AccessLevel,
    pub credential_id: Option<Uuid>,
    pub proof_kind: ProofKind,
    pub proof_hash: [u8; 32],
    pub result: ConsentResult,
}

/// SHA-256 of `proof_bytes`. Stored beside the bytes so the chain commits
/// to the proof without feeding a multi-kilobyte assertion through the
/// entry encoding twice.
#[must_use]
pub fn hash_proof(proof_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(proof_bytes).into()
}

/// Canonical v1 encoding, length-prefixed, no JSON.
///
/// ```text
/// u8  version = 1
/// 32  xid
/// u64 seq (BE)
/// 32  prev_hash (zeroes if first)
/// u16 action_len + action
/// u16 audience_len + audience
/// u16 purpose_len + purpose
/// u8  access_level tag ('0'..'4')
/// 16  credential_id (zeroes if none)
/// u8  proof_kind tag
/// 32  proof_hash
/// u8  result tag
/// ```
#[must_use]
pub fn hash_consent_entry(input: &ConsentHashInput<'_>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([CONSENT_HASH_V1]);
    h.update(input.xid.as_bytes());
    h.update(input.seq.to_be_bytes());
    h.update(input.prev_hash.unwrap_or([0u8; 32]));
    write_lp(&mut h, input.action.as_bytes());
    write_lp(&mut h, input.audience.unwrap_or("").as_bytes());
    write_lp(&mut h, input.purpose.unwrap_or("").as_bytes());
    h.update([access_tag(input.access_level)]);
    h.update(input.credential_id.unwrap_or(Uuid::nil()).as_bytes());
    h.update([proof_tag(input.proof_kind)]);
    h.update(input.proof_hash);
    h.update([result_tag(input.result)]);
    h.finalize().into()
}

fn write_lp(h: &mut Sha256, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    h.update(len.to_be_bytes());
    let take = usize::from(len);
    if let Some(slice) = bytes.get(..take) {
        h.update(slice);
    }
}

const fn access_tag(level: AccessLevel) -> u8 {
    match level {
        AccessLevel::A0 => b'0',
        AccessLevel::A1 => b'1',
        AccessLevel::A2 => b'2',
        AccessLevel::A3 => b'3',
        AccessLevel::A4 => b'4',
    }
}

const fn proof_tag(kind: ProofKind) -> u8 {
    match kind {
        ProofKind::WebauthnAssertion => 1,
        ProofKind::IdentikeyAuthResponse => 2,
        ProofKind::Password => 3,
        ProofKind::EmailLink => 4,
        ProofKind::SmsOtp => 5,
        ProofKind::OidcAssertion => 6,
    }
}

const fn result_tag(result: ConsentResult) -> u8 {
    match result {
        ConsentResult::Signed => 1,
        ConsentResult::Refused => 2,
        ConsentResult::Error => 3,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;

    fn sample(prev: Option<[u8; 32]>) -> ConsentHashInput<'static> {
        ConsentHashInput {
            xid: Xid::from_bytes([0x11; 32]),
            seq: 1,
            prev_hash: prev,
            action: "sign",
            audience: Some("https://rp.example"),
            purpose: Some("login"),
            access_level: AccessLevel::A3,
            credential_id: None,
            proof_kind: ProofKind::WebauthnAssertion,
            proof_hash: [0x22; 32],
            result: ConsentResult::Signed,
        }
    }

    #[test]
    fn deterministic() {
        let a = hash_consent_entry(&sample(None));
        let b = hash_consent_entry(&sample(None));
        assert_eq!(a, b);
    }

    #[test]
    fn prev_hash_changes_entry() {
        let a = hash_consent_entry(&sample(None));
        let b = hash_consent_entry(&sample(Some([0x33; 32])));
        assert_ne!(a, b);
    }

    #[test]
    fn action_is_committed() {
        let mut other = sample(None);
        other.action = "export";
        assert_ne!(
            hash_consent_entry(&sample(None)),
            hash_consent_entry(&other)
        );
    }
}
