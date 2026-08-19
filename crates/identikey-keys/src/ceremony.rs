//! C2→C3 fail-closed checks (ADR-011). Persistence is [`crate::store`].
//!
//! Pre-rotation is off in v1 (`identikey-core-29v`). The 32-byte
//! `custody_records.successor_digest` column is the commitment slot.
//! A next-key digest assertion can be added to the XID document later
//! without a format version bump: `bc-xid` preserves unrecognised
//! assertions (`XIDDocument::extra_assertions`).

use std::collections::HashSet;
use std::net::IpAddr;

use bc_components::{PublicKeys, PublicKeysProvider, Signature, Verifier};
use bc_xid::{Privilege, XIDDocument};
use sha2::{Digest, Sha256};
use url::Url;

use crate::privilege::{PrivilegeError, authorize_elect, is_c2, key_allows};
use crate::rung::CustodyRung;
use crate::xid::Xid;
use bc_components::XIDProvider;

/// Length of `custody_records.successor_digest`. Matches
/// `CONSTRAINT custody_successor_digest_len CHECK (octet_length = 32)`.
pub const SUCCESSOR_DIGEST_LEN: usize = 32;

/// eTLD+1 we operate. A sibling or CNAME under these is still us.
const OPERATOR_ETLD1: [&str; 2] = ["identikey.me", "identikey.io"];

const HELD_MUST_DROP: [Privilege; 9] = [
    Privilege::Sign,
    Privilege::All,
    Privilege::Elect,
    Privilege::Transfer,
    Privilege::Verify,
    Privilege::Update,
    Privilege::Delegate,
    Privilege::Burn,
    Privilege::Revoke,
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CeremonyError {
    #[error("stored identity is not C2")]
    NotC2,
    #[error("XID in the new document does not match the stored identity")]
    XidMismatch,
    #[error("signer is not authorized to Elect")]
    ElectDenied,
    #[error("Elect signature does not verify")]
    ElectSignatureInvalid,
    #[error("signer is a key we hold")]
    SignerIsHeldKey,
    #[error("a key we hold still has Sign or management privilege")]
    HeldKeyRetainsPrivilege,
    #[error("no user-held key can Sign")]
    UserCannotSign,
    #[error("no user-held key can Elect")]
    UserCannotElect,
    #[error("no user-held key has Update")]
    UserCannotUpdate,
    #[error("resolution set is not a valid C3 exit: {0}")]
    Resolution(&'static str),
    #[error("C3 document must carry a provenance mark when C2 had none")]
    ProvenanceRequired,
    #[error("submitted document must not carry a provenance generator")]
    GeneratorNotAllowed,
    #[error("successor digest must be {SUCCESSOR_DIGEST_LEN} bytes")]
    SuccessorDigestLength,
    #[error("published successor digest does not match the local successor key")]
    SuccessorDigestMismatch,
}

/// SHA-256 of successor public-key bytes or their CBOR.
///
/// Same 32 bytes the column CHECK stores. A later next-key assertion on
/// the XID document can carry this digest without a version bump.
#[must_use]
pub fn successor_digest(local_successor_public_or_cbor: &[u8]) -> [u8; SUCCESSOR_DIGEST_LEN] {
    Sha256::digest(local_successor_public_or_cbor).into()
}

/// Accept only a 32-byte digest — the same rule as
/// `CONSTRAINT custody_successor_digest_len`.
///
/// ```
/// use identikey_keys::{parse_successor_digest, SUCCESSOR_DIGEST_LEN};
/// assert!(parse_successor_digest(&[0u8; SUCCESSOR_DIGEST_LEN]).is_ok());
/// assert!(parse_successor_digest(&[0u8; 31]).is_err());
/// assert!(parse_successor_digest(&[0u8; 33]).is_err());
/// ```
pub fn parse_successor_digest(bytes: &[u8]) -> Result<[u8; SUCCESSOR_DIGEST_LEN], CeremonyError> {
    bytes
        .try_into()
        .map_err(|_| CeremonyError::SuccessorDigestLength)
}

/// Client check before treating C2→C3 as complete (`identikey-core-4qd`).
///
/// ADR-011: the climb is Elect-gated by the user, not our key — still
/// verify a published digest when one is set. `None` skips: v1 ships
/// without pre-rotation (ADR-008).
pub fn verify_successor_digest(
    published: Option<&[u8; SUCCESSOR_DIGEST_LEN]>,
    local_successor_public_or_cbor: &[u8],
) -> Result<(), CeremonyError> {
    let Some(published) = published else {
        return Ok(());
    };
    if successor_digest(local_successor_public_or_cbor) == *published {
        Ok(())
    } else {
        Err(CeremonyError::SuccessorDigestMismatch)
    }
}

/// Sign+Auth keys on a C2 document are the keys we hold (blob is opaque).
#[must_use]
pub fn held_publics(doc: &XIDDocument) -> Vec<PublicKeys> {
    doc.keys()
        .iter()
        .filter(|key| key_allows(key, Privilege::Sign) && key_allows(key, Privilege::Auth))
        .map(|key| key.public_keys().clone())
        .collect()
}

pub fn validate_c2_to_c3(
    stored_rung: CustodyRung,
    stored: &XIDDocument,
    new_doc: &XIDDocument,
    signature: &Signature,
    signer: &impl PublicKeysProvider,
    new_bytes: &[u8],
) -> Result<(), CeremonyError> {
    if stored_rung != CustodyRung::C2 || !is_c2(stored) {
        return Err(CeremonyError::NotC2);
    }
    if Xid::from(new_doc.xid()) != Xid::from(stored.xid()) {
        return Err(CeremonyError::XidMismatch);
    }

    authorize_elect(stored, signer).map_err(|e| match e {
        PrivilegeError::ElectDenied => CeremonyError::ElectDenied,
        _ => CeremonyError::ElectDenied,
    })?;

    let held = held_publics(stored);
    let signer_pub = signer.public_keys();
    if held.iter().any(|k| k == &signer_pub) {
        return Err(CeremonyError::SignerIsHeldKey);
    }

    let Some(elect_key) = stored.find_key_by_public_keys(signer) else {
        return Err(CeremonyError::ElectDenied);
    };
    if !elect_key
        .public_keys()
        .signing_public_key()
        .verify(signature, &new_bytes)
    {
        return Err(CeremonyError::ElectSignatureInvalid);
    }

    for held_pub in &held {
        if let Some(on_new) = new_doc.find_key_by_public_keys(held_pub) {
            if HELD_MUST_DROP.iter().any(|p| key_allows(on_new, p.clone())) {
                return Err(CeremonyError::HeldKeyRetainsPrivilege);
            }
        }
    }

    let user_keys: Vec<_> = new_doc
        .keys()
        .iter()
        .filter(|key| !held.iter().any(|h| h == key.public_keys()))
        .collect();
    if !user_keys.iter().any(|k| key_allows(k, Privilege::Sign)) {
        return Err(CeremonyError::UserCannotSign);
    }
    if !user_keys.iter().any(|k| key_allows(k, Privilege::Elect)) {
        return Err(CeremonyError::UserCannotElect);
    }
    if !user_keys.iter().any(|k| key_allows(k, Privilege::Update)) {
        return Err(CeremonyError::UserCannotUpdate);
    }

    check_resolution(new_doc)?;
    check_provenance(stored, new_doc)?;
    Ok(())
}

/// C3/C4 resolver set: N≥2 distinct HTTP(S) hosts, one not-us eTLD+1.
pub fn check_resolution(doc: &XIDDocument) -> Result<(), CeremonyError> {
    let mut hosts = HashSet::new();
    let mut saw_not_ours = false;

    for method in doc.resolution_methods() {
        let Ok(url) = Url::parse(method.as_ref()) else {
            continue;
        };
        if url.scheme() != "http" && url.scheme() != "https" {
            continue;
        }
        let Some(host) = url.host_str() else {
            return Err(CeremonyError::Resolution("hostless HTTP(S) URI"));
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if is_local_or_private(&host) {
            return Err(CeremonyError::Resolution("localhost or RFC1918 resolver"));
        }
        if !is_operator_host(&host) {
            saw_not_ours = true;
        }
        hosts.insert(host);
    }

    if hosts.len() < 2 {
        return Err(CeremonyError::Resolution(
            "need N>=2 distinct HTTP(S) hosts",
        ));
    }
    if !saw_not_ours {
        return Err(CeremonyError::Resolution(
            "at least one host must be outside identikey.me / identikey.io",
        ));
    }
    Ok(())
}

fn is_operator_host(host: &str) -> bool {
    OPERATOR_ETLD1
        .iter()
        .any(|root| host == *root || host.ends_with(&format!(".{root}")))
}

fn is_local_or_private(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v)) => {
            v.is_loopback() || v.is_private() || v.is_link_local() || v.is_unspecified()
        }
        Ok(IpAddr::V6(v)) => v.is_loopback() || v.is_unspecified(),
        Err(_) => false,
    }
}

fn check_provenance(stored: &XIDDocument, new_doc: &XIDDocument) -> Result<(), CeremonyError> {
    if new_doc.provenance_generator().is_some() {
        return Err(CeremonyError::GeneratorNotAllowed);
    }
    if stored.provenance().is_none() && new_doc.provenance().is_none() {
        return Err(CeremonyError::ProvenanceRequired);
    }
    Ok(())
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
    fn operator_hosts() {
        assert!(is_operator_host("auth.identikey.me"));
        assert!(is_operator_host("identikey.io"));
        assert!(is_operator_host("app.identikey.io"));
        assert!(!is_operator_host("resolver.example"));
        assert!(!is_operator_host("identikey.com"));
    }

    #[test]
    fn local_hosts() {
        assert!(is_local_or_private("localhost"));
        assert!(is_local_or_private("127.0.0.1"));
        assert!(is_local_or_private("10.0.0.1"));
        assert!(is_local_or_private("192.168.1.1"));
        assert!(!is_local_or_private("resolver.example"));
    }

    #[test]
    fn successor_digest_column_length_is_32_bytes() {
        assert_eq!(SUCCESSOR_DIGEST_LEN, 32);
        assert!(parse_successor_digest(&[0u8; 32]).is_ok());
        assert!(matches!(
            parse_successor_digest(&[0u8; 31]),
            Err(CeremonyError::SuccessorDigestLength)
        ));
        assert!(matches!(
            parse_successor_digest(&[0u8; 33]),
            Err(CeremonyError::SuccessorDigestLength)
        ));
        assert!(matches!(
            parse_successor_digest(&[]),
            Err(CeremonyError::SuccessorDigestLength)
        ));
    }

    #[test]
    fn verify_successor_digest_match_ok() {
        let local = b"successor-public-or-cbor";
        let published = successor_digest(local);
        assert!(verify_successor_digest(Some(&published), local).is_ok());
    }

    #[test]
    fn verify_successor_digest_mismatch_err() {
        let published = successor_digest(b"generated-here");
        let err = verify_successor_digest(Some(&published), b"suggested-by-us").unwrap_err();
        assert_eq!(err, CeremonyError::SuccessorDigestMismatch);
    }

    #[test]
    fn verify_successor_digest_none_skips() {
        assert!(verify_successor_digest(None, b"anything").is_ok());
        assert!(verify_successor_digest(None, &[]).is_ok());
    }
}
