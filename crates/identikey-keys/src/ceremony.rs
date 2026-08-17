//! C2→C3 fail-closed checks (ADR-011). Persistence is [`crate::store`].

use std::collections::HashSet;
use std::net::IpAddr;

use bc_components::{PublicKeys, PublicKeysProvider, Signature, Verifier};
use bc_xid::{Privilege, XIDDocument};
use url::Url;

use bc_components::XIDProvider;
use crate::privilege::{authorize_elect, is_c2, key_allows, PrivilegeError};
use crate::rung::CustodyRung;
use crate::xid::Xid;

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
            if HELD_MUST_DROP
                .iter()
                .any(|p| key_allows(on_new, p.clone()))
            {
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

fn check_resolution(doc: &XIDDocument) -> Result<(), CeremonyError> {
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
    OPERATOR_ETLD1.iter().any(|root| host == *root || host.ends_with(&format!(".{root}")))
}

fn is_local_or_private(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v)) => v.is_loopback() || v.is_private() || v.is_link_local() || v.is_unspecified(),
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
}
