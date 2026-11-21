//! Offline verification for the experimental forgejo-ci-owner-v1 profile.
//!
//! The consumer supplies the authenticated current policy, binding target and outstanding
//! challenge independently of the claimant. A successful verification checks signatures.
//! The caller must still consume the challenge exactly once against its current durable
//! state and authenticate the Forgejo administrator before installing a binding.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Deserializer, de::Error as _};
use thiserror::Error;

const APPROVAL_DOMAIN: &[u8] = b"identikey/forgejo-ci-owner/approval/v1\0";
const CONSUME_DOMAIN: &[u8] = b"identikey/forgejo-ci-owner/consume/v1\0";
const MAX_KEYS: usize = 64;

fn hex_bytes<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let value = String::deserialize(deserializer)?;
    if value.len() != N * 2 || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(D::Error::custom("expected fixed-width lowercase hex"));
    }
    let mut result = [0; N];
    hex::decode_to_slice(value, &mut result).map_err(D::Error::custom)?;
    Ok(result)
}

/// One proposed action in the context of a specific predecessor.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct Binding {
    #[serde(deserialize_with = "hex_bytes")]
    pub keyspace_id: [u8; 32],
    #[serde(deserialize_with = "hex_bytes")]
    pub guild_xid: [u8; 32],
    #[serde(deserialize_with = "hex_bytes")]
    pub predecessor: [u8; 32],
    #[serde(deserialize_with = "hex_bytes")]
    pub policy_digest: [u8; 32],
    pub seq: u64,
    pub instance: String,
    pub org_id: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    #[serde(deserialize_with = "hex_bytes")]
    pub principal: [u8; 32],
    #[serde(deserialize_with = "hex_bytes")]
    pub public_key: [u8; 32],
}

/// Independent, already authenticated consumer inputs. Never take this from the proof.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentAuthority {
    #[serde(flatten)]
    pub binding: Binding,
    pub threshold: usize,
    pub owners: Vec<Owner>,
    #[serde(deserialize_with = "hex_bytes")]
    pub witness_key: [u8; 32],
    #[serde(deserialize_with = "hex_bytes")]
    pub challenge: [u8; 32],
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    #[serde(deserialize_with = "hex_bytes")]
    pub public_key: [u8; 32],
    #[serde(deserialize_with = "hex_bytes")]
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settlement {
    #[serde(deserialize_with = "hex_bytes")]
    pub challenge: [u8; 32],
    #[serde(deserialize_with = "hex_bytes")]
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    #[serde(flatten)]
    pub binding: Binding,
    pub approvals: Vec<Approval>,
    pub settlement: Option<Settlement>,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum BindingError {
    #[error("binding differs from the expected action or current authority")]
    WrongBinding,
    #[error("invalid hostname, sequence, or organization ID")]
    InvalidAction,
    #[error("invalid authority configuration")]
    InvalidPolicy,
    #[error("approval by an unknown or repeated principal, or invalid approval signature")]
    InvalidApproval,
    #[error("approval count does not satisfy the current policy")]
    Quorum,
    #[error("missing or invalid witness consume for the outstanding challenge")]
    Settlement,
}

impl Binding {
    fn approval_bytes(&self) -> Result<Vec<u8>, BindingError> {
        let host = &self.instance;
        if self.seq == 0
            || self.org_id == 0
            || host.len() > 253
            || !host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        {
            return Err(BindingError::InvalidAction);
        }
        let mut out = APPROVAL_DOMAIN.to_vec();
        for field in [
            &self.keyspace_id,
            &self.guild_xid,
            &self.predecessor,
            &self.policy_digest,
        ] {
            out.extend_from_slice(field);
        }
        out.extend_from_slice(&self.seq.to_be_bytes());
        let len = u16::try_from(host.len()).map_err(|_| BindingError::InvalidAction)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(host.as_bytes());
        out.extend_from_slice(&self.org_id.to_be_bytes());
        Ok(out)
    }
}

fn policy_key(bytes: &[u8; 32]) -> Result<VerifyingKey, BindingError> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| BindingError::InvalidPolicy)?;
    if key.is_weak() {
        return Err(BindingError::InvalidPolicy);
    }
    Ok(key)
}

/// Verify the explicit-quorum/single-witness profile against a trusted action and policy.
/// The caller bounds input size before decoding untrusted proof JSON.
pub fn verify(authority: &CurrentAuthority, proof: &Proof) -> Result<(), BindingError> {
    if authority.binding != proof.binding {
        return Err(BindingError::WrongBinding);
    }
    let bytes = authority.binding.approval_bytes()?;
    if authority.owners.len() > MAX_KEYS || authority.threshold == 0 {
        return Err(BindingError::InvalidPolicy);
    }
    let witness = policy_key(&authority.witness_key)?;
    let mut by_key = HashMap::new();
    let mut principals = HashSet::new();
    for owner in &authority.owners {
        let key = policy_key(&owner.public_key)?;
        if by_key
            .insert(owner.public_key, (key, owner.principal))
            .is_some()
        {
            return Err(BindingError::InvalidPolicy);
        }
        principals.insert(owner.principal);
    }
    if by_key.contains_key(&authority.witness_key) || authority.threshold > principals.len() {
        return Err(BindingError::InvalidPolicy);
    }
    if proof.approvals.len() > MAX_KEYS || proof.approvals.len() < authority.threshold {
        return Err(BindingError::Quorum);
    }
    let mut signed = HashSet::new();
    for approval in &proof.approvals {
        let (key, principal) = by_key
            .get(&approval.public_key)
            .ok_or(BindingError::InvalidApproval)?;
        if !signed.insert(principal) {
            return Err(BindingError::InvalidApproval);
        }
        key.verify_strict(&bytes, &Signature::from_bytes(&approval.signature))
            .map_err(|_| BindingError::InvalidApproval)?;
    }
    let settle = proof.settlement.as_ref().ok_or(BindingError::Settlement)?;
    if settle.challenge != authority.challenge {
        return Err(BindingError::Settlement);
    }
    let mut consume = CONSUME_DOMAIN.to_vec();
    consume.extend_from_slice(&bytes);
    consume.extend_from_slice(&authority.challenge);
    witness
        .verify_strict(&consume, &Signature::from_bytes(&settle.signature))
        .map_err(|_| BindingError::Settlement)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Vectors {
        profile: String,
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        name: String,
        valid: bool,
        context: CurrentAuthority,
        proof: Proof,
        approval_bytes: String,
        consume_bytes: Option<String>,
    }

    fn cases() -> Result<Vec<Case>, serde_json::Error> {
        // Byte-for-byte copy of docs/standards/vectors/forgejo-ci-owner-v1.json
        // in identikey-protocol commit 401b4078fe82d31ee29c28512356bce99cc563c8.
        let vectors: Vectors =
            serde_json::from_str(include_str!("../tests/vectors/forgejo-ci-owner-v1.json"))?;
        assert_eq!(vectors.profile, "forgejo-ci-owner-v1");
        assert!(!vectors.cases.is_empty());
        Ok(vectors.cases)
    }

    #[test]
    fn protocol_vectors() -> Result<(), Box<dyn std::error::Error>> {
        for case in cases()? {
            let signed = case.proof.binding.approval_bytes()?;
            assert_eq!(hex::encode(&signed), case.approval_bytes, "{}", case.name);
            let consume = case.proof.settlement.as_ref().map(|settlement| {
                hex::encode([CONSUME_DOMAIN, signed.as_slice(), &settlement.challenge].concat())
            });
            assert_eq!(consume, case.consume_bytes, "{}", case.name);
            assert_eq!(
                verify(&case.context, &case.proof).is_ok(),
                case.valid,
                "{}",
                case.name
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_policy_and_untrusted_signatures() -> Result<(), Box<dyn std::error::Error>> {
        let case = cases()?
            .into_iter()
            .find(|c| c.name == "settled-quorum")
            .ok_or("missing settled-quorum vector")?;
        let mut policy = case.context.clone();
        policy.threshold = 0;
        assert_eq!(
            verify(&policy, &case.proof),
            Err(BindingError::InvalidPolicy)
        );
        let mut policy = case.context.clone();
        let duplicate = policy.owners.first().ok_or("empty fixture roster")?.clone();
        let mut shared_witness = policy.clone();
        shared_witness.witness_key = duplicate.public_key;
        assert_eq!(
            verify(&shared_witness, &case.proof),
            Err(BindingError::InvalidPolicy)
        );
        policy.owners.push(duplicate);
        assert_eq!(
            verify(&policy, &case.proof),
            Err(BindingError::InvalidPolicy)
        );

        let mut proof = case.proof.clone();
        let signer = proof.approvals.first_mut().ok_or("missing signer")?;
        signer.signature = [0u8; 64];
        assert_eq!(
            verify(&case.context, &proof),
            Err(BindingError::InvalidApproval)
        );
        let mut proof = case.proof;
        proof
            .approvals
            .first_mut()
            .ok_or("missing signer")?
            .public_key = case.context.witness_key;
        assert_eq!(
            verify(&case.context, &proof),
            Err(BindingError::InvalidApproval)
        );
        Ok(())
    }
}
