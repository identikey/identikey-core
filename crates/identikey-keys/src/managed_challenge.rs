//! Consent-gated, one-shot signing for C2 managed operational keys.

use std::collections::HashMap;

use bc_components::{
    Ed25519PrivateKey, EncapsulationPublicKey, PublicKeys, SigningPublicKey, X25519PrivateKey,
};
use bc_xid::{Privilege, XIDDocument};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use identikey_auth::{
    Challenge, ClassicalAlg, ClassicalPublicKey, Response as AuthResponse, Signer, SoftwareSigner,
    signing_payload, verify_classical,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::consent::{ConsentResult, ProofKind};
use crate::privilege::{is_c2, key_allows};
use crate::rung::{AccessLevel, CustodyRung};
use crate::store::{ConsentAppend, KeysStore, append_consent_tx};
use crate::xid::Xid;

const ENVELOPE_MAGIC: &[u8; 4] = b"IKMK";
const ENVELOPE_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const SEED_LEN: usize = 32;
const MAX_CHALLENGE_LEN: usize = 8 * 1024;
const MAX_CHALLENGE_TTL: u64 = 10 * 60;
const CLOCK_SKEW: u64 = 2 * 60;
const CONSENT_TTL: u64 = 5 * 60;
const CONSENT_DOMAIN: &[u8] = b"identikey-managed-consent-v1\n";
const AUTHORIZED_ACTION: &str = "signing_instruction_authorized";
const COMPLETED_ACTION: &str = "signing_completed";
const FAILED_ACTION: &str = "signing_failed";

#[derive(Debug, thiserror::Error)]
pub enum ManagedChallengeError {
    #[error("challenge is malformed or noncanonical")]
    NonCanonicalChallenge,
    #[error("challenge is not admissible: {0}")]
    ChallengeAdmission(&'static str),
    #[error("managed key envelope is malformed or cannot be opened")]
    BadEnvelope,
    #[error("managed wrapping key is unavailable")]
    MissingWrappingKey,
    #[error("managed key does not match the current operational public key")]
    OperationalKeyMismatch,
    #[error("account is not current C2 custody")]
    NotC2,
    #[error("managed challenge attempt was not found")]
    NotFound,
    #[error("managed challenge was already begun")]
    Replay,
    #[error("managed challenge proof is invalid")]
    InvalidProof,
    #[error("managed challenge consent has expired")]
    Expired,
    #[error("managed challenge state does not permit this operation")]
    InvalidState,
    #[error("managed challenge key use has already been claimed")]
    AlreadyClaimed,
    #[error("managed challenge outcome is indeterminate")]
    Indeterminate,
    #[error("PKCE verifier does not match this attempt")]
    VerifierMismatch,
    #[error("database: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("stored document: {0}")]
    Document(String),
    #[error("protocol: {0}")]
    Protocol(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedChallengeState {
    Authorized,
    Claimed,
    Completed,
    Failed,
    Indeterminate,
}

impl ManagedChallengeState {
    fn parse(value: &str) -> Result<Self, ManagedChallengeError> {
        match value {
            "authorized" => Ok(Self::Authorized),
            "claimed" => Ok(Self::Claimed),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "indeterminate" => Ok(Self::Indeterminate),
            _ => Err(ManagedChallengeError::InvalidState),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedChallengeProof {
    A3,
    A4,
}

impl ManagedChallengeProof {
    fn as_str(self) -> &'static str {
        match self {
            Self::A3 => "a3",
            Self::A4 => "a4",
        }
    }
}

/// Immutable, validated inputs to the edge session bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSessionBind {
    pub session_public_key: ClassicalPublicKey,
    pub operation: Vec<String>,
    pub resource: Vec<String>,
    pub channel: Vec<u8>,
}

impl ManagedSessionBind {
    pub fn validate(&self) -> Result<(), ManagedChallengeError> {
        if self.session_public_key.alg != ClassicalAlg::Ed25519
            || self.session_public_key.bytes.len() != 32
            || self.channel.len() != 32
        {
            return Err(ManagedChallengeError::InvalidProof);
        }
        for tuple in [&self.operation, &self.resource] {
            if tuple.is_empty()
                || tuple.len() > 8
                || tuple.iter().any(|component| {
                    component.is_empty()
                        || component.len() > 64
                        || !component.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
                })
            {
                return Err(ManagedChallengeError::InvalidProof);
            }
        }
        Ok(())
    }

    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, ManagedChallengeError> {
        let required = |name| -> Result<Vec<u8>, ManagedChallengeError> {
            row.try_get::<Option<Vec<u8>>, _>(name)?
                .ok_or(ManagedChallengeError::InvalidProof)
        };
        let key = required("session_public_key")?;
        let cbor =
            dcbor::CBOR::try_from_data(&key).map_err(|_| ManagedChallengeError::InvalidProof)?;
        let map = match cbor.as_case() {
            dcbor::CBORCase::Map(map) => map,
            _ => return Err(ManagedChallengeError::InvalidProof),
        };
        let alg: String = map
            .extract("alg")
            .map_err(|_| ManagedChallengeError::InvalidProof)?;
        let bytes: dcbor::ByteString = map
            .extract("key")
            .map_err(|_| ManagedChallengeError::InvalidProof)?;
        let bind = Self {
            session_public_key: ClassicalPublicKey {
                alg: ClassicalAlg::Ed25519,
                bytes: bytes.to_vec(),
            },
            operation: row
                .try_get::<Option<Vec<String>>, _>("operation")?
                .ok_or(ManagedChallengeError::InvalidProof)?,
            resource: row
                .try_get::<Option<Vec<String>>, _>("resource")?
                .ok_or(ManagedChallengeError::InvalidProof)?,
            channel: required("channel")?,
        };
        bind.validate()?;
        if alg != "ed25519" || bind.session_public_key.to_value().to_bytes() != key {
            return Err(ManagedChallengeError::InvalidProof);
        }
        Ok(bind)
    }
}

/// Port of Mjolnir 696fb00 bind_signing_bytes; pinned by the joint vector.
#[must_use]
pub fn bind_signing_bytes(challenge: &[u8], bind: &ManagedSessionBind) -> Vec<u8> {
    use dcbor::prelude::*;
    let mut map = Map::new();
    map.insert("alg", bind.session_public_key.alg.tag());
    map.insert("key", CBOR::to_byte_string(&bind.session_public_key.bytes));
    let values: Vec<CBOR> = vec![
        "identikey-mjolnir/v1".into(),
        "bind".into(),
        CBOR::to_byte_string(challenge),
        map.into(),
        bind.operation.clone().into(),
        bind.resource.clone().into(),
        CBOR::to_byte_string(&bind.channel),
    ];
    CBOR::from(values).to_cbor_data()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedManagedChallenge {
    pub response: Vec<u8>,
    pub bind: Vec<u8>,
    pub fields: ManagedSessionBind,
}

#[derive(Debug, Clone)]
pub struct BeginManagedChallenge {
    pub request_id: Uuid,
    pub consent_challenge: Vec<u8>,
    pub consent_iat: u64,
    pub consent_exp: u64,
    pub bind: ManagedSessionBind,
}

#[derive(Debug, Clone)]
pub struct A3Authorization<'a> {
    pub credential_id: Uuid,
    pub proof_bytes: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetrievedManagedChallenge {
    Completed(CompletedManagedChallenge),
    Failed,
    Indeterminate,
    Pending,
}

/// A generated Ed25519 seed plus the complete public-key tuple required by XID.
pub struct OperationalEd25519 {
    seed: [u8; SEED_LEN],
    public_keys: PublicKeys,
}

impl OperationalEd25519 {
    #[must_use]
    pub fn generate() -> Self {
        let private = Ed25519PrivateKey::new();
        let seed = *private.data();
        let signing = SigningPublicKey::from_ed25519(private.public_key());
        // XID keys carry a signing and an encapsulation public. This random
        // operational encapsulation private is deliberately discarded: the
        // user's distinct Elect/X25519 key remains the C2 wrap target.
        let encapsulation = EncapsulationPublicKey::X25519(X25519PrivateKey::new().public_key());
        Self {
            seed,
            public_keys: PublicKeys::new(signing, encapsulation),
        }
    }

    #[must_use]
    pub fn public_keys(&self) -> &PublicKeys {
        &self.public_keys
    }

    #[must_use]
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }
}

impl Drop for OperationalEd25519 {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

pub struct ManagedKeyring {
    active_kid: String,
    keys: HashMap<String, [u8; 32]>,
}

impl Drop for ManagedKeyring {
    fn drop(&mut self) {
        for key in self.keys.values_mut() {
            key.zeroize();
        }
    }
}

impl ManagedKeyring {
    #[must_use]
    pub fn single(kid: impl Into<String>, key: [u8; 32]) -> Self {
        let active_kid = kid.into();
        let mut keys = HashMap::new();
        keys.insert(active_kid.clone(), key);
        Self { active_kid, keys }
    }

    pub fn insert(&mut self, kid: impl Into<String>, key: [u8; 32]) {
        self.keys.insert(kid.into(), key);
    }

    pub fn seal(
        &self,
        xid: Xid,
        operational_public: &[u8; 32],
        seed: &[u8; SEED_LEN],
    ) -> Result<Vec<u8>, ManagedChallengeError> {
        let key = self
            .keys
            .get(&self.active_kid)
            .ok_or(ManagedChallengeError::MissingWrappingKey)?;
        let kid = self.active_kid.as_bytes();
        let kid_len = u8::try_from(kid.len()).map_err(|_| ManagedChallengeError::BadEnvelope)?;
        if kid.is_empty() {
            return Err(ManagedChallengeError::BadEnvelope);
        }
        let mut nonce = [0_u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = envelope_aad(xid, operational_public);
        let cipher = XChaCha20Poly1305::new(key.into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: seed,
                    aad: &aad,
                },
            )
            .map_err(|_| ManagedChallengeError::BadEnvelope)?;
        let mut out = Vec::with_capacity(6 + kid.len() + nonce.len() + ciphertext.len());
        out.extend_from_slice(ENVELOPE_MAGIC);
        out.push(ENVELOPE_VERSION);
        out.push(kid_len);
        out.extend_from_slice(kid);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn open(
        &self,
        envelope: &[u8],
        xid: Xid,
        operational_public: &[u8; 32],
    ) -> Result<SoftwareSigner, ManagedChallengeError> {
        let parsed = ManagedKeyEnvelope::parse(envelope)?;
        let key = self
            .keys
            .get(parsed.kid)
            .ok_or(ManagedChallengeError::MissingWrappingKey)?;
        let cipher = XChaCha20Poly1305::new(key.into());
        let aad = envelope_aad(xid, operational_public);
        let mut plaintext = cipher
            .decrypt(
                XNonce::from_slice(parsed.nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| ManagedChallengeError::BadEnvelope)?;
        let mut seed: [u8; SEED_LEN] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| ManagedChallengeError::BadEnvelope)?;
        let signer = SoftwareSigner::from_ed25519_seed(seed);
        seed.zeroize();
        plaintext.zeroize();
        let public = signer.classical_public_key();
        if public.alg != ClassicalAlg::Ed25519 || public.bytes.as_slice() != operational_public {
            return Err(ManagedChallengeError::OperationalKeyMismatch);
        }
        Ok(signer)
    }
}

pub struct ManagedKeyEnvelope<'a> {
    pub kid: &'a str,
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
}

impl<'a> ManagedKeyEnvelope<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ManagedChallengeError> {
        if bytes.len() < 6 + NONCE_LEN + SEED_LEN + 16
            || bytes.get(..4) != Some(ENVELOPE_MAGIC.as_slice())
            || bytes.get(4) != Some(&ENVELOPE_VERSION)
        {
            return Err(ManagedChallengeError::BadEnvelope);
        }
        let kid_len = usize::from(*bytes.get(5).ok_or(ManagedChallengeError::BadEnvelope)?);
        if kid_len == 0 {
            return Err(ManagedChallengeError::BadEnvelope);
        }
        let kid_start = 6;
        let nonce_start = kid_start + kid_len;
        let ciphertext_start = nonce_start + NONCE_LEN;
        let kid = std::str::from_utf8(
            bytes
                .get(kid_start..nonce_start)
                .ok_or(ManagedChallengeError::BadEnvelope)?,
        )
        .map_err(|_| ManagedChallengeError::BadEnvelope)?;
        let nonce = bytes
            .get(nonce_start..ciphertext_start)
            .ok_or(ManagedChallengeError::BadEnvelope)?;
        let ciphertext = bytes
            .get(ciphertext_start..)
            .ok_or(ManagedChallengeError::BadEnvelope)?;
        if ciphertext.len() != SEED_LEN + 16 {
            return Err(ManagedChallengeError::BadEnvelope);
        }
        Ok(Self {
            kid,
            nonce,
            ciphertext,
        })
    }
}

fn envelope_aad(xid: Xid, public: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(22 + 32 + 32);
    aad.extend_from_slice(b"identikey-managed-key-v1\n");
    aad.extend_from_slice(xid.as_bytes());
    aad.extend_from_slice(public);
    aad
}

pub struct ChallengeAdmission {
    pub challenge: Challenge,
    pub digest: [u8; 32],
}

impl ChallengeAdmission {
    pub fn parse(bytes: &[u8], now: u64) -> Result<Self, ManagedChallengeError> {
        if bytes.len() > MAX_CHALLENGE_LEN {
            return Err(ManagedChallengeError::ChallengeAdmission(
                "body exceeds 8 KiB",
            ));
        }
        let challenge = Challenge::from_bytes(bytes)
            .map_err(|_| ManagedChallengeError::NonCanonicalChallenge)?;
        if challenge.to_bytes() != bytes {
            return Err(ManagedChallengeError::NonCanonicalChallenge);
        }
        if challenge.version != 1 {
            return Err(ManagedChallengeError::ChallengeAdmission(
                "version is not v1",
            ));
        }
        if !(16..=64).contains(&challenge.nonce.len()) {
            return Err(ManagedChallengeError::ChallengeAdmission("nonce length"));
        }
        if !is_canonical_edge_xid(&challenge.audience) {
            return Err(ManagedChallengeError::ChallengeAdmission("audience format"));
        }
        let ttl = challenge
            .expires_at
            .checked_sub(challenge.issued_at)
            .ok_or(ManagedChallengeError::ChallengeAdmission(
                "expiry precedes issue",
            ))?;
        if ttl > MAX_CHALLENGE_TTL {
            return Err(ManagedChallengeError::ChallengeAdmission(
                "TTL exceeds ten minutes",
            ));
        }
        if challenge.issued_at > now.saturating_add(CLOCK_SKEW)
            || challenge.expires_at.saturating_add(CLOCK_SKEW) < now
        {
            return Err(ManagedChallengeError::ChallengeAdmission(
                "outside clock skew",
            ));
        }
        Ok(Self {
            challenge,
            digest: Sha256::digest(bytes).into(),
        })
    }
}

fn is_canonical_edge_xid(value: &str) -> bool {
    bs58::decode(value)
        .into_vec()
        .is_ok_and(|bytes| bytes.len() == 32 && bs58::encode(bytes).into_string() == value)
}

#[must_use]
pub fn verifier_commitment(verifier: &str) -> [u8; 32] {
    Sha256::digest(verifier.as_bytes()).into()
}

#[must_use]
pub fn consent_digest(
    xid: Xid,
    request_id: Uuid,
    challenge: &[u8],
    commitment: &[u8; 32],
    iat: u64,
    bind: &ManagedSessionBind,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CONSENT_DOMAIN);
    hash.update(xid.as_bytes());
    hash.update(request_id.as_bytes());
    let len = u32::try_from(challenge.len()).unwrap_or(u32::MAX);
    hash.update(len.to_be_bytes());
    hash.update(challenge);
    hash.update(commitment);
    hash.update(iat.to_be_bytes());
    hash.update(bind.session_public_key.to_value().to_bytes());
    for tuple in [&bind.operation, &bind.resource] {
        hash.update((tuple.len() as u32).to_be_bytes());
        for component in tuple {
            hash.update((component.len() as u32).to_be_bytes());
            hash.update(component.as_bytes());
        }
    }
    hash.update(&bind.channel);
    hash.finalize().into()
}

fn consent_challenge(
    xid: Xid,
    request_id: Uuid,
    challenge: &[u8],
    commitment: &[u8; 32],
    iat: u64,
    exp: u64,
    bind: &ManagedSessionBind,
) -> Challenge {
    Challenge {
        version: 1,
        audience: xid_hex(xid),
        nonce: consent_digest(xid, request_id, challenge, commitment, iat, bind).to_vec(),
        issued_at: iat,
        expires_at: exp,
    }
}

fn xid_hex(xid: Xid) -> String {
    fn digit(value: u8) -> u8 {
        match value {
            0..=9 => b'0' + value,
            _ => b'a' + (value - 10),
        }
    }
    let mut out = String::with_capacity(64);
    for byte in xid.as_bytes() {
        out.push(char::from(digit(byte >> 4)));
        out.push(char::from(digit(byte & 0x0f)));
    }
    out
}

pub fn operational_ed25519_public(
    document: &XIDDocument,
) -> Result<[u8; 32], ManagedChallengeError> {
    if !is_c2(document) {
        return Err(ManagedChallengeError::NotC2);
    }
    for key in document.keys() {
        if key_allows(key, Privilege::Sign)
            && key_allows(key, Privilege::Auth)
            && !key_allows(key, Privilege::Elect)
        {
            if let SigningPublicKey::Ed25519(public) = key.public_keys().signing_public_key() {
                return Ok(*public.data());
            }
            return Err(ManagedChallengeError::OperationalKeyMismatch);
        }
    }
    Err(ManagedChallengeError::OperationalKeyMismatch)
}

fn document_has_elect_public(
    document: &XIDDocument,
    public: &[u8],
    operational: &[u8; 32],
) -> bool {
    public != operational
        && document.keys().iter().any(|key| {
            key_allows(key, Privilege::Elect)
                && matches!(
                    key.public_keys().signing_public_key(),
                    SigningPublicKey::Ed25519(ed) if ed.data().as_slice() == public
                )
        })
}

fn i64_time(value: u64) -> Result<i64, ManagedChallengeError> {
    i64::try_from(value).map_err(|_| ManagedChallengeError::ChallengeAdmission("time overflow"))
}

fn current_unix() -> Result<u64, ManagedChallengeError> {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| ManagedChallengeError::ChallengeAdmission("system time precedes epoch"))
}

fn xid_from_row(bytes: &[u8]) -> Result<Xid, ManagedChallengeError> {
    Xid::try_from_slice(bytes).map_err(|e| ManagedChallengeError::Document(e.to_string()))
}

fn decode_document(bytes: &[u8]) -> Result<XIDDocument, ManagedChallengeError> {
    use dcbor::prelude::*;
    let cbor =
        CBOR::try_from_data(bytes).map_err(|e| ManagedChallengeError::Document(e.to_string()))?;
    XIDDocument::try_from(cbor).map_err(|e| ManagedChallengeError::Document(e.to_string()))
}

// No partial result escapes this function if the second signature fails.
fn sign_managed_result(
    signer: &impl Signer,
    challenge: &Challenge,
    bind: &ManagedSessionBind,
) -> Result<(Vec<u8>, Vec<u8>), ManagedChallengeError> {
    let response = signer
        .respond(challenge)
        .map_err(|error| ManagedChallengeError::Protocol(error.to_string()))?;
    let signature = signer
        .sign_classical(&bind_signing_bytes(&challenge.to_bytes(), bind))
        .map_err(|error| ManagedChallengeError::Protocol(error.to_string()))?;
    if signature.alg != ClassicalAlg::Ed25519 || signature.bytes.len() != 64 {
        return Err(ManagedChallengeError::InvalidProof);
    }
    Ok((response.to_bytes(), signature.bytes))
}

impl KeysStore {
    /// Begin an immutable managed-signing attempt. `webauthn_state` is the
    /// serialised server verifier state for A3 and must be absent for A4.
    pub async fn begin_managed_challenge(
        &self,
        xid: Xid,
        challenge_bytes: &[u8],
        commitment: [u8; 32],
        proof: ManagedChallengeProof,
        webauthn_state: Option<&[u8]>,
        now: u64,
        bind: &ManagedSessionBind,
    ) -> Result<BeginManagedChallenge, ManagedChallengeError> {
        bind.validate()?;
        let admission = ChallengeAdmission::parse(challenge_bytes, now)?;
        if (proof == ManagedChallengeProof::A3) != webauthn_state.is_some() {
            return Err(ManagedChallengeError::InvalidProof);
        }
        let custody = self
            .get_custody(xid)
            .await
            .map_err(|e| ManagedChallengeError::Document(e.to_string()))?
            .ok_or(ManagedChallengeError::NotFound)?;
        if custody.rung != CustodyRung::C2 {
            return Err(ManagedChallengeError::NotC2);
        }
        operational_ed25519_public(&custody.document)?;
        let request_id = Uuid::new_v4();
        let consent_iat = now;
        let consent_exp = admission
            .challenge
            .expires_at
            .min(now.saturating_add(CONSENT_TTL));
        if consent_exp <= now {
            return Err(ManagedChallengeError::Expired);
        }
        let inserted = sqlx::query(
            "INSERT INTO managed_challenge_attempts (
                request_id, xid, challenge_digest, challenge, verifier_commitment,
                proof_kind, webauthn_state, consent_iat, consent_exp,
                session_public_key, operation, resource, channel
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
             RETURNING session_public_key, operation, resource, channel",
        )
        .bind(request_id)
        .bind(xid.as_bytes().as_slice())
        .bind(admission.digest.as_slice())
        .bind(challenge_bytes)
        .bind(commitment.as_slice())
        .bind(proof.as_str())
        .bind(webauthn_state)
        .bind(i64_time(consent_iat)?)
        .bind(i64_time(consent_exp)?)
        .bind(bind.session_public_key.to_value().to_bytes())
        .bind(&bind.operation)
        .bind(&bind.resource)
        .bind(&bind.channel)
        .fetch_one(self.pool())
        .await;
        let stored = match inserted {
            Ok(row) => row,
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                return Err(ManagedChallengeError::Replay);
            }
            Err(error) => return Err(error.into()),
        };
        let bind = ManagedSessionBind::from_row(&stored)?;
        Ok(BeginManagedChallenge {
            request_id,
            consent_challenge: consent_challenge(
                xid,
                request_id,
                challenge_bytes,
                &commitment,
                consent_iat,
                consent_exp,
                &bind,
            )
            .to_bytes(),
            consent_iat,
            consent_exp,
            bind,
        })
    }

    /// Return the persisted WebAuthn verifier state for the exact A3 attempt.
    pub async fn managed_a3_state(
        &self,
        request_id: Uuid,
    ) -> Result<(Xid, Vec<u8>), ManagedChallengeError> {
        let row = sqlx::query(
            "SELECT xid, webauthn_state, proof_kind, state
             FROM managed_challenge_attempts WHERE request_id = $1",
        )
        .bind(request_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(ManagedChallengeError::NotFound)?;
        if row.try_get::<String, _>("proof_kind")? != "a3"
            || row.try_get::<Option<String>, _>("state")?.is_some()
        {
            return Err(ManagedChallengeError::InvalidState);
        }
        let xid = xid_from_row(&row.try_get::<Vec<u8>, _>("xid")?)?;
        let state = row
            .try_get::<Option<Vec<u8>>, _>("webauthn_state")?
            .ok_or(ManagedChallengeError::InvalidProof)?;
        Ok((xid, state))
    }

    pub async fn authorize_managed_a3(
        &self,
        request_id: Uuid,
        authorization: A3Authorization<'_>,
    ) -> Result<(), ManagedChallengeError> {
        let mut tx = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT xid, proof_kind, state FROM managed_challenge_attempts
             WHERE request_id = $1 FOR UPDATE",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ManagedChallengeError::NotFound)?;
        if row.try_get::<String, _>("proof_kind")? != "a3"
            || row.try_get::<Option<String>, _>("state")?.is_some()
        {
            return Err(ManagedChallengeError::InvalidState);
        }
        let xid = xid_from_row(&row.try_get::<Vec<u8>, _>("xid")?)?;
        let fresh = sqlx::query(
            "SELECT consent_exp, challenge FROM managed_challenge_attempts WHERE request_id = $1",
        )
        .bind(request_id)
        .fetch_one(&mut *tx)
        .await?;
        let challenge = Challenge::from_bytes(&fresh.try_get::<Vec<u8>, _>("challenge")?)
            .map_err(|_| ManagedChallengeError::NonCanonicalChallenge)?;
        let now = current_unix()?;
        let consent_exp = u64::try_from(fresh.try_get::<i64, _>("consent_exp")?)
            .map_err(|_| ManagedChallengeError::Expired)?;
        if consent_exp <= now || challenge.expires_at <= now {
            return Err(ManagedChallengeError::Expired);
        }
        let live = sqlx::query(
            "SELECT id FROM credentials
             WHERE id = $1 AND xid = $2 AND kind = 'passkey' AND revoked_at IS NULL
             FOR UPDATE",
        )
        .bind(authorization.credential_id)
        .bind(xid.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        if live.is_none() {
            return Err(ManagedChallengeError::InvalidProof);
        }
        append_consent_tx(
            &mut tx,
            ConsentAppend {
                xid,
                action: AUTHORIZED_ACTION,
                audience: Some("managed-challenge"),
                purpose: Some(&request_id.to_string()),
                access_level: AccessLevel::A3,
                credential_id: Some(authorization.credential_id),
                proof_kind: ProofKind::WebauthnAssertion,
                proof_bytes: authorization.proof_bytes,
                result: ConsentResult::Signed,
            },
        )
        .await
        .map_err(|e| ManagedChallengeError::Document(e.to_string()))?;
        sqlx::query(
            "UPDATE managed_challenge_attempts
             SET state = 'authorized', credential_id = $2, consent_proof = $3,
                 webauthn_state = NULL, updated_at = now()
             WHERE request_id = $1",
        )
        .bind(request_id)
        .bind(authorization.credential_id)
        .bind(authorization.proof_bytes)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn authorize_managed_a4(
        &self,
        request_id: Uuid,
        response_bytes: &[u8],
    ) -> Result<(), ManagedChallengeError> {
        let response = AuthResponse::from_bytes(response_bytes)
            .map_err(|e| ManagedChallengeError::Protocol(e.to_string()))?;
        let mut tx = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT xid, challenge, verifier_commitment, consent_iat, consent_exp,
                    proof_kind, state, session_public_key, operation, resource, channel
             FROM managed_challenge_attempts WHERE request_id = $1 FOR UPDATE",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ManagedChallengeError::NotFound)?;
        if row.try_get::<String, _>("proof_kind")? != "a4"
            || row.try_get::<Option<String>, _>("state")?.is_some()
        {
            return Err(ManagedChallengeError::InvalidState);
        }
        let xid = xid_from_row(&row.try_get::<Vec<u8>, _>("xid")?)?;
        let challenge: Vec<u8> = row.try_get("challenge")?;
        let commitment: [u8; 32] = row
            .try_get::<Vec<u8>, _>("verifier_commitment")?
            .try_into()
            .map_err(|_| ManagedChallengeError::InvalidProof)?;
        let iat = u64::try_from(row.try_get::<i64, _>("consent_iat")?)
            .map_err(|_| ManagedChallengeError::InvalidProof)?;
        let exp = u64::try_from(row.try_get::<i64, _>("consent_exp")?)
            .map_err(|_| ManagedChallengeError::InvalidProof)?;
        let now = current_unix()?;
        if exp <= now {
            return Err(ManagedChallengeError::Expired);
        }
        let bind = ManagedSessionBind::from_row(&row)?;
        let expected = consent_challenge(xid, request_id, &challenge, &commitment, iat, exp, &bind);
        if response.challenge_bytes != expected.to_bytes() {
            return Err(ManagedChallengeError::InvalidProof);
        }
        if response.public_key.alg != ClassicalAlg::Ed25519 {
            return Err(ManagedChallengeError::InvalidProof);
        }
        verify_classical(
            &response.public_key,
            &signing_payload(&response.challenge_bytes),
            &response.signature,
        )
        .map_err(|_| ManagedChallengeError::InvalidProof)?;
        let custody =
            sqlx::query("SELECT rung, xid_document FROM custody_records WHERE xid = $1 FOR UPDATE")
                .bind(xid.as_bytes().as_slice())
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(ManagedChallengeError::NotFound)?;
        if custody.try_get::<String, _>("rung")? != "c2" {
            return Err(ManagedChallengeError::NotC2);
        }
        let document = decode_document(&custody.try_get::<Vec<u8>, _>("xid_document")?)?;
        let operational = operational_ed25519_public(&document)?;
        if !document_has_elect_public(&document, &response.public_key.bytes, &operational) {
            return Err(ManagedChallengeError::InvalidProof);
        }
        append_consent_tx(
            &mut tx,
            ConsentAppend {
                xid,
                action: AUTHORIZED_ACTION,
                audience: Some("managed-challenge"),
                purpose: Some(&request_id.to_string()),
                access_level: AccessLevel::A4,
                credential_id: None,
                proof_kind: ProofKind::IdentikeyAuthResponse,
                proof_bytes: response_bytes,
                result: ConsentResult::Signed,
            },
        )
        .await
        .map_err(|e| ManagedChallengeError::Document(e.to_string()))?;
        sqlx::query(
            "UPDATE managed_challenge_attempts
             SET state = 'authorized', consenting_public = $2, consent_proof = $3,
                 updated_at = now() WHERE request_id = $1",
        )
        .bind(request_id)
        .bind(&response.public_key.bytes)
        .bind(response_bytes)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Claim the one allowed key use after proof-specific current-authority
    /// rechecks. The claim commits before the envelope leaves the transaction.
    async fn claim_managed_challenge_material(
        &self,
        request_id: Uuid,
        now: u64,
    ) -> Result<(Xid, Vec<u8>, [u8; 32], Challenge, ManagedSessionBind), ManagedChallengeError>
    {
        let mut tx = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT xid, challenge, proof_kind, state, credential_id, consenting_public,
                    consent_exp, session_public_key, operation, resource, channel
             FROM managed_challenge_attempts WHERE request_id = $1 FOR UPDATE",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ManagedChallengeError::NotFound)?;
        let state = row.try_get::<Option<String>, _>("state")?;
        match state.as_deref() {
            Some("authorized") => {}
            // Another live finisher may currently own the claim. Do not let a
            // loser poison the winner's result transaction. Process startup
            // converts claims that survived a crash to terminal indeterminate.
            Some("claimed") => return Err(ManagedChallengeError::AlreadyClaimed),
            Some("indeterminate") => return Err(ManagedChallengeError::Indeterminate),
            _ => return Err(ManagedChallengeError::InvalidState),
        }
        let bind = ManagedSessionBind::from_row(&row)?;
        let xid = xid_from_row(&row.try_get::<Vec<u8>, _>("xid")?)?;
        let proof_kind: String = row.try_get("proof_kind")?;
        let consent_exp = u64::try_from(row.try_get::<i64, _>("consent_exp")?)
            .map_err(|_| ManagedChallengeError::Expired)?;
        let custody = sqlx::query(
            "SELECT rung, xid_document, managed_key_blob FROM custody_records
             WHERE xid = $1 FOR UPDATE",
        )
        .bind(xid.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ManagedChallengeError::NotFound)?;
        let challenge_bytes: Vec<u8> = row.try_get("challenge")?;
        let challenge = Challenge::from_bytes(&challenge_bytes)
            .map_err(|_| ManagedChallengeError::NonCanonicalChallenge)?;
        let document = decode_document(&custody.try_get::<Vec<u8>, _>("xid_document")?)?;
        let operational = operational_ed25519_public(&document);
        let authority_ok = custody.try_get::<String, _>("rung")? == "c2"
            && consent_exp > now
            && challenge.expires_at > now
            && match proof_kind.as_str() {
                "a3" => {
                    let credential_id = row.try_get::<Option<Uuid>, _>("credential_id")?;
                    if let Some(credential_id) = credential_id {
                        sqlx::query(
                            "SELECT id FROM credentials
                             WHERE id = $1 AND xid = $2 AND kind = 'passkey'
                               AND revoked_at IS NULL FOR UPDATE",
                        )
                        .bind(credential_id)
                        .bind(xid.as_bytes().as_slice())
                        .fetch_optional(&mut *tx)
                        .await?
                        .is_some()
                    } else {
                        false
                    }
                }
                "a4" => {
                    let public = row
                        .try_get::<Option<Vec<u8>>, _>("consenting_public")?
                        .unwrap_or_default();
                    operational
                        .as_ref()
                        .is_ok_and(|op| document_has_elect_public(&document, &public, op))
                }
                _ => false,
            };
        let operational = match operational {
            Ok(value) if authority_ok => value,
            _ => {
                fail_attempt_tx(
                    &mut tx,
                    request_id,
                    xid,
                    proof_kind.as_str(),
                    "authority recheck",
                )
                .await?;
                tx.commit().await?;
                return Err(if consent_exp <= now || challenge.expires_at <= now {
                    ManagedChallengeError::Expired
                } else {
                    ManagedChallengeError::InvalidProof
                });
            }
        };
        let blob = custody
            .try_get::<Option<Vec<u8>>, _>("managed_key_blob")?
            .ok_or(ManagedChallengeError::NotC2)?;
        sqlx::query(
            "UPDATE managed_challenge_attempts SET state = 'claimed', updated_at = now()
             WHERE request_id = $1 AND state = 'authorized'",
        )
        .bind(request_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((xid, blob, operational, challenge, bind))
    }

    /// Perform the one allowed key use. The encrypted blob and plaintext seed
    /// never cross the custody-crate boundary; only the durable state machine
    /// and protocol Response are observable by callers.
    pub async fn finish_authorized_managed_challenge(
        &self,
        keyring: &ManagedKeyring,
        request_id: Uuid,
        now: u64,
    ) -> Result<(), ManagedChallengeError> {
        let (xid, blob, public, challenge, bind) = self
            .claim_managed_challenge_material(request_id, now)
            .await?;
        let signer = match keyring.open(&blob, xid, &public) {
            Ok(signer) => signer,
            Err(error) => {
                self.fail_claimed_managed_challenge(request_id, "managed key unavailable")
                    .await?;
                return Err(error);
            }
        };
        let (response, bind_signature) = match sign_managed_result(&signer, &challenge, &bind) {
            Ok(result) => result,
            Err(error) => {
                self.fail_claimed_managed_challenge(request_id, "signer refused")
                    .await?;
                return Err(error);
            }
        };
        // If this transaction fails after the signature, leave `claimed`
        // durable. Startup will make it terminal indeterminate; never retry.
        self.complete_managed_challenge(request_id, &response, &bind_signature)
            .await
    }

    async fn complete_managed_challenge(
        &self,
        request_id: Uuid,
        response: &[u8],
        bind_signature: &[u8],
    ) -> Result<(), ManagedChallengeError> {
        let mut tx = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT xid, proof_kind, state, session_public_key, operation, resource, channel FROM managed_challenge_attempts
             WHERE request_id = $1 FOR UPDATE",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ManagedChallengeError::NotFound)?;
        if row.try_get::<Option<String>, _>("state")?.as_deref() != Some("claimed") {
            return Err(ManagedChallengeError::InvalidState);
        }
        let xid = xid_from_row(&row.try_get::<Vec<u8>, _>("xid")?)?;
        let proof_kind: String = row.try_get("proof_kind")?;
        let fields = ManagedSessionBind::from_row(&row)?;
        if bind_signature.len() != 64 {
            return Err(ManagedChallengeError::InvalidProof);
        }
        let audit = serde_json::to_vec(&serde_json::json!({
            "response": response,
            "bind": bind_signature,
            "operation": fields.operation,
            "resource": fields.resource,
            "session_key_fingerprint": fields.session_public_key.fingerprint().to_base58(),
        }))
        .map_err(|_| ManagedChallengeError::InvalidProof)?;
        append_outcome_tx(
            &mut tx,
            xid,
            request_id,
            &proof_kind,
            COMPLETED_ACTION,
            &audit,
            ConsentResult::Signed,
        )
        .await?;
        sqlx::query(
            "UPDATE managed_challenge_attempts
             SET state = 'completed', response = $2, bind_signature = $3, updated_at = now()
             WHERE request_id = $1",
        )
        .bind(request_id)
        .bind(response)
        .bind(bind_signature)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn fail_claimed_managed_challenge(
        &self,
        request_id: Uuid,
        reason: &str,
    ) -> Result<(), ManagedChallengeError> {
        let mut tx = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT xid, proof_kind, state FROM managed_challenge_attempts
             WHERE request_id = $1 FOR UPDATE",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ManagedChallengeError::NotFound)?;
        if row.try_get::<Option<String>, _>("state")?.as_deref() != Some("claimed") {
            return Err(ManagedChallengeError::InvalidState);
        }
        let xid = xid_from_row(&row.try_get::<Vec<u8>, _>("xid")?)?;
        let proof_kind: String = row.try_get("proof_kind")?;
        fail_attempt_tx(&mut tx, request_id, xid, &proof_kind, reason).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn retrieve_managed_challenge(
        &self,
        request_id: Uuid,
        verifier: &str,
    ) -> Result<RetrievedManagedChallenge, ManagedChallengeError> {
        let commitment = verifier_commitment(verifier);
        let mut tx = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT verifier_commitment, state, response, bind_signature, session_public_key, operation, resource, channel FROM managed_challenge_attempts
             WHERE request_id = $1 FOR UPDATE",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ManagedChallengeError::NotFound)?;
        if row.try_get::<Vec<u8>, _>("verifier_commitment")?.as_slice() != commitment {
            return Err(ManagedChallengeError::VerifierMismatch);
        }
        let state = row.try_get::<Option<String>, _>("state")?;
        let result = match state.as_deref() {
            Some("completed") => RetrievedManagedChallenge::Completed(CompletedManagedChallenge {
                response: row
                    .try_get::<Option<Vec<u8>>, _>("response")?
                    .ok_or(ManagedChallengeError::InvalidState)?,
                bind: row
                    .try_get::<Option<Vec<u8>>, _>("bind_signature")?
                    .filter(|bytes| bytes.len() == 64)
                    .ok_or(ManagedChallengeError::InvalidState)?,
                fields: ManagedSessionBind::from_row(&row)?,
            }),
            Some("failed") => RetrievedManagedChallenge::Failed,
            Some("indeterminate") => RetrievedManagedChallenge::Indeterminate,
            Some("claimed") => RetrievedManagedChallenge::Pending,
            Some("authorized") | None => RetrievedManagedChallenge::Pending,
            Some(other) => {
                ManagedChallengeState::parse(other)?;
                return Err(ManagedChallengeError::InvalidState);
            }
        };
        tx.commit().await?;
        Ok(result)
    }

    /// At process start, any claim without a durable result is an unknown key
    /// use and therefore terminal. This is deliberately not performed by a
    /// concurrent loser while the winning finisher may still be signing.
    pub async fn mark_claimed_managed_challenges_indeterminate(
        &self,
    ) -> Result<u64, ManagedChallengeError> {
        let result = sqlx::query(
            "UPDATE managed_challenge_attempts
             SET state = 'indeterminate', updated_at = now()
             WHERE state = 'claimed'",
        )
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }
}

async fn append_outcome_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    xid: Xid,
    request_id: Uuid,
    proof_kind: &str,
    action: &str,
    proof_bytes: &[u8],
    result: ConsentResult,
) -> Result<(), ManagedChallengeError> {
    let (access_level, proof) = if proof_kind == "a3" {
        (AccessLevel::A3, ProofKind::WebauthnAssertion)
    } else {
        (AccessLevel::A4, ProofKind::IdentikeyAuthResponse)
    };
    append_consent_tx(
        tx,
        ConsentAppend {
            xid,
            action,
            audience: Some("managed-challenge"),
            purpose: Some(&request_id.to_string()),
            access_level,
            credential_id: None,
            proof_kind: proof,
            proof_bytes,
            result,
        },
    )
    .await
    .map_err(|e| ManagedChallengeError::Document(e.to_string()))?;
    Ok(())
}

async fn fail_attempt_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request_id: Uuid,
    xid: Xid,
    proof_kind: &str,
    reason: &str,
) -> Result<(), ManagedChallengeError> {
    append_outcome_tx(
        tx,
        xid,
        request_id,
        proof_kind,
        FAILED_ACTION,
        reason.as_bytes(),
        ConsentResult::Refused,
    )
    .await?;
    sqlx::query(
        "UPDATE managed_challenge_attempts
         SET state = 'failed', failure = $2, updated_at = now() WHERE request_id = $1",
    )
    .bind(request_id)
    .bind(reason)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test assertions"
)]
mod tests {
    use super::*;
    use bc_components::{PrivateKeyBase, SigningPublicKey, XIDProvider};
    use identikey_auth::Response;
    use identikey_auth::{ClassicalPublicKey, Signer, verify_classical};
    use sqlx::PgPool;

    use crate::{CustodyRung, c2_native};

    fn bind_fields() -> ManagedSessionBind {
        ManagedSessionBind {
            session_public_key: ClassicalPublicKey {
                alg: ClassicalAlg::Ed25519,
                bytes: vec![0x11; 32],
            },
            operation: vec!["vms".into(), "stop".into()],
            resource: vec!["vm".into(), "A".into()],
            channel: vec![0x22; 32],
        }
    }

    fn xid() -> Xid {
        Xid::from_bytes(std::array::from_fn(|i| u8::try_from(i).unwrap()))
    }

    #[test]
    fn managed_challenge_fixed_consent_vector() {
        let request = Uuid::from_bytes(std::array::from_fn(|i| u8::try_from(i).unwrap()));
        assert_eq!(
            consent_digest(
                xid(),
                request,
                &[1, 2],
                &[0xab; 32],
                1_700_000_000,
                &bind_fields()
            ),
            [
                0x7e, 0xfc, 0x1d, 0x28, 0x4a, 0xc4, 0x5e, 0xc6, 0x6c, 0x92, 0x8a, 0x75, 0x0c, 0x70,
                0x1e, 0xd2, 0x66, 0xce, 0x28, 0xe3, 0xda, 0xb0, 0xe3, 0x06, 0x58, 0x89, 0x28, 0xc7,
                0x9d, 0xce, 0x8c, 0x03
            ]
        );
        let digest = consent_digest(
            xid(),
            request,
            &[1, 2],
            &[0xab; 32],
            1_700_000_000,
            &bind_fields(),
        );
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_ne!(
            hex,
            "13ef62b41aa5240b246aec4d4bbb240fe5c94bb4a423c24898e2dee6a6844e35"
        );
    }

    #[test]
    fn managed_challenge_envelope_round_trip_and_fail_closed() {
        let operational = OperationalEd25519::generate();
        let SigningPublicKey::Ed25519(public) = operational.public_keys().signing_public_key()
        else {
            panic!("operational key must be Ed25519");
        };
        let keyring = ManagedKeyring::single("test", [7; 32]);
        let blob = keyring
            .seal(xid(), public.data(), operational.seed())
            .unwrap();
        let signer = keyring.open(&blob, xid(), public.data()).unwrap();
        assert_eq!(signer.classical_public_key().bytes, public.data());
        assert!(
            keyring
                .open(&blob, Xid::from_bytes([9; 32]), public.data())
                .is_err()
        );
        assert!(keyring.open(&[0x51; 32], xid(), public.data()).is_err());
        assert!(
            ManagedKeyring::single("other", [8; 32])
                .open(&blob, xid(), public.data())
                .is_err()
        );
    }

    #[test]
    fn managed_challenge_envelope_loads_protocol_signer() {
        let operational = OperationalEd25519::generate();
        let public = match operational.public_keys().signing_public_key() {
            SigningPublicKey::Ed25519(public) => *public.data(),
            _ => panic!("operational key must be Ed25519"),
        };
        let keyring = ManagedKeyring::single("restart-key", [3; 32]);
        let persisted = keyring.seal(xid(), &public, operational.seed()).unwrap();
        drop(operational);
        let restarted = keyring.open(&persisted, xid(), &public).unwrap();
        let challenge = Challenge {
            version: 1,
            audience: bs58::encode([0xab; 32]).into_string(),
            nonce: vec![1; 16],
            issued_at: 100,
            expires_at: 200,
        };
        let response = restarted.respond(&challenge).unwrap();
        verify_classical(
            &ClassicalPublicKey {
                alg: ClassicalAlg::Ed25519,
                bytes: public.to_vec(),
            },
            &signing_payload(&challenge.to_bytes()),
            &response.signature,
        )
        .unwrap();
    }

    #[test]
    fn managed_challenge_admission_is_exact_and_bounded() {
        let challenge = Challenge {
            version: 1,
            audience: bs58::encode([0xab; 32]).into_string(),
            nonce: vec![1; 16],
            issued_at: 1_000,
            expires_at: 1_600,
        };
        assert!(ChallengeAdmission::parse(&challenge.to_bytes(), 1_100).is_ok());
        let mut too_long = challenge.clone();
        too_long.nonce = vec![1; 65];
        assert!(ChallengeAdmission::parse(&too_long.to_bytes(), 1_100).is_err());
        for audience in [
            format!("1{}", bs58::encode([0_u8; 32]).into_string()),
            bs58::encode([0_u8; 31]).into_string(),
            "0OIl".into(),
            "ab".repeat(32),
        ] {
            let mut invalid = challenge.clone();
            invalid.audience = audience;
            assert!(ChallengeAdmission::parse(&invalid.to_bytes(), 1_100).is_err());
        }
    }

    #[test]
    fn managed_challenge_joint_bind_vector_and_domain_separation() {
        let bind = bind_fields();
        let encoded = bind_signing_bytes(b"challenge", &bind);
        let hex: String = encoded.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "87746964656e74696b65792d6d6a6f6c6e69722f76316462696e64496368616c6c656e6765a263616c676765643235353139636b6579582011111111111111111111111111111111111111111111111111111111111111118263766d736473746f708262766d614158202222222222222222222222222222222222222222222222222222222222222222"
        );
        let auth = signing_payload(b"challenge");
        assert_eq!(auth[0], 0x83);
        assert_eq!(encoded[0], 0x87);
        assert_ne!(auth, encoded);
        let mut colon = bind.clone();
        colon.operation = vec!["vms:stop".into()];
        assert_ne!(encoded, bind_signing_bytes(b"challenge", &colon));
        assert_ne!(
            consent_digest(xid(), Uuid::nil(), b"challenge", &[0; 32], 1, &bind),
            consent_digest(xid(), Uuid::nil(), b"challenge", &[0; 32], 1, &colon)
        );
    }

    #[test]
    fn managed_challenge_bind_sign_failure_has_no_partial_result() {
        struct RefuseBind(SoftwareSigner);
        impl Signer for RefuseBind {
            fn classical_public_key(&self) -> ClassicalPublicKey {
                self.0.classical_public_key()
            }
            fn sign_classical(
                &self,
                payload: &[u8],
            ) -> identikey_auth::Result<identikey_auth::ClassicalSignature> {
                if payload[0] == 0x87 {
                    return Err(identikey_auth::AuthError::InvalidKey(
                        "injected bind failure",
                    ));
                }
                self.0.sign_classical(payload)
            }
        }
        let challenge = Challenge {
            version: 1,
            audience: bs58::encode([1; 32]).into_string(),
            nonce: vec![2; 32],
            issued_at: 1,
            expires_at: 2,
        };
        let signer = RefuseBind(SoftwareSigner::from_ed25519_seed([3; 32]));
        assert!(signer.respond(&challenge).is_ok());
        assert!(sign_managed_result(&signer, &challenge, &bind_fields()).is_err());
    }

    fn invalid_bind_fields() -> Vec<ManagedSessionBind> {
        let mut invalid = Vec::new();
        for length in [0, 31, 33] {
            let mut bind = bind_fields();
            bind.channel = vec![0; length];
            invalid.push(bind);
        }
        let mut bind = bind_fields();
        bind.session_public_key.alg = ClassicalAlg::P256;
        invalid.push(bind);
        let mut bind = bind_fields();
        bind.session_public_key.bytes.pop();
        invalid.push(bind);
        for tuple in [
            vec![],
            vec!["".into()],
            vec!["a b".into()],
            vec!["\n".into()],
            vec!["é".into()],
            vec!["a".repeat(65)],
            vec!["a".into(); 9],
        ] {
            let mut bind = bind_fields();
            bind.operation = tuple.clone();
            invalid.push(bind);
            let mut bind = bind_fields();
            bind.resource = tuple;
            invalid.push(bind);
        }
        invalid
    }

    #[test]
    fn managed_challenge_bind_admission_caps() {
        assert!(bind_fields().validate().is_ok());
        for bind in invalid_bind_fields() {
            assert!(bind.validate().is_err());
        }
        let mut bind = bind_fields();
        bind.operation = vec!["a".repeat(64); 8];
        assert!(bind.validate().is_ok());
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_invalid_bind_and_audience_store_nothing(pool: PgPool) {
        let (store, _, xid, _, challenge) = managed_fixture(pool).await;
        let now = current_unix().unwrap();
        for bind in invalid_bind_fields() {
            assert!(
                store
                    .begin_managed_challenge(
                        xid,
                        &challenge.to_bytes(),
                        [0; 32],
                        ManagedChallengeProof::A4,
                        None,
                        now,
                        &bind
                    )
                    .await
                    .is_err()
            );
        }
        for audience in [
            "1".repeat(33),
            "1".repeat(31),
            "0OIl".into(),
            "ab".repeat(32),
        ] {
            let mut invalid = challenge.clone();
            invalid.audience = audience;
            assert!(
                store
                    .begin_managed_challenge(
                        xid,
                        &invalid.to_bytes(),
                        [0; 32],
                        ManagedChallengeProof::A4,
                        None,
                        now,
                        &bind_fields()
                    )
                    .await
                    .is_err()
            );
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM managed_challenge_attempts")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_legacy_attempt_fails_before_decrypt(pool: PgPool) {
        let (store, keyring, xid, credential, challenge) = managed_fixture(pool).await;
        let request_id = Uuid::new_v4();
        let now = current_unix().unwrap();
        sqlx::query("INSERT INTO managed_challenge_attempts
            (request_id, xid, challenge_digest, challenge, verifier_commitment, proof_kind, consent_iat, consent_exp, state, credential_id)
            VALUES ($1,$2,$3,$4,$5,'a3',$6,$7,'authorized',$8)")
            .bind(request_id).bind(xid.as_bytes().as_slice()).bind([0_u8;32].as_slice())
            .bind(challenge.to_bytes()).bind(verifier_commitment("legacy").as_slice())
            .bind(now as i64).bind((now+300) as i64).bind(credential).execute(store.pool()).await.unwrap();
        assert!(matches!(
            store
                .finish_authorized_managed_challenge(&keyring, request_id, now)
                .await,
            Err(ManagedChallengeError::InvalidProof)
        ));
        let row = sqlx::query("SELECT state, response, bind_signature FROM managed_challenge_attempts WHERE request_id = $1").bind(request_id).fetch_one(store.pool()).await.unwrap();
        assert_eq!(row.get::<String, _>("state"), "authorized");
        assert!(row.get::<Option<Vec<u8>>, _>("response").is_none());
        assert!(row.get::<Option<Vec<u8>>, _>("bind_signature").is_none());
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_bind_fields_are_immutable(pool: PgPool) {
        let (store, _, xid, _, challenge) = managed_fixture(pool).await;
        let begun = store
            .begin_managed_challenge(
                xid,
                &challenge.to_bytes(),
                [0; 32],
                ManagedChallengeProof::A4,
                None,
                current_unix().unwrap(),
                &bind_fields(),
            )
            .await
            .unwrap();
        for assignment in [
            "request_id = '00000000-0000-0000-0000-000000000000'::uuid",
            "xid = decode(repeat('ff',32),'hex')",
            "challenge = decode('00','hex')",
            "verifier_commitment = decode(repeat('ff',32),'hex')",
            "session_public_key = decode('00','hex')",
            "operation = ARRAY['vms','start']",
            "resource = ARRAY['vm','B']",
            "channel = decode(repeat('ff',32),'hex')",
        ] {
            let query =
                format!("UPDATE managed_challenge_attempts SET {assignment} WHERE request_id = $1");
            let error = sqlx::query(sqlx::AssertSqlSafe(query))
                .bind(begun.request_id)
                .execute(store.pool())
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("managed challenge binding is immutable")
            );
        }
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_completion_audit_failure_releases_neither(pool: PgPool) {
        let (store, keyring, xid, credential, challenge) = managed_fixture(pool).await;
        let now = current_unix().unwrap();
        let begun = store
            .begin_managed_challenge(
                xid,
                &challenge.to_bytes(),
                verifier_commitment("audit"),
                ManagedChallengeProof::A3,
                Some(b"state"),
                now,
                &bind_fields(),
            )
            .await
            .unwrap();
        store
            .authorize_managed_a3(
                begun.request_id,
                A3Authorization {
                    credential_id: credential,
                    proof_bytes: b"proof",
                },
            )
            .await
            .unwrap();
        sqlx::query("CREATE FUNCTION reject_managed_completion() RETURNS trigger AS $$
            BEGIN IF NEW.action = 'signing_completed' THEN RAISE EXCEPTION 'injected completion failure'; END IF;
            RETURN NEW; END; $$ LANGUAGE plpgsql").execute(store.pool()).await.unwrap();
        sqlx::query(
            "CREATE TRIGGER reject_managed_completion BEFORE INSERT ON consent_log
            FOR EACH ROW EXECUTE FUNCTION reject_managed_completion()",
        )
        .execute(store.pool())
        .await
        .unwrap();
        assert!(
            store
                .finish_authorized_managed_challenge(&keyring, begun.request_id, now)
                .await
                .is_err()
        );
        assert_eq!(
            store
                .retrieve_managed_challenge(begun.request_id, "audit")
                .await
                .unwrap(),
            RetrievedManagedChallenge::Pending
        );
        let row = sqlx::query("SELECT state, response, bind_signature FROM managed_challenge_attempts WHERE request_id = $1")
            .bind(begun.request_id).fetch_one(store.pool()).await.unwrap();
        assert_eq!(row.get::<String, _>("state"), "claimed");
        assert!(row.get::<Option<Vec<u8>>, _>("response").is_none());
        assert!(row.get::<Option<Vec<u8>>, _>("bind_signature").is_none());
        store
            .mark_claimed_managed_challenges_indeterminate()
            .await
            .unwrap();
        assert_eq!(
            store
                .retrieve_managed_challenge(begun.request_id, "audit")
                .await
                .unwrap(),
            RetrievedManagedChallenge::Indeterminate
        );
    }

    async fn managed_fixture(pool: PgPool) -> (KeysStore, ManagedKeyring, Xid, Uuid, Challenge) {
        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let operational = OperationalEd25519::generate();
        let document = c2_native(&user, operational.public_keys()).unwrap();
        let xid = Xid::from(document.xid());
        let public = operational_ed25519_public(&document).unwrap();
        let keyring = ManagedKeyring::single("test-db", [0x42; 32]);
        let blob = keyring.seal(xid, &public, operational.seed()).unwrap();
        store
            .create_managed(CustodyRung::C2, &document, &blob)
            .await
            .unwrap();
        let credential = store
            .insert_passkey(xid, b"managed-test-credential", b"{}", 0)
            .await
            .unwrap();
        let now = current_unix().unwrap();
        let challenge = Challenge {
            version: 1,
            audience: bs58::encode([0xab; 32]).into_string(),
            nonce: vec![9; 32],
            issued_at: now,
            expires_at: now + 300,
        };
        (store, keyring, xid, credential, challenge)
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_a3_signs_once_and_retrieval_needs_verifier(pool: PgPool) {
        let (store, keyring, xid, credential, challenge) = managed_fixture(pool).await;
        let verifier = "pkce verifier known only to initiating client";
        let begun = store
            .begin_managed_challenge(
                xid,
                &challenge.to_bytes(),
                verifier_commitment(verifier),
                ManagedChallengeProof::A3,
                Some(b"persisted webauthn verifier state"),
                current_unix().unwrap(),
                &bind_fields(),
            )
            .await
            .unwrap();
        store
            .authorize_managed_a3(
                begun.request_id,
                A3Authorization {
                    credential_id: credential,
                    proof_bytes: b"verified assertion",
                },
            )
            .await
            .unwrap();
        assert_eq!(begun.bind, bind_fields());
        store
            .finish_authorized_managed_challenge(
                &keyring,
                begun.request_id,
                current_unix().unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .retrieve_managed_challenge(begun.request_id, "attacker")
                .await,
            Err(ManagedChallengeError::VerifierMismatch)
        ));
        let RetrievedManagedChallenge::Completed(retrieved) = store
            .retrieve_managed_challenge(begun.request_id, verifier)
            .await
            .unwrap()
        else {
            panic!("completed response expected");
        };
        assert_eq!(retrieved.fields, bind_fields());
        let bind_signature = identikey_auth::ClassicalSignature {
            alg: ClassicalAlg::Ed25519,
            bytes: retrieved.bind.clone(),
        };
        let decoded = Response::from_bytes(&retrieved.response).unwrap();
        verify_classical(
            &decoded.public_key,
            &bind_signing_bytes(&challenge.to_bytes(), &retrieved.fields),
            &bind_signature,
        )
        .unwrap();
        let audit: Vec<u8> = sqlx::query_scalar(
            "SELECT proof_bytes FROM consent_log WHERE action = 'signing_completed' AND xid = $1",
        )
        .bind(xid.as_bytes().as_slice())
        .fetch_one(store.pool())
        .await
        .unwrap();
        let audit: serde_json::Value = serde_json::from_slice(&audit).unwrap();
        assert_eq!(
            audit["session_key_fingerprint"],
            bind_fields().session_public_key.fingerprint().to_base58()
        );
        assert_eq!(audit["operation"], serde_json::json!(["vms", "stop"]));
        assert_eq!(audit["resource"], serde_json::json!(["vm", "A"]));
        assert_eq!(audit["bind"], serde_json::json!(retrieved.bind));
        assert_eq!(audit["response"], serde_json::json!(retrieved.response));
        assert_eq!(decoded.challenge_bytes, challenge.to_bytes());
        verify_classical(
            &decoded.public_key,
            &signing_payload(&decoded.challenge_bytes),
            &decoded.signature,
        )
        .unwrap();
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_replay_and_unknown_key_use_are_terminal(pool: PgPool) {
        let (store, _keyring, xid, credential, challenge) = managed_fixture(pool).await;
        let commitment = verifier_commitment("one client");
        let begun = store
            .begin_managed_challenge(
                xid,
                &challenge.to_bytes(),
                commitment,
                ManagedChallengeProof::A3,
                Some(b"state"),
                current_unix().unwrap(),
                &bind_fields(),
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .begin_managed_challenge(
                    xid,
                    &challenge.to_bytes(),
                    commitment,
                    ManagedChallengeProof::A3,
                    Some(b"other state"),
                    current_unix().unwrap(),
                    &bind_fields(),
                )
                .await,
            Err(ManagedChallengeError::Replay)
        ));
        store
            .authorize_managed_a3(
                begun.request_id,
                A3Authorization {
                    credential_id: credential,
                    proof_bytes: b"proof",
                },
            )
            .await
            .unwrap();
        store
            .claim_managed_challenge_material(begun.request_id, current_unix().unwrap())
            .await
            .unwrap();
        assert!(matches!(
            store
                .claim_managed_challenge_material(begun.request_id, current_unix().unwrap())
                .await,
            Err(ManagedChallengeError::AlreadyClaimed)
        ));
        store
            .mark_claimed_managed_challenges_indeterminate()
            .await
            .unwrap();
        assert_eq!(
            store
                .retrieve_managed_challenge(begun.request_id, "one client")
                .await
                .unwrap(),
            RetrievedManagedChallenge::Indeterminate
        );
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_revocation_wins_before_decrypt(pool: PgPool) {
        let (store, _keyring, xid, credential, challenge) = managed_fixture(pool).await;
        let begun = store
            .begin_managed_challenge(
                xid,
                &challenge.to_bytes(),
                verifier_commitment("revoked client"),
                ManagedChallengeProof::A3,
                Some(b"state"),
                current_unix().unwrap(),
                &bind_fields(),
            )
            .await
            .unwrap();
        store
            .authorize_managed_a3(
                begun.request_id,
                A3Authorization {
                    credential_id: credential,
                    proof_bytes: b"proof",
                },
            )
            .await
            .unwrap();
        store.revoke_device(xid, credential).await.unwrap();
        assert!(
            store
                .claim_managed_challenge_material(begun.request_id, current_unix().unwrap())
                .await
                .is_err()
        );
        assert_eq!(
            store
                .retrieve_managed_challenge(begun.request_id, "revoked client")
                .await
                .unwrap(),
            RetrievedManagedChallenge::Failed
        );
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_a4_uses_server_challenge_without_passkey(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let user = OperationalEd25519::generate();
        let user_signer = SoftwareSigner::from_ed25519_seed(*user.seed());
        let managed = OperationalEd25519::generate();
        let document = c2_native(user.public_keys(), managed.public_keys()).unwrap();
        let xid = Xid::from(document.xid());
        let managed_public = operational_ed25519_public(&document).unwrap();
        let keyring = ManagedKeyring::single("a4", [0x24; 32]);
        let blob = keyring.seal(xid, &managed_public, managed.seed()).unwrap();
        store
            .create_managed(CustodyRung::C2, &document, &blob)
            .await
            .unwrap();
        let now = current_unix().unwrap();
        let edge = Challenge {
            version: 1,
            audience: bs58::encode([0xcd; 32]).into_string(),
            nonce: vec![5; 32],
            issued_at: now,
            expires_at: now + 300,
        };
        let begun = store
            .begin_managed_challenge(
                xid,
                &edge.to_bytes(),
                verifier_commitment("a4 verifier"),
                ManagedChallengeProof::A4,
                None,
                now,
                &bind_fields(),
            )
            .await
            .unwrap();
        let consent = Challenge::from_bytes(&begun.consent_challenge).unwrap();
        let response = user_signer.respond(&consent).unwrap().to_bytes();
        store
            .authorize_managed_a4(begun.request_id, &response)
            .await
            .unwrap();
        let (bound_xid, blob, public, challenge, _) = store
            .claim_managed_challenge_material(begun.request_id, now)
            .await
            .unwrap();
        let managed_response = keyring
            .open(&blob, bound_xid, &public)
            .unwrap()
            .respond(&challenge)
            .unwrap()
            .to_bytes();
        store
            .complete_managed_challenge(
                begun.request_id,
                &managed_response,
                &keyring
                    .open(&blob, bound_xid, &public)
                    .unwrap()
                    .sign_classical(&bind_signing_bytes(&challenge.to_bytes(), &bind_fields()))
                    .unwrap()
                    .bytes,
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .retrieve_managed_challenge(begun.request_id, "a4 verifier")
                .await
                .unwrap(),
            RetrievedManagedChallenge::Completed(_)
        ));
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_a4_rejects_substituted_consent_challenge(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let user = OperationalEd25519::generate();
        let signer = SoftwareSigner::from_ed25519_seed(*user.seed());
        let managed = OperationalEd25519::generate();
        let document = c2_native(user.public_keys(), managed.public_keys()).unwrap();
        let xid = Xid::from(document.xid());
        let public = operational_ed25519_public(&document).unwrap();
        let keyring = ManagedKeyring::single("a4", [0x25; 32]);
        let blob = keyring.seal(xid, &public, managed.seed()).unwrap();
        store
            .create_managed(CustodyRung::C2, &document, &blob)
            .await
            .unwrap();
        let now = current_unix().unwrap();
        let edge = Challenge {
            version: 1,
            audience: bs58::encode([0xef; 32]).into_string(),
            nonce: vec![7; 32],
            issued_at: now,
            expires_at: now + 300,
        };
        let begun = store
            .begin_managed_challenge(
                xid,
                &edge.to_bytes(),
                verifier_commitment("substitution"),
                ManagedChallengeProof::A4,
                None,
                now,
                &bind_fields(),
            )
            .await
            .unwrap();
        let mut substituted = Challenge::from_bytes(&begun.consent_challenge).unwrap();
        let mut wrong_bind = bind_fields();
        wrong_bind.operation = vec!["vms".into(), "start".into()];
        substituted.nonce = consent_digest(
            xid,
            begun.request_id,
            &edge.to_bytes(),
            &verifier_commitment("substitution"),
            begun.consent_iat,
            &wrong_bind,
        )
        .to_vec();
        assert_eq!(substituted.audience, xid_hex(xid));
        let response = signer.respond(&substituted).unwrap().to_bytes();
        assert!(matches!(
            store
                .authorize_managed_a4(begun.request_id, &response)
                .await,
            Err(ManagedChallengeError::InvalidProof)
        ));
        let row = sqlx::query("SELECT state, response, bind_signature FROM managed_challenge_attempts WHERE request_id = $1")
            .bind(begun.request_id).fetch_one(store.pool()).await.unwrap();
        assert!(row.get::<Option<String>, _>("state").is_none());
        assert!(row.get::<Option<Vec<u8>>, _>("response").is_none());
        assert!(row.get::<Option<Vec<u8>>, _>("bind_signature").is_none());
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_concurrent_claim_has_one_winner(pool: PgPool) {
        let (store, keyring, xid, credential, challenge) = managed_fixture(pool).await;
        let begun = store
            .begin_managed_challenge(
                xid,
                &challenge.to_bytes(),
                verifier_commitment("concurrent"),
                ManagedChallengeProof::A3,
                Some(b"state"),
                current_unix().unwrap(),
                &bind_fields(),
            )
            .await
            .unwrap();
        store
            .authorize_managed_a3(
                begun.request_id,
                A3Authorization {
                    credential_id: credential,
                    proof_bytes: b"proof",
                },
            )
            .await
            .unwrap();
        let first = store.clone();
        let second = store.clone();
        let now = current_unix().unwrap();
        let (left, right) = tokio::join!(
            first.claim_managed_challenge_material(begun.request_id, now),
            second.claim_managed_challenge_material(begun.request_id, now)
        );
        let claimed = match (left, right) {
            (Ok(claimed), Err(ManagedChallengeError::AlreadyClaimed))
            | (Err(ManagedChallengeError::AlreadyClaimed), Ok(claimed)) => claimed,
            other => panic!("expected one winner and one loser, got {other:?}"),
        };
        let response = keyring
            .open(&claimed.1, claimed.0, &claimed.2)
            .unwrap()
            .respond(&claimed.3)
            .unwrap()
            .to_bytes();
        store
            .complete_managed_challenge(
                begun.request_id,
                &response,
                &keyring
                    .open(&claimed.1, claimed.0, &claimed.2)
                    .unwrap()
                    .sign_classical(&bind_signing_bytes(&claimed.3.to_bytes(), &claimed.4))
                    .unwrap()
                    .bytes,
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .retrieve_managed_challenge(begun.request_id, "concurrent")
                .await
                .unwrap(),
            RetrievedManagedChallenge::Completed(_)
        ));
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_restart_terminalizes_claim_without_result(pool: PgPool) {
        let (store, _keyring, xid, credential, challenge) = managed_fixture(pool).await;
        let begun = store
            .begin_managed_challenge(
                xid,
                &challenge.to_bytes(),
                verifier_commitment("restart"),
                ManagedChallengeProof::A3,
                Some(b"state"),
                current_unix().unwrap(),
                &bind_fields(),
            )
            .await
            .unwrap();
        store
            .authorize_managed_a3(
                begun.request_id,
                A3Authorization {
                    credential_id: credential,
                    proof_bytes: b"proof",
                },
            )
            .await
            .unwrap();
        store
            .claim_managed_challenge_material(begun.request_id, current_unix().unwrap())
            .await
            .unwrap();
        assert_eq!(
            store
                .mark_claimed_managed_challenges_indeterminate()
                .await
                .unwrap(),
            1
        );
        assert!(matches!(
            store
                .complete_managed_challenge(begun.request_id, b"late result", &[0x44; 64])
                .await,
            Err(ManagedChallengeError::InvalidState)
        ));
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_stale_session_is_rejected_before_authorization(pool: PgPool) {
        let (store, _keyring, xid, credential, _challenge) = managed_fixture(pool).await;
        let stale_now = current_unix().unwrap() - (CONSENT_TTL + 1);
        let challenge = Challenge {
            version: 1,
            audience: bs58::encode([0xab; 32]).into_string(),
            nonce: vec![11; 32],
            issued_at: stale_now,
            expires_at: stale_now + MAX_CHALLENGE_TTL,
        };
        let begun = store
            .begin_managed_challenge(
                xid,
                &challenge.to_bytes(),
                verifier_commitment("stale session"),
                ManagedChallengeProof::A3,
                Some(b"persisted webauthn verifier state"),
                stale_now,
                &bind_fields(),
            )
            .await
            .unwrap();

        assert!(matches!(
            store
                .authorize_managed_a3(
                    begun.request_id,
                    A3Authorization {
                        credential_id: credential,
                        proof_bytes: b"otherwise valid assertion",
                    },
                )
                .await,
            Err(ManagedChallengeError::Expired)
        ));
        assert!(matches!(
            store
                .claim_managed_challenge_material(begun.request_id, current_unix().unwrap())
                .await,
            Err(ManagedChallengeError::InvalidState)
        ));
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_pre_sign_log_failure_prevents_key_use(pool: PgPool) {
        let (store, _keyring, xid, credential, challenge) = managed_fixture(pool).await;
        let begun = store
            .begin_managed_challenge(
                xid,
                &challenge.to_bytes(),
                verifier_commitment("audit failure"),
                ManagedChallengeProof::A3,
                Some(b"state"),
                current_unix().unwrap(),
                &bind_fields(),
            )
            .await
            .unwrap();
        sqlx::query(
            "CREATE FUNCTION reject_managed_authorization() RETURNS trigger AS $$
             BEGIN
               IF NEW.action = 'signing_instruction_authorized' THEN
                 RAISE EXCEPTION 'injected consent-log failure';
               END IF;
               RETURN NEW;
             END;
             $$ LANGUAGE plpgsql",
        )
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER reject_managed_authorization
             BEFORE INSERT ON consent_log
             FOR EACH ROW EXECUTE FUNCTION reject_managed_authorization()",
        )
        .execute(store.pool())
        .await
        .unwrap();

        assert!(matches!(
            store
                .authorize_managed_a3(
                    begun.request_id,
                    A3Authorization {
                        credential_id: credential,
                        proof_bytes: b"verified assertion",
                    },
                )
                .await,
            Err(ManagedChallengeError::Document(_))
        ));
        let row = sqlx::query("SELECT state FROM managed_challenge_attempts WHERE request_id = $1")
            .bind(begun.request_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(row.try_get::<Option<String>, _>("state").unwrap(), None);
        assert!(matches!(
            store
                .claim_managed_challenge_material(begun.request_id, current_unix().unwrap())
                .await,
            Err(ManagedChallengeError::InvalidState)
        ));
    }

    async fn managed_rotation_fixture(
        pool: PgPool,
    ) -> (
        KeysStore,
        ManagedKeyring,
        Xid,
        Uuid,
        Challenge,
        PrivateKeyBase,
    ) {
        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let operational = OperationalEd25519::generate();
        let document = c2_native(&user, operational.public_keys()).unwrap();
        let xid = Xid::from(document.xid());
        let public = operational_ed25519_public(&document).unwrap();
        let keyring = ManagedKeyring::single("rotation", [0x53; 32]);
        let blob = keyring.seal(xid, &public, operational.seed()).unwrap();
        store
            .create_managed(CustodyRung::C2, &document, &blob)
            .await
            .unwrap();
        let credential = store
            .insert_passkey(xid, b"rotation-credential", b"{}", 0)
            .await
            .unwrap();
        let now = current_unix().unwrap();
        let challenge = Challenge {
            version: 1,
            audience: bs58::encode([0x34; 32]).into_string(),
            nonce: vec![0x35; 32],
            issued_at: now,
            expires_at: now + 300,
        };
        (store, keyring, xid, credential, challenge, user)
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_rotation_before_claim_prevents_old_key_use(pool: PgPool) {
        let (store, keyring, xid, credential, challenge, user) =
            managed_rotation_fixture(pool).await;
        let begun = store
            .begin_managed_challenge(
                xid,
                &challenge.to_bytes(),
                verifier_commitment("rotation loses"),
                ManagedChallengeProof::A3,
                Some(b"state"),
                current_unix().unwrap(),
                &bind_fields(),
            )
            .await
            .unwrap();
        store
            .authorize_managed_a3(
                begun.request_id,
                A3Authorization {
                    credential_id: credential,
                    proof_bytes: b"proof",
                },
            )
            .await
            .unwrap();
        let replacement = OperationalEd25519::generate();
        let rotated = c2_native(&user, replacement.public_keys()).unwrap();
        store.apply_document_update(&user, &rotated).await.unwrap();

        assert!(matches!(
            store
                .finish_authorized_managed_challenge(
                    &keyring,
                    begun.request_id,
                    current_unix().unwrap(),
                )
                .await,
            Err(ManagedChallengeError::BadEnvelope)
        ));
        assert_eq!(
            store
                .retrieve_managed_challenge(begun.request_id, "rotation loses")
                .await
                .unwrap(),
            RetrievedManagedChallenge::Failed
        );
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_claim_before_rotation_completes_once(pool: PgPool) {
        let (store, keyring, xid, credential, challenge, user) =
            managed_rotation_fixture(pool).await;
        let begun = store
            .begin_managed_challenge(
                xid,
                &challenge.to_bytes(),
                verifier_commitment("claim wins rotation"),
                ManagedChallengeProof::A3,
                Some(b"state"),
                current_unix().unwrap(),
                &bind_fields(),
            )
            .await
            .unwrap();
        store
            .authorize_managed_a3(
                begun.request_id,
                A3Authorization {
                    credential_id: credential,
                    proof_bytes: b"proof",
                },
            )
            .await
            .unwrap();
        let claimed = store
            .claim_managed_challenge_material(begun.request_id, current_unix().unwrap())
            .await
            .unwrap();
        let replacement = OperationalEd25519::generate();
        let rotated = c2_native(&user, replacement.public_keys()).unwrap();
        store.apply_document_update(&user, &rotated).await.unwrap();
        let response = keyring
            .open(&claimed.1, claimed.0, &claimed.2)
            .unwrap()
            .respond(&claimed.3)
            .unwrap()
            .to_bytes();
        store
            .complete_managed_challenge(
                begun.request_id,
                &response,
                &keyring
                    .open(&claimed.1, claimed.0, &claimed.2)
                    .unwrap()
                    .sign_classical(&bind_signing_bytes(&claimed.3.to_bytes(), &claimed.4))
                    .unwrap()
                    .bytes,
            )
            .await
            .unwrap();

        assert!(matches!(
            store
                .retrieve_managed_challenge(begun.request_id, "claim wins rotation")
                .await
                .unwrap(),
            RetrievedManagedChallenge::Completed(_)
        ));
    }

    #[test]
    fn managed_challenge_c3_c4_response_shape_matches_managed_response() {
        let challenge = Challenge {
            version: 1,
            audience: bs58::encode([0x56; 32]).into_string(),
            nonce: vec![0x57; 32],
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        };
        let operational = OperationalEd25519::generate();
        let managed_public = match operational.public_keys().signing_public_key() {
            SigningPublicKey::Ed25519(public) => *public.data(),
            _ => panic!("operational key must be Ed25519"),
        };
        let keyring = ManagedKeyring::single("response-shape", [0x58; 32]);
        let blob = keyring
            .seal(xid(), &managed_public, operational.seed())
            .unwrap();
        let managed = keyring
            .open(&blob, xid(), &managed_public)
            .unwrap()
            .respond(&challenge)
            .unwrap();
        let c3 = SoftwareSigner::generate_ed25519()
            .respond(&challenge)
            .unwrap();
        let c4 = SoftwareSigner::generate_ed25519()
            .respond(&challenge)
            .unwrap();
        let managed = Response::from_bytes(&managed.to_bytes()).unwrap();
        let c3 = Response::from_bytes(&c3.to_bytes()).unwrap();
        let c4 = Response::from_bytes(&c4.to_bytes()).unwrap();

        assert_eq!(managed.challenge_bytes, c3.challenge_bytes);
        assert_eq!(managed.challenge_bytes, c4.challenge_bytes);
        assert_eq!(managed.public_key.alg, ClassicalAlg::Ed25519);
        assert_eq!(c3.public_key.alg, ClassicalAlg::Ed25519);
        assert_eq!(c4.public_key.alg, ClassicalAlg::Ed25519);
        assert_eq!(managed.public_key.bytes.len(), c3.public_key.bytes.len());
        assert_eq!(managed.public_key.bytes.len(), c4.public_key.bytes.len());
        assert_eq!(managed.signature.bytes.len(), c3.signature.bytes.len());
        assert_eq!(managed.signature.bytes.len(), c4.signature.bytes.len());
        for response in [&managed, &c3, &c4] {
            verify_classical(
                &response.public_key,
                &signing_payload(&response.challenge_bytes),
                &response.signature,
            )
            .unwrap();
        }
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_claim_wins_before_revocation(pool: PgPool) {
        let (store, keyring, xid, credential, challenge) = managed_fixture(pool).await;
        let begun = store
            .begin_managed_challenge(
                xid,
                &challenge.to_bytes(),
                verifier_commitment("winner"),
                ManagedChallengeProof::A3,
                Some(b"state"),
                current_unix().unwrap(),
                &bind_fields(),
            )
            .await
            .unwrap();
        store
            .authorize_managed_a3(
                begun.request_id,
                A3Authorization {
                    credential_id: credential,
                    proof_bytes: b"proof",
                },
            )
            .await
            .unwrap();
        let claimed = store
            .claim_managed_challenge_material(begun.request_id, current_unix().unwrap())
            .await
            .unwrap();
        store.revoke_device(xid, credential).await.unwrap();
        let response = keyring
            .open(&claimed.1, claimed.0, &claimed.2)
            .unwrap()
            .respond(&claimed.3)
            .unwrap()
            .to_bytes();
        store
            .complete_managed_challenge(
                begun.request_id,
                &response,
                &keyring
                    .open(&claimed.1, claimed.0, &claimed.2)
                    .unwrap()
                    .sign_classical(&bind_signing_bytes(&claimed.3.to_bytes(), &claimed.4))
                    .unwrap()
                    .bytes,
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .retrieve_managed_challenge(begun.request_id, "winner")
                .await
                .unwrap(),
            RetrievedManagedChallenge::Completed(_)
        ));
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn managed_challenge_managed_key_cannot_supply_a4(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let user = OperationalEd25519::generate();
        let managed = OperationalEd25519::generate();
        let managed_signer = SoftwareSigner::from_ed25519_seed(*managed.seed());
        let document = c2_native(user.public_keys(), managed.public_keys()).unwrap();
        let xid = Xid::from(document.xid());
        let public = operational_ed25519_public(&document).unwrap();
        let keyring = ManagedKeyring::single("managed-a4", [0x29; 32]);
        let blob = keyring.seal(xid, &public, managed.seed()).unwrap();
        store
            .create_managed(CustodyRung::C2, &document, &blob)
            .await
            .unwrap();
        let now = current_unix().unwrap();
        let edge = Challenge {
            version: 1,
            audience: bs58::encode([0x12; 32]).into_string(),
            nonce: vec![8; 32],
            issued_at: now,
            expires_at: now + 300,
        };
        let begun = store
            .begin_managed_challenge(
                xid,
                &edge.to_bytes(),
                verifier_commitment("managed key"),
                ManagedChallengeProof::A4,
                None,
                now,
                &bind_fields(),
            )
            .await
            .unwrap();
        let consent = Challenge::from_bytes(&begun.consent_challenge).unwrap();
        let response = managed_signer.respond(&consent).unwrap().to_bytes();
        assert!(matches!(
            store
                .authorize_managed_a4(begun.request_id, &response)
                .await,
            Err(ManagedChallengeError::InvalidProof)
        ));
    }
}
