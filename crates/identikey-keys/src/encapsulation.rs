//! Held user X25519: seal, consent, export, and keyspace §7 unwrap.
//!
//! The operator holds the managed wrap key, so this ceremony is policy.
//! It is not a cryptographic absence of the scalar. The recryption proxy
//! is a different machine and is not given this blob.

use bc_components::{Signature, Verifier};
use bc_xid::{Privilege, XIDDocument};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dcbor::prelude::*;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyAuthentication, PublicKeyCredential, Webauthn};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::consent::{ConsentResult, ProofKind};
use crate::managed_challenge::ManagedKeyring;
use crate::privilege::{c2_wrap_recipient, key_allows};
use crate::rung::AccessLevel;
use crate::store::{ConsentAppend, KeysStore, StoreError, append_consent_tx, decode_document};
use crate::xid::Xid;

const CONSENT_DOMAIN: &[u8] = b"identikey-encapsulation-consent-v1\n";
const CONSENT_TTL: u64 = 5 * 60;
const WRAP_LABEL: &[u8] = b"identikey-keyspace-v1-wrap";
const EXPORT_ACTION: &str = "encapsulation_export";
const UNWRAP_ACTION: &str = "encapsulation_unwrap";

/// Eight small-order Montgomery u-coordinates, little-endian on the wire.
/// The last entry is the non-canonical high-bit encoding of zero, which
/// X25519 would otherwise clear and accept as the identity.
const SMALL_ORDER: [[u8; 32]; 8] = [
    [0; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x80,
    ],
];

#[derive(Debug, thiserror::Error)]
pub enum EncapsulationError {
    #[error("encapsulation purpose is not export or unwrap")]
    BadPurpose,
    #[error("encapsulation attempt was not found")]
    NotFound,
    #[error("encapsulation consent is expired or already used")]
    Expired,
    #[error("encapsulation proof is invalid")]
    InvalidProof,
    #[error("passkey was revoked before the seal was opened")]
    Revoked,
    #[error("wrap does not match the consent digest")]
    WrongWrap,
    #[error("encapsulation seal is missing or cannot be opened")]
    Seal,
    #[error("wrap is not a successful x25519-xchacha20poly1305 unwrap")]
    Wrap,
    #[error("account is not current C2 custody")]
    NotC2,
    #[error("database: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("store: {0}")]
    Store(#[from] StoreError),
}

/// Proof that opens the seal. A4 is an Elect signature over the transcript.
/// A3 is a WebAuthn assertion finished inside this call. Neither is a flag
/// the caller has already decided.
pub enum HeldProof<'a> {
    A4(&'a Signature),
    A3 {
        webauthn: &'a Webauthn,
        credential: &'a PublicKeyCredential,
    },
}

pub struct BeginEncapsulation {
    pub id: Uuid,
    pub challenge: Vec<u8>,
    pub iat: u64,
    pub exp: u64,
}

pub struct BeginEncapsulationRequest<'a> {
    pub xid: Xid,
    pub purpose: &'a str,
    pub challenge: &'a [u8],
    pub wrap: Option<&'a [u8]>,
    pub webauthn_state: Option<&'a [u8]>,
    pub now: u64,
}

/// Transcript bytes pinned by the held-encapsulation contract.
#[must_use]
pub fn encapsulation_transcript(
    purpose: &str,
    xid: &[u8; 32],
    attempt_id: &[u8; 16],
    challenge: &[u8],
    iat: u64,
    exp: u64,
    wrap_digest: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(CONSENT_DOMAIN.len() + 1 + purpose.len() + 96 + challenge.len());
    out.extend_from_slice(CONSENT_DOMAIN);
    let purpose_bytes = purpose.as_bytes();
    let plen = u8::try_from(purpose_bytes.len()).unwrap_or(u8::MAX);
    out.push(plen);
    out.extend(purpose_bytes.iter().take(usize::from(plen)).copied());
    out.extend_from_slice(xid);
    out.extend_from_slice(attempt_id);
    let clen = u16::try_from(challenge.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&clen.to_be_bytes());
    out.extend(challenge.iter().take(usize::from(clen)).copied());
    out.extend_from_slice(&iat.to_be_bytes());
    out.extend_from_slice(&exp.to_be_bytes());
    if purpose == "unwrap" {
        if let Some(digest) = wrap_digest {
            out.extend_from_slice(digest);
        }
    }
    out
}

/// True when an Elect rewrite changed the user X25519 this seal was bound to.
#[must_use]
pub fn wrap_recipient_changed(previous: &XIDDocument, updated: &XIDDocument) -> bool {
    match (c2_wrap_recipient(previous), c2_wrap_recipient(updated)) {
        (Ok(old), Ok(new)) => old != new,
        (Ok(_), Err(_)) => true,
        _ => false,
    }
}

/// Wrap a 32-byte data key to `recipient` with keyspace §7.
pub fn wrap_data_key(recipient: &[u8; 32], ptk: &[u8; 32]) -> Result<Vec<u8>, EncapsulationError> {
    if is_small_order(recipient) {
        return Err(EncapsulationError::Wrap);
    }
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let ephemeral_sk = StaticSecret::from(seed);
    seed.zeroize();
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = seal_ptk(
        &ephemeral_sk,
        ephemeral_pk.as_bytes(),
        recipient,
        ptk,
        &nonce,
    )?;
    encode_wrap(recipient, ephemeral_pk.as_bytes(), &nonce, &ciphertext)
}

impl KeysStore {
    pub async fn begin_encapsulation(
        &self,
        request: BeginEncapsulationRequest<'_>,
    ) -> Result<BeginEncapsulation, EncapsulationError> {
        if request.purpose != "export" && request.purpose != "unwrap" {
            return Err(EncapsulationError::BadPurpose);
        }
        if request.challenge.is_empty() {
            return Err(EncapsulationError::InvalidProof);
        }
        let wrap_digest = match (request.purpose, request.wrap) {
            ("unwrap", Some(wrap)) => Some(sha256(wrap)),
            ("export", None) => None,
            _ => return Err(EncapsulationError::BadPurpose),
        };
        let iat = i64::try_from(request.now).map_err(|_| EncapsulationError::InvalidProof)?;
        let exp_u = request
            .now
            .checked_add(CONSENT_TTL)
            .ok_or(EncapsulationError::InvalidProof)?;
        let exp = i64::try_from(exp_u).map_err(|_| EncapsulationError::InvalidProof)?;
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO encapsulation_attempts
                (id, xid, purpose, webauthn_challenge, webauthn_state, wrap_digest, iat, exp)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(id)
        .bind(request.xid.as_bytes().as_slice())
        .bind(request.purpose)
        .bind(request.challenge)
        .bind(request.webauthn_state)
        .bind(wrap_digest.as_ref().map(|d| d.as_slice()))
        .bind(iat)
        .bind(exp)
        .execute(self.pool())
        .await?;
        Ok(BeginEncapsulation {
            id,
            challenge: request.challenge.to_vec(),
            iat: request.now,
            exp: exp_u,
        })
    }

    /// Export the 32-byte scalar. The server copy stays until a climb that
    /// follows this logged export.
    pub async fn export_encapsulation(
        &self,
        keyring: &ManagedKeyring,
        attempt_id: Uuid,
        proof: HeldProof<'_>,
        now: u64,
    ) -> Result<[u8; 32], EncapsulationError> {
        self.finish_encapsulation(keyring, attempt_id, proof, None, now)
            .await
    }

    /// Unwrap one data key inside this process. No HTTP caller in this change.
    /// The first production caller is `add-recrypt-proxy-vm`.
    pub async fn unwrap_encapsulation(
        &self,
        keyring: &ManagedKeyring,
        attempt_id: Uuid,
        proof: HeldProof<'_>,
        wrap: &[u8],
        now: u64,
    ) -> Result<[u8; 32], EncapsulationError> {
        self.finish_encapsulation(keyring, attempt_id, proof, Some(wrap), now)
            .await
    }

    pub async fn has_encapsulation_key(&self, xid: Xid) -> Result<Option<bool>, StoreError> {
        let present: Option<bool> = sqlx::query_scalar(
            "SELECT (encapsulation_key_blob IS NOT NULL) FROM custody_records WHERE xid = $1",
        )
        .bind(xid.as_bytes().as_slice())
        .fetch_optional(self.pool())
        .await?;
        Ok(present)
    }

    async fn finish_encapsulation(
        &self,
        keyring: &ManagedKeyring,
        attempt_id: Uuid,
        proof: HeldProof<'_>,
        wrap: Option<&[u8]>,
        now: u64,
    ) -> Result<[u8; 32], EncapsulationError> {
        let mut tx = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT xid, purpose, webauthn_challenge, webauthn_state, wrap_digest, iat, exp, used_at
             FROM encapsulation_attempts WHERE id = $1 FOR UPDATE",
        )
        .bind(attempt_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(EncapsulationError::NotFound)?;
        if row
            .try_get::<Option<time::OffsetDateTime>, _>("used_at")?
            .is_some()
        {
            return Err(EncapsulationError::Expired);
        }
        let purpose: String = row.try_get("purpose")?;
        let expected = match wrap {
            Some(_) => "unwrap",
            None => "export",
        };
        if purpose != expected {
            return Err(EncapsulationError::InvalidProof);
        }
        let exp = u64::try_from(row.try_get::<i64, _>("exp")?)
            .map_err(|_| EncapsulationError::Expired)?;
        let iat = u64::try_from(row.try_get::<i64, _>("iat")?)
            .map_err(|_| EncapsulationError::InvalidProof)?;
        if exp <= now {
            return Err(EncapsulationError::Expired);
        }
        let xid = Xid::try_from_slice(&row.try_get::<Vec<u8>, _>("xid")?)
            .map_err(|_| EncapsulationError::NotFound)?;
        let challenge: Vec<u8> = row.try_get("webauthn_challenge")?;
        let stored_digest: Option<Vec<u8>> = row.try_get("wrap_digest")?;
        let webauthn_state: Option<Vec<u8>> = row.try_get("webauthn_state")?;

        let digest_arr = match (&purpose[..], stored_digest.as_deref()) {
            ("unwrap", Some(bytes)) => {
                Some(<[u8; 32]>::try_from(bytes).map_err(|_| EncapsulationError::InvalidProof)?)
            }
            ("export", None) => None,
            _ => return Err(EncapsulationError::InvalidProof),
        };
        if let Some(wrap) = wrap {
            let got = sha256(wrap);
            if digest_arr != Some(got) {
                return Err(EncapsulationError::WrongWrap);
            }
        }

        let custody = sqlx::query(
            "SELECT rung, xid_document, encapsulation_key_blob
             FROM custody_records WHERE xid = $1 FOR UPDATE",
        )
        .bind(xid.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(EncapsulationError::NotFound)?;
        if custody.try_get::<String, _>("rung")? != "c2" {
            return Err(EncapsulationError::NotC2);
        }
        let document = decode_document(&custody.try_get::<Vec<u8>, _>("xid_document")?)?;
        let recipient = recipient_array(&document)?;

        let (access, proof_kind, proof_bytes, credential_id) = match &proof {
            HeldProof::A4(signature) => {
                verify_elect(
                    &document,
                    signature,
                    &transcript_for(
                        &purpose,
                        xid,
                        attempt_id,
                        &challenge,
                        iat,
                        exp,
                        digest_arr.as_ref(),
                    ),
                )?;
                let bytes = cbor_signature(signature);
                (
                    AccessLevel::A4,
                    ProofKind::IdentikeyAuthResponse,
                    bytes,
                    None,
                )
            }
            HeldProof::A3 {
                webauthn,
                credential,
            } => {
                let cred_bytes = credential.get_credential_id().to_vec();
                let cred = sqlx::query(
                    "SELECT id, sign_counter FROM credentials
                     WHERE webauthn_credential_id = $1 AND xid = $2 AND kind = 'passkey'
                       AND revoked_at IS NULL
                     FOR UPDATE",
                )
                .bind(&cred_bytes)
                .bind(xid.as_bytes().as_slice())
                .fetch_optional(&mut *tx)
                .await?;
                let Some(cred) = cred else {
                    return Err(EncapsulationError::Revoked);
                };
                let state_bytes = webauthn_state.ok_or(EncapsulationError::InvalidProof)?;
                let state: PasskeyAuthentication = serde_json::from_slice(&state_bytes)
                    .map_err(|_| EncapsulationError::InvalidProof)?;
                let result = webauthn
                    .finish_passkey_authentication(credential, &state)
                    .map_err(|_| EncapsulationError::InvalidProof)?;
                let counter = i64::from(result.counter());
                let stored_counter: i64 = cred.try_get("sign_counter")?;
                if result.counter() > 0 && counter <= stored_counter {
                    return Err(EncapsulationError::InvalidProof);
                }
                sqlx::query(
                    "UPDATE credentials SET sign_counter = $2 WHERE webauthn_credential_id = $1",
                )
                .bind(&cred_bytes)
                .bind(counter)
                .execute(&mut *tx)
                .await?;
                let assertion =
                    serde_json::to_vec(credential).map_err(|_| EncapsulationError::InvalidProof)?;
                (
                    AccessLevel::A3,
                    ProofKind::WebauthnAssertion,
                    assertion,
                    Some(cred.try_get("id")?),
                )
            }
        };

        let marked = sqlx::query(
            "UPDATE encapsulation_attempts SET used_at = now() WHERE id = $1 AND used_at IS NULL",
        )
        .bind(attempt_id)
        .execute(&mut *tx)
        .await?;
        if marked.rows_affected() != 1 {
            return Err(EncapsulationError::Expired);
        }

        let blob = custody
            .try_get::<Option<Vec<u8>>, _>("encapsulation_key_blob")?
            .ok_or(EncapsulationError::Seal)?;
        let mut scalar = keyring
            .open_encapsulation(&blob, xid, &recipient)
            .map_err(|_| EncapsulationError::Seal)?;

        let returned = if let Some(wrap) = wrap {
            match unwrap_with_scalar(&scalar, wrap, &recipient) {
                Ok(ptk) => {
                    scalar.zeroize();
                    ptk
                }
                Err(err) => {
                    scalar.zeroize();
                    return Err(err);
                }
            }
        } else {
            scalar
        };

        let digest_hex = digest_arr.map(hex_digest);
        let log_purpose = if purpose == "unwrap" {
            digest_hex.as_deref()
        } else {
            Some("export")
        };
        let consent_id = append_consent_tx(
            &mut tx,
            ConsentAppend {
                xid,
                action: if purpose == "unwrap" {
                    UNWRAP_ACTION
                } else {
                    EXPORT_ACTION
                },
                audience: Some("encapsulation"),
                purpose: log_purpose,
                access_level: access,
                credential_id,
                proof_kind,
                proof_bytes: &proof_bytes,
                result: ConsentResult::Signed,
            },
        )
        .await?;
        let ceremony = if purpose == "unwrap" {
            UNWRAP_ACTION
        } else {
            EXPORT_ACTION
        };
        sqlx::query(
            "INSERT INTO custody_events (xid, from_rung, to_rung, ceremony, consent_id)
             VALUES ($1, 'c2', 'c2', $2, $3)",
        )
        .bind(xid.as_bytes().as_slice())
        .bind(ceremony)
        .bind(consent_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(returned)
    }
}

fn transcript_for(
    purpose: &str,
    xid: Xid,
    attempt_id: Uuid,
    challenge: &[u8],
    iat: u64,
    exp: u64,
    wrap_digest: Option<&[u8; 32]>,
) -> Vec<u8> {
    encapsulation_transcript(
        purpose,
        xid.as_bytes(),
        attempt_id.as_bytes(),
        challenge,
        iat,
        exp,
        wrap_digest,
    )
}

fn verify_elect(
    document: &XIDDocument,
    signature: &Signature,
    transcript: &[u8],
) -> Result<(), EncapsulationError> {
    let mut found = false;
    for key in document.keys() {
        if key_allows(key, Privilege::Elect) && !key_allows(key, Privilege::Sign) {
            found = true;
            if !key
                .public_keys()
                .signing_public_key()
                .verify(signature, &transcript)
            {
                return Err(EncapsulationError::InvalidProof);
            }
        }
    }
    if !found {
        return Err(EncapsulationError::NotC2);
    }
    Ok(())
}

fn cbor_signature(signature: &Signature) -> Vec<u8> {
    CBOR::from(signature.clone()).to_cbor_data()
}

fn recipient_array(document: &XIDDocument) -> Result<[u8; 32], EncapsulationError> {
    let bytes = c2_wrap_recipient(document).map_err(|_| EncapsulationError::NotC2)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| EncapsulationError::NotC2)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in digest {
        let hi = usize::from(byte >> 4);
        let lo = usize::from(byte & 0x0f);
        out.push(char::from(*HEX.get(hi).unwrap_or(&b'0')));
        out.push(char::from(*HEX.get(lo).unwrap_or(&b'0')));
    }
    out
}

fn is_small_order(point: &[u8; 32]) -> bool {
    SMALL_ORDER.iter().any(|bad| bad == point)
}

fn seal_ptk(
    ephemeral_sk: &StaticSecret,
    ephemeral_pub: &[u8; 32],
    recipient: &[u8; 32],
    ptk: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, EncapsulationError> {
    let their = PublicKey::from(*recipient);
    let shared = ephemeral_sk.diffie_hellman(&their);
    if !shared.was_contributory() {
        return Err(EncapsulationError::Wrap);
    }
    let mut dh = *shared.as_bytes();
    if dh == [0u8; 32] {
        dh.zeroize();
        return Err(EncapsulationError::Wrap);
    }
    let mut key = wrap_kdf(&dh, ephemeral_pub, recipient);
    dh.zeroize();
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(nonce), ptk.as_slice())
        .map_err(|_| EncapsulationError::Wrap)?;
    key.zeroize();
    Ok(ciphertext)
}

fn wrap_kdf(dh: &[u8; 32], ephemeral: &[u8; 32], recipient: &[u8; 32]) -> [u8; 32] {
    let mut material = Vec::with_capacity(WRAP_LABEL.len() + 96);
    material.extend_from_slice(WRAP_LABEL);
    material.extend_from_slice(dh);
    material.extend_from_slice(ephemeral);
    material.extend_from_slice(recipient);
    let hash = blake3::hash(&material);
    material.zeroize();
    *hash.as_bytes()
}

fn encode_wrap(
    recipient: &[u8; 32],
    ephemeral: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncapsulationError> {
    let mut wrap = Map::new();
    wrap.insert("alg", "x25519-xchacha20poly1305");
    wrap.insert("recipient", CBOR::to_byte_string(recipient));
    wrap.insert("ephemeral", CBOR::to_byte_string(ephemeral));
    wrap.insert("nonce", CBOR::to_byte_string(nonce));
    wrap.insert("ciphertext", CBOR::to_byte_string(ciphertext));
    wrap.insert("epoch", 0_u64);
    Ok(CBOR::from(wrap).to_cbor_data())
}

fn unwrap_with_scalar(
    scalar: &[u8; 32],
    wrap: &[u8],
    expected_recipient: &[u8; 32],
) -> Result<[u8; 32], EncapsulationError> {
    let cbor = CBOR::try_from_data(wrap).map_err(|_| EncapsulationError::Wrap)?;
    let map = match cbor.into_case() {
        CBORCase::Map(map) => map,
        _ => return Err(EncapsulationError::Wrap),
    };
    let alg: String = map.extract("alg").map_err(|_| EncapsulationError::Wrap)?;
    if alg != "x25519-xchacha20poly1305" {
        return Err(EncapsulationError::Wrap);
    }
    let WrapParts {
        recipient,
        ephemeral,
        nonce,
        ciphertext,
    } = parse_wrap_fields(&map)?;
    if recipient != *expected_recipient || is_small_order(&ephemeral) {
        return Err(EncapsulationError::Wrap);
    }
    let sk = StaticSecret::from(*scalar);
    let their = PublicKey::from(ephemeral);
    let shared = sk.diffie_hellman(&their);
    if !shared.was_contributory() {
        return Err(EncapsulationError::Wrap);
    }
    let mut dh = *shared.as_bytes();
    if dh == [0u8; 32] {
        dh.zeroize();
        return Err(EncapsulationError::Wrap);
    }
    let mut key = wrap_kdf(&dh, &ephemeral, &recipient);
    dh.zeroize();
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut plain = cipher
        .decrypt(XNonce::from_slice(nonce.as_slice()), ciphertext.as_slice())
        .map_err(|_| EncapsulationError::Wrap)?;
    key.zeroize();
    let ptk: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| EncapsulationError::Wrap)?;
    plain.zeroize();
    Ok(ptk)
}

fn bytes32(bytes: &impl AsRef<[u8]>) -> Result<[u8; 32], EncapsulationError> {
    <[u8; 32]>::try_from(bytes.as_ref()).map_err(|_| EncapsulationError::Wrap)
}

fn bytes24(bytes: &impl AsRef<[u8]>) -> Result<[u8; 24], EncapsulationError> {
    <[u8; 24]>::try_from(bytes.as_ref()).map_err(|_| EncapsulationError::Wrap)
}

struct WrapParts {
    recipient: [u8; 32],
    ephemeral: [u8; 32],
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

fn parse_wrap_fields(map: &Map) -> Result<WrapParts, EncapsulationError> {
    let recipient: ByteString = map
        .extract("recipient")
        .map_err(|_| EncapsulationError::Wrap)?;
    let ephemeral: ByteString = map
        .extract("ephemeral")
        .map_err(|_| EncapsulationError::Wrap)?;
    let nonce: ByteString = map.extract("nonce").map_err(|_| EncapsulationError::Wrap)?;
    let ciphertext: ByteString = map
        .extract("ciphertext")
        .map_err(|_| EncapsulationError::Wrap)?;
    Ok(WrapParts {
        recipient: bytes32(&recipient)?,
        ephemeral: bytes32(&ephemeral)?,
        nonce: bytes24(&nonce)?,
        ciphertext: ciphertext.to_vec(),
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use bc_components::{
        EncapsulationPublicKey, Encrypter, PrivateKeyBase, PublicKeysProvider, Signer, URI,
        X25519PrivateKey, XIDProvider,
    };
    use bc_xid::{Key, Privilege, XIDGenesisMarkOptions, XIDInceptionKeyOptions};
    use sha2::{Digest, Sha256};
    use sqlx::PgPool;
    use webauthn_rs::prelude::{PublicKeyCredential, Url, WebauthnBuilder};

    use super::*;
    use crate::consent::{ConsentResult, ProofKind};
    use crate::managed_challenge::OperationalEd25519;
    use crate::privilege::{USER_C2_PRIVILEGES, c2_native};
    use crate::rung::{AccessLevel, CustodyRung};
    use crate::store::ConsentAppend;

    const NOW: u64 = 1_700_000_000;

    fn digest(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn keyring() -> ManagedKeyring {
        ManagedKeyring::single("v1", [0x44; 32])
    }

    #[test]
    fn pinned_transcript_digests_match() {
        let export = encapsulation_transcript(
            "export",
            &[0x11; 32],
            &[0x22; 16],
            &[0x33; 32],
            1_700_000_000,
            1_700_000_300,
            None,
        );
        let export_hex = hex_digest(digest(&export));
        assert_eq!(
            export_hex,
            "7d93d9c193c5a60338be4d9b646c1429bfc62718da3e67c2954673627a6d2061"
        );
        let unwrap = encapsulation_transcript(
            "unwrap",
            &[0x11; 32],
            &[0x22; 16],
            &[0x33; 32],
            1_700_000_000,
            1_700_000_300,
            Some(&[0x44; 32]),
        );
        assert_eq!(
            hex_digest(digest(&unwrap)),
            "b18286bad604fc6da5425928d1f0892201b137bdcc9633e90b00bb93af0a558f"
        );
    }

    #[test]
    fn ikek_rejects_ikmk_and_a_swapped_binding() {
        let user = PrivateKeyBase::new();
        let operational = OperationalEd25519::generate();
        let doc = c2_native(&user, operational.public_keys()).unwrap();
        let xid = Xid::from(doc.xid());
        let scalar = *user.x25519_private_key().data();
        let recipient: [u8; 32] = c2_wrap_recipient(&doc).unwrap().try_into().unwrap();
        let keys = keyring();
        let op_pub = crate::operational_ed25519_public(&doc).unwrap();
        let ikmk = keys.seal(xid, &op_pub, operational.seed()).unwrap();
        let ikek = keys.seal_encapsulation(xid, &recipient, &scalar).unwrap();
        assert!(keys.open_encapsulation(&ikmk, xid, &recipient).is_err());
        assert!(keys.open(&ikek, xid, &op_pub).is_err());
        let opened = keys.open_encapsulation(&ikek, xid, &recipient).unwrap();
        assert_eq!(opened, scalar);
        assert_eq!(
            X25519PrivateKey::from_data(opened).public_key().as_bytes(),
            recipient.as_slice()
        );
        let other = Xid::try_from_slice(&[0x99; 32]).unwrap();
        assert!(keys.open_encapsulation(&ikek, other, &recipient).is_err());
        let mut swapped = recipient;
        swapped[0] ^= 0xff;
        assert!(keys.open_encapsulation(&ikek, xid, &swapped).is_err());
        let EncapsulationPublicKey::X25519(companion) =
            operational.public_keys().encapsulation_public_key()
        else {
            panic!("operational encapsulation is not x25519");
        };
        assert_ne!(companion.as_bytes(), recipient.as_slice());
    }

    #[test]
    fn section7_round_trip_and_small_order_ephemeral() {
        let user = PrivateKeyBase::new();
        let doc = c2_native(&user, &PrivateKeyBase::new()).unwrap();
        let recipient: [u8; 32] = c2_wrap_recipient(&doc).unwrap().try_into().unwrap();
        let scalar = *user.x25519_private_key().data();
        let ptk = [0xab; 32];
        let wrapped = wrap_data_key(&recipient, &ptk).unwrap();
        assert_eq!(
            unwrap_with_scalar(&scalar, &wrapped, &recipient).unwrap(),
            ptk
        );
        let mut bad = Map::new();
        bad.insert("alg", "x25519-xchacha20poly1305");
        bad.insert("recipient", CBOR::to_byte_string(recipient));
        bad.insert("ephemeral", CBOR::to_byte_string([0u8; 32]));
        bad.insert("nonce", CBOR::to_byte_string([1u8; 24]));
        bad.insert("ciphertext", CBOR::to_byte_string([2u8; 48]));
        bad.insert("epoch", 0_u64);
        let forged = CBOR::from(bad).to_cbor_data();
        assert!(matches!(
            unwrap_with_scalar(&scalar, &forged, &recipient),
            Err(EncapsulationError::Wrap)
        ));
        let mut unknown = Map::new();
        unknown.insert("alg", "not-a-wrap");
        unknown.insert("recipient", CBOR::to_byte_string(recipient));
        unknown.insert("ephemeral", CBOR::to_byte_string([3u8; 32]));
        unknown.insert("nonce", CBOR::to_byte_string([1u8; 24]));
        unknown.insert("ciphertext", CBOR::to_byte_string([2u8; 48]));
        unknown.insert("epoch", 0_u64);
        assert!(
            unwrap_with_scalar(&scalar, &CBOR::from(unknown).to_cbor_data(), &recipient).is_err()
        );
    }

    struct Sealed {
        xid: Xid,
        user: PrivateKeyBase,
        doc: bc_xid::XIDDocument,
        scalar: [u8; 32],
    }

    async fn sealed(pool: &PgPool) -> (KeysStore, ManagedKeyring, Sealed) {
        let store = KeysStore::from_pool(pool.clone());
        let user = PrivateKeyBase::new();
        let operational = OperationalEd25519::generate();
        let doc = c2_native(&user, operational.public_keys()).unwrap();
        let xid = Xid::from(doc.xid());
        let scalar = *user.x25519_private_key().data();
        let recipient: [u8; 32] = c2_wrap_recipient(&doc).unwrap().try_into().unwrap();
        let keys = keyring();
        let blob = keys.seal_encapsulation(xid, &recipient, &scalar).unwrap();
        let op_pub = crate::operational_ed25519_public(&doc).unwrap();
        let managed = keys.seal(xid, &op_pub, operational.seed()).unwrap();
        store
            .create_managed_with_encapsulation(CustodyRung::C2, &doc, &managed, Some(&blob))
            .await
            .unwrap();
        (
            store,
            keys,
            Sealed {
                xid,
                user,
                doc,
                scalar,
            },
        )
    }

    fn begin<'a>(
        xid: Xid,
        purpose: &'a str,
        challenge: &'a [u8],
        wrap: Option<&'a [u8]>,
    ) -> BeginEncapsulationRequest<'a> {
        BeginEncapsulationRequest {
            xid,
            purpose,
            challenge,
            wrap,
            webauthn_state: None,
            now: NOW,
        }
    }

    async fn consent_actions(store: &KeysStore, xid: Xid) -> Vec<String> {
        sqlx::query_scalar("SELECT action FROM consent_log WHERE xid = $1 ORDER BY seq")
            .bind(xid.as_bytes().as_slice())
            .fetch_all(store.pool())
            .await
            .unwrap()
    }

    #[sqlx::test]
    async fn export_returns_the_scalar_and_keeps_the_seal(pool: PgPool) {
        let (store, keys, sealed) = sealed(&pool).await;
        let again = KeysStore::from_pool(pool);
        let begun = again
            .begin_encapsulation(begin(sealed.xid, "export", &[0x33; 32], None))
            .await
            .unwrap();
        let transcript = encapsulation_transcript(
            "export",
            sealed.xid.as_bytes(),
            begun.id.as_bytes(),
            &begun.challenge,
            begun.iat,
            begun.exp,
            None,
        );
        let signature = sealed.user.sign(&transcript).unwrap();
        let scalar = again
            .export_encapsulation(&keys, begun.id, HeldProof::A4(&signature), NOW)
            .await
            .unwrap();
        assert_eq!(scalar, sealed.scalar);
        assert_eq!(
            store.has_encapsulation_key(sealed.xid).await.unwrap(),
            Some(true)
        );
        assert_eq!(
            consent_actions(&store, sealed.xid).await,
            vec!["encapsulation_export".to_string()]
        );
        let events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM custody_events WHERE xid = $1 AND ceremony = 'encapsulation_export'",
        )
        .bind(sealed.xid.as_bytes().as_slice())
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(events, 1);
        let err = again
            .export_encapsulation(&keys, begun.id, HeldProof::A4(&signature), NOW)
            .await
            .unwrap_err();
        assert!(matches!(err, EncapsulationError::Expired));
    }

    #[sqlx::test]
    async fn unwrap_uses_only_the_proof_and_refuses_a_different_wrap(pool: PgPool) {
        let (store, keys, sealed) = sealed(&pool).await;
        let reader = KeysStore::from_pool(pool);
        let recipient: [u8; 32] = c2_wrap_recipient(&sealed.doc).unwrap().try_into().unwrap();
        let ptk = [0xcd; 32];
        let wrapped = wrap_data_key(&recipient, &ptk).unwrap();
        let other = wrap_data_key(&recipient, &[0x11; 32]).unwrap();
        let begun = reader
            .begin_encapsulation(begin(sealed.xid, "unwrap", &[0x33; 32], Some(&wrapped)))
            .await
            .unwrap();
        let transcript = encapsulation_transcript(
            "unwrap",
            sealed.xid.as_bytes(),
            begun.id.as_bytes(),
            &begun.challenge,
            begun.iat,
            begun.exp,
            Some(&digest(&wrapped)),
        );
        let signature = sealed.user.sign(&transcript).unwrap();
        let err = reader
            .unwrap_encapsulation(&keys, begun.id, HeldProof::A4(&signature), &other, NOW)
            .await
            .unwrap_err();
        assert!(matches!(err, EncapsulationError::WrongWrap));
        assert!(consent_actions(&store, sealed.xid).await.is_empty());
        let got = reader
            .unwrap_encapsulation(&keys, begun.id, HeldProof::A4(&signature), &wrapped, NOW)
            .await
            .unwrap();
        assert_eq!(got, ptk);
        assert_eq!(
            consent_actions(&store, sealed.xid).await,
            vec!["encapsulation_unwrap".to_string()]
        );
    }

    #[sqlx::test]
    async fn managed_challenge_transcript_cannot_export(pool: PgPool) {
        let (_store, keys, sealed) = sealed(&pool).await;
        let begun = _store
            .begin_encapsulation(begin(sealed.xid, "export", &[0x33; 32], None))
            .await
            .unwrap();
        let signature = sealed
            .user
            .sign(b"identikey-managed-consent-v1\nexport")
            .unwrap();
        let err = _store
            .export_encapsulation(&keys, begun.id, HeldProof::A4(&signature), NOW)
            .await
            .unwrap_err();
        assert!(matches!(err, EncapsulationError::InvalidProof));
        assert_eq!(
            _store.has_encapsulation_key(sealed.xid).await.unwrap(),
            Some(true)
        );
    }

    #[sqlx::test]
    async fn null_seal_and_small_order_fail_closed(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &[0x51, 0x47])
            .await
            .unwrap();
        let recipient: [u8; 32] = c2_wrap_recipient(&doc).unwrap().try_into().unwrap();
        let wrapped = wrap_data_key(&recipient, &[0xab; 32]).unwrap();
        let begun = store
            .begin_encapsulation(begin(xid, "unwrap", &[9], Some(&wrapped)))
            .await
            .unwrap();
        let transcript = encapsulation_transcript(
            "unwrap",
            xid.as_bytes(),
            begun.id.as_bytes(),
            &begun.challenge,
            begun.iat,
            begun.exp,
            Some(&digest(&wrapped)),
        );
        let signature = user.sign(&transcript).unwrap();
        let err = store
            .unwrap_encapsulation(
                &keyring(),
                begun.id,
                HeldProof::A4(&signature),
                &wrapped,
                NOW,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, EncapsulationError::Seal));
    }

    #[sqlx::test]
    async fn small_order_wrap_does_not_return_a_data_key(pool: PgPool) {
        let (store, keys, sealed) = sealed(&pool).await;
        let recipient: [u8; 32] = c2_wrap_recipient(&sealed.doc).unwrap().try_into().unwrap();
        let mut bad = Map::new();
        bad.insert("alg", "x25519-xchacha20poly1305");
        bad.insert("recipient", CBOR::to_byte_string(recipient));
        bad.insert("ephemeral", CBOR::to_byte_string([0u8; 32]));
        bad.insert("nonce", CBOR::to_byte_string([1u8; 24]));
        bad.insert("ciphertext", CBOR::to_byte_string([2u8; 48]));
        bad.insert("epoch", 0_u64);
        let forged = CBOR::from(bad).to_cbor_data();
        let begun = store
            .begin_encapsulation(begin(sealed.xid, "unwrap", &[0x33; 32], Some(&forged)))
            .await
            .unwrap();
        let transcript = encapsulation_transcript(
            "unwrap",
            sealed.xid.as_bytes(),
            begun.id.as_bytes(),
            &begun.challenge,
            begun.iat,
            begun.exp,
            Some(&digest(&forged)),
        );
        let signature = sealed.user.sign(&transcript).unwrap();
        let err = store
            .unwrap_encapsulation(&keys, begun.id, HeldProof::A4(&signature), &forged, NOW)
            .await
            .unwrap_err();
        assert!(matches!(err, EncapsulationError::Wrap));
        assert!(consent_actions(&store, sealed.xid).await.is_empty());
        assert_eq!(
            store.has_encapsulation_key(sealed.xid).await.unwrap(),
            Some(true)
        );
    }

    #[sqlx::test]
    async fn climb_requires_a_logged_export(pool: PgPool) {
        let (store, keys, sealed) = sealed(&pool).await;
        let c3 = c3_doc(&sealed.doc, &sealed.user, &store, sealed.xid).await;
        let bytes = {
            let cbor = CBOR::from(c3.clone());
            cbor.to_cbor_data()
        };
        let sig = sealed.user.sign(&bytes).unwrap();
        let err = store
            .migrate_c2_to_c3(&c3, &sig, &sealed.user, climb_consent(sealed.xid), None)
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::EncapsulationExportRequired));
        assert_eq!(
            store.get_custody(sealed.xid).await.unwrap().unwrap().rung,
            CustodyRung::C2
        );
        assert_eq!(
            store.has_encapsulation_key(sealed.xid).await.unwrap(),
            Some(true)
        );

        let begun = store
            .begin_encapsulation(begin(sealed.xid, "export", &[0x33; 32], None))
            .await
            .unwrap();
        let transcript = encapsulation_transcript(
            "export",
            sealed.xid.as_bytes(),
            begun.id.as_bytes(),
            &begun.challenge,
            begun.iat,
            begun.exp,
            None,
        );
        let export_sig = sealed.user.sign(&transcript).unwrap();
        store
            .export_encapsulation(&keys, begun.id, HeldProof::A4(&export_sig), NOW)
            .await
            .unwrap();
        store
            .migrate_c2_to_c3(&c3, &sig, &sealed.user, climb_consent(sealed.xid), None)
            .await
            .unwrap();
        assert_eq!(
            store.has_encapsulation_key(sealed.xid).await.unwrap(),
            Some(false)
        );
        assert_eq!(
            store.has_managed_key(sealed.xid).await.unwrap(),
            Some(false)
        );
    }

    #[sqlx::test]
    async fn elect_rewrite_of_the_recipient_nulls_the_seal(pool: PgPool) {
        let (store, _keys, sealed) = sealed(&pool).await;
        let mut updated = sealed.doc.clone();
        updated.remove_key(&sealed.user).unwrap();
        let replacement = PrivateKeyBase::new();
        let mut key = Key::new(replacement.public_keys());
        for privilege in USER_C2_PRIVILEGES {
            key.add_permission(privilege);
        }
        updated.add_key(key).unwrap();
        store
            .apply_document_update(&sealed.user, &updated)
            .await
            .unwrap();
        assert_eq!(
            store.has_encapsulation_key(sealed.xid).await.unwrap(),
            Some(false)
        );
    }

    #[sqlx::test]
    async fn revocation_wins_the_export_race(pool: PgPool) {
        let (store, keys, sealed) = sealed(&pool).await;
        let cred_id = [1u8, 2, 3];
        let passkey = store
            .insert_passkey(sealed.xid, &cred_id, br#"{"ok":true}"#, 0)
            .await
            .unwrap();
        store.revoke_device(sealed.xid, passkey).await.unwrap();
        let begun = store
            .begin_encapsulation(begin(sealed.xid, "export", &[0x33; 32], None))
            .await
            .unwrap();
        let credential: PublicKeyCredential = serde_json::from_str(
            r#"{"id":"AQID","rawId":"AQID","type":"public-key","response":{"authenticatorData":"AQID","clientDataJSON":"AQID","signature":"AQID"}}"#,
        )
        .unwrap();
        let webauthn =
            WebauthnBuilder::new("localhost", &Url::parse("http://localhost:8080").unwrap())
                .unwrap()
                .build()
                .unwrap();
        let err = store
            .export_encapsulation(
                &keys,
                begun.id,
                HeldProof::A3 {
                    webauthn: &webauthn,
                    credential: &credential,
                },
                NOW,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, EncapsulationError::Revoked));
        assert!(consent_actions(&store, sealed.xid).await.is_empty());
        assert_eq!(
            store.has_encapsulation_key(sealed.xid).await.unwrap(),
            Some(true)
        );
    }

    fn climb_consent(xid: Xid) -> ConsentAppend<'static> {
        ConsentAppend {
            xid,
            action: "c2_to_c3",
            audience: None,
            purpose: Some("leave managed custody"),
            access_level: AccessLevel::A3,
            credential_id: None,
            proof_kind: ProofKind::WebauthnAssertion,
            proof_bytes: b"assertion",
            result: ConsentResult::Signed,
        }
    }

    async fn c3_doc(
        c2: &bc_xid::XIDDocument,
        user: &PrivateKeyBase,
        store: &KeysStore,
        xid: Xid,
    ) -> bc_xid::XIDDocument {
        let ours = store.get_custody(xid).await.unwrap().unwrap().document;
        let sign_key = ours
            .keys()
            .iter()
            .find(|key| {
                crate::privilege::key_allows(key, Privilege::Sign)
                    && !crate::privilege::key_allows(key, Privilege::Elect)
            })
            .unwrap()
            .clone();
        let mut c3 = c2.clone();
        c3.remove_key(&sign_key).unwrap();
        let mut user_key = c3.take_key(user).unwrap();
        user_key.add_permission(Privilege::Sign);
        user_key.add_permission(Privilege::Auth);
        c3.add_key(user_key).unwrap();
        c3.add_resolution_method(URI::new("https://auth.identikey.me/.well-known/xid").unwrap());
        c3.add_resolution_method(URI::new("https://resolver.example/.well-known/xid").unwrap());
        let tmp = bc_xid::XIDDocument::new(
            XIDInceptionKeyOptions::Default,
            XIDGenesisMarkOptions::Passphrase("c3-mark".to_owned(), None, None, None),
        );
        c3.set_provenance(tmp.provenance().cloned());
        c3
    }
}
