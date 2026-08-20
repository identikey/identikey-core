//! Durable store. Elect is checked against the row, not the caller.

use bc_components::{PublicKeysProvider, Signature, XIDProvider};
use bc_xid::XIDDocument;
use dcbor::prelude::*;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::MIGRATOR;
use crate::ceremony::{
    CeremonyError, check_resolution, parse_successor_digest, validate_c2_to_c3,
    verify_successor_digest,
};
use crate::consent::{ConsentHashInput, ConsentResult, ProofKind, hash_consent_entry, hash_proof};
use crate::privilege::{PrivilegeError, authorize_elect, is_c2};
use crate::rung::{AccessLevel, CustodyRung};
use crate::xid::Xid;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error(transparent)]
    Privilege(#[from] PrivilegeError),
    #[error("no custody record for this XID")]
    NotFound,
    #[error("XID in the new document does not match the stored identity")]
    XidMismatch,
    #[error("rung {0} is not a managed (C1/C2) create")]
    NotManagedRung(CustodyRung),
    #[error("document does not match the requested rung")]
    DocumentRungMismatch,
    #[error("XID document: {0}")]
    Document(String),
    #[error(transparent)]
    Ceremony(#[from] CeremonyError),
    #[error("consent proof must be A3 or A4")]
    ConsentProofNotAccess,
    #[error("stored XID is not 32 bytes")]
    BadXid,
}

#[derive(Clone)]
pub struct KeysStore {
    pool: PgPool,
}

#[derive(Debug, Clone)]
pub struct StoredCustody {
    pub xid: Xid,
    pub rung: CustodyRung,
    pub document: XIDDocument,
}

#[derive(Debug, Clone)]
pub struct StoredAccount {
    pub xid: Xid,
}

/// Bytes we will serve as a convenience resolver. No key material.
#[derive(Debug, Clone)]
pub struct PublishedDocument {
    pub bytes: Vec<u8>,
    pub updated_at: OffsetDateTime,
}

/// Stored passkey row. `passkey_json` is the serialised `webauthn-rs` Passkey.
#[derive(Debug, Clone)]
pub struct StoredPasskey {
    pub xid: Xid,
    pub credential_id: Vec<u8>,
    pub passkey_json: Vec<u8>,
    pub sign_counter: i64,
}

/// A credential listed as a device. No public keys, no trust flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub id: Uuid,
    pub kind: String,
    pub nickname: Option<String>,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

fn stored_passkey(
    xid: Vec<u8>,
    webauthn_credential_id: Option<Vec<u8>>,
    cose_public_key: Option<Vec<u8>>,
    sign_counter: Option<i64>,
) -> Result<StoredPasskey, StoreError> {
    Ok(StoredPasskey {
        xid: Xid::try_from_slice(&xid).map_err(|_| StoreError::BadXid)?,
        credential_id: webauthn_credential_id.ok_or(StoreError::NotFound)?,
        passkey_json: cose_public_key.ok_or(StoreError::NotFound)?,
        sign_counter: sign_counter.ok_or(StoreError::NotFound)?,
    })
}

pub struct ConsentAppend<'a> {
    pub xid: Xid,
    pub action: &'a str,
    pub audience: Option<&'a str>,
    pub purpose: Option<&'a str>,
    pub access_level: AccessLevel,
    pub credential_id: Option<Uuid>,
    pub proof_kind: ProofKind,
    pub proof_bytes: &'a [u8],
    pub result: ConsentResult,
}

impl KeysStore {
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new().max_connections(8).connect(url).await?;
        Ok(Self { pool })
    }

    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<(), StoreError> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Create a C1/C2 identity: account + custody row + signup event.
    pub async fn create_managed(
        &self,
        rung: CustodyRung,
        document: &XIDDocument,
        managed_key_blob: &[u8],
    ) -> Result<Xid, StoreError> {
        if !rung.holds_managed_key() {
            return Err(StoreError::NotManagedRung(rung));
        }
        match rung {
            CustodyRung::C2 if !is_c2(document) => {
                return Err(StoreError::DocumentRungMismatch);
            }
            CustodyRung::C1 if is_c2(document) => {
                return Err(StoreError::DocumentRungMismatch);
            }
            _ => {}
        }

        let xid = Xid::from(document.xid());
        let xid_bytes = xid.as_bytes().as_slice();
        let bytes = encode_document(document)?;
        let rung_s = rung.as_str();
        let mut tx = self.pool.begin().await?;
        sqlx::query!("INSERT INTO accounts (xid) VALUES ($1)", xid_bytes)
            .execute(&mut *tx)
            .await?;
        sqlx::query!(
            "INSERT INTO custody_records (xid, rung, xid_document, managed_key_blob)
             VALUES ($1, $2, $3, $4)",
            xid_bytes,
            rung_s,
            &bytes,
            managed_key_blob
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            "INSERT INTO custody_events (xid, from_rung, to_rung, ceremony)
             VALUES ($1, NULL, $2, 'signup')",
            xid_bytes,
            rung_s
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(xid)
    }

    pub async fn get_account(&self, xid: Xid) -> Result<Option<StoredAccount>, StoreError> {
        let row = sqlx::query!(
            "SELECT xid FROM accounts WHERE xid = $1",
            xid.as_bytes().as_slice()
        )
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some(rec) => Ok(Some(StoredAccount {
                xid: Xid::try_from_slice(&rec.xid)
                    .map_err(|e| StoreError::Document(e.to_string()))?,
            })),
        }
    }

    pub async fn get_custody(&self, xid: Xid) -> Result<Option<StoredCustody>, StoreError> {
        let row = sqlx::query!(
            "SELECT xid, rung, xid_document FROM custody_records WHERE xid = $1",
            xid.as_bytes().as_slice()
        )
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some(rec) => Ok(Some(StoredCustody {
                xid: Xid::try_from_slice(&rec.xid)
                    .map_err(|e| StoreError::Document(e.to_string()))?,
                rung: rec
                    .rung
                    .parse()
                    .map_err(|e: crate::ParseRungError| StoreError::Document(e.to_string()))?,
                document: decode_document(&rec.xid_document)?,
            })),
        }
    }

    /// Raw document bytes. Used to prove a denied update did not write.
    pub async fn document_bytes(&self, xid: Xid) -> Result<Option<Vec<u8>>, StoreError> {
        let row = sqlx::query!(
            "SELECT xid_document FROM custody_records WHERE xid = $1",
            xid.as_bytes().as_slice()
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|rec| rec.xid_document))
    }

    /// Document bytes for the well-known resolver. Missing or disabled → `None`.
    pub async fn published_document(
        &self,
        xid: Xid,
    ) -> Result<Option<PublishedDocument>, StoreError> {
        let row = sqlx::query!(
            "SELECT c.xid_document, c.updated_at
             FROM custody_records c
             JOIN accounts a ON a.xid = c.xid
             WHERE c.xid = $1 AND a.disabled_at IS NULL",
            xid.as_bytes().as_slice()
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|rec| PublishedDocument {
            bytes: rec.xid_document,
            updated_at: rec.updated_at,
        }))
    }

    /// Persist a new XID document only if `signer` holds Elect on the stored one.
    ///
    /// On a C2 row the new document must still be C2. Privilege-shape change
    /// that drops our Sign key goes through [`Self::migrate_c2_to_c3`].
    pub async fn apply_document_update(
        &self,
        signer: &impl PublicKeysProvider,
        new_document: &XIDDocument,
    ) -> Result<(), StoreError> {
        let xid = Xid::from(new_document.xid());
        let new_bytes = encode_document(new_document)?;
        let mut tx = self.pool.begin().await?;
        apply_document_update_tx(&mut tx, xid, signer, new_document, &new_bytes).await?;
        tx.commit().await?;
        Ok(())
    }

    /// C2→C3 exit. One UPDATE of document + NULL blob + `rung = c3`.
    ///
    /// `successor_digest` on the row is the pre-rotation slot (32-byte
    /// SHA-256, or NULL). v1 leaves it NULL. When set, the locally
    /// generated successor key material must match before the climb is
    /// treated as complete (`identikey-core-4qd`).
    pub async fn migrate_c2_to_c3(
        &self,
        new_document: &XIDDocument,
        elect_signature: &Signature,
        signer: &impl PublicKeysProvider,
        consent: ConsentAppend<'_>,
        local_successor_public_or_cbor: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        match (consent.access_level, consent.proof_kind) {
            (
                AccessLevel::A3 | AccessLevel::A4,
                ProofKind::WebauthnAssertion | ProofKind::IdentikeyAuthResponse,
            ) => {}
            _ => return Err(StoreError::ConsentProofNotAccess),
        }

        let xid = Xid::from(new_document.xid());
        if consent.xid != xid {
            return Err(StoreError::XidMismatch);
        }
        let new_bytes = encode_document(new_document)?;
        let mut tx = self.pool.begin().await?;

        let xid_bytes = xid.as_bytes().as_slice();
        let row = sqlx::query!(
            "SELECT xid_document, rung, successor_digest
             FROM custody_records WHERE xid = $1 FOR UPDATE",
            xid_bytes
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Err(StoreError::NotFound);
        };
        let stored_rung: CustodyRung = row
            .rung
            .parse()
            .map_err(|e: crate::ParseRungError| StoreError::Document(e.to_string()))?;
        let stored = decode_document(&row.xid_document)?;
        let published = match row.successor_digest.as_deref() {
            None => None,
            Some(bytes) => Some(parse_successor_digest(bytes)?),
        };
        // ADR-011: Elect-gated by the user. Still verify a published
        // digest when the column is set. NULL skips (v1 default).
        verify_successor_digest(
            published.as_ref(),
            local_successor_public_or_cbor.unwrap_or(&[]),
        )?;
        validate_c2_to_c3(
            stored_rung,
            &stored,
            new_document,
            elect_signature,
            signer,
            &new_bytes,
        )?;

        let consent_id = append_consent_tx(&mut tx, consent).await?;
        sqlx::query!(
            "UPDATE custody_records
             SET xid_document = $2, managed_key_blob = NULL, rung = 'c3', updated_at = now()
             WHERE xid = $1",
            xid_bytes,
            &new_bytes
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            "INSERT INTO custody_events (xid, from_rung, to_rung, ceremony, consent_id)
             VALUES ($1, 'c2', 'c3', 'c2_to_c3', $2)",
            xid_bytes,
            consent_id
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Whether the managed-key blob is present. Does not return the bytes.
    pub async fn has_managed_key(&self, xid: Xid) -> Result<Option<bool>, StoreError> {
        let row = sqlx::query!(
            "SELECT (managed_key_blob IS NOT NULL) AS present FROM custody_records WHERE xid = $1",
            xid.as_bytes().as_slice()
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|rec| rec.present.unwrap_or(false)))
    }

    pub async fn insert_passkey(
        &self,
        xid: Xid,
        webauthn_credential_id: &[u8],
        cose_public_key: &[u8],
        sign_counter: i64,
    ) -> Result<Uuid, StoreError> {
        let rec = sqlx::query!(
            "INSERT INTO credentials
                (xid, kind, webauthn_credential_id, cose_public_key, sign_counter)
             VALUES ($1, 'passkey', $2, $3, $4)
             RETURNING id",
            xid.as_bytes().as_slice(),
            webauthn_credential_id,
            cose_public_key,
            sign_counter
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(rec.id)
    }

    pub async fn get_passkey_by_credential_id(
        &self,
        webauthn_credential_id: &[u8],
    ) -> Result<Option<StoredPasskey>, StoreError> {
        let row = sqlx::query!(
            "SELECT xid, webauthn_credential_id, cose_public_key, sign_counter
             FROM credentials
             WHERE webauthn_credential_id = $1
               AND kind = 'passkey'
               AND revoked_at IS NULL",
            webauthn_credential_id
        )
        .fetch_optional(&self.pool)
        .await?;
        row.map(|rec| {
            stored_passkey(
                rec.xid,
                rec.webauthn_credential_id,
                rec.cose_public_key,
                rec.sign_counter,
            )
        })
        .transpose()
    }

    pub async fn list_passkeys(&self, xid: Xid) -> Result<Vec<StoredPasskey>, StoreError> {
        let rows = sqlx::query!(
            "SELECT xid, webauthn_credential_id, cose_public_key, sign_counter
             FROM credentials
             WHERE xid = $1
               AND kind = 'passkey'
               AND revoked_at IS NULL
             ORDER BY created_at ASC",
            xid.as_bytes().as_slice()
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|rec| {
                stored_passkey(
                    rec.xid,
                    rec.webauthn_credential_id,
                    rec.cose_public_key,
                    rec.sign_counter,
                )
            })
            .collect()
    }

    pub async fn update_passkey_sign_counter(
        &self,
        webauthn_credential_id: &[u8],
        sign_counter: i64,
    ) -> Result<(), StoreError> {
        let result = sqlx::query!(
            "UPDATE credentials
             SET sign_counter = $2, last_used_at = now()
             WHERE webauthn_credential_id = $1
               AND kind = 'passkey'
               AND revoked_at IS NULL",
            webauthn_credential_id,
            sign_counter
        )
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Non-revoked credentials for this XID. Ids + kind + nickname + timestamps only.
    pub async fn list_devices(&self, xid: Xid) -> Result<Vec<DeviceRecord>, StoreError> {
        let rows = sqlx::query!(
            "SELECT id, kind, nickname, created_at, last_used_at
             FROM credentials
             WHERE xid = $1 AND revoked_at IS NULL
             ORDER BY created_at ASC",
            xid.as_bytes().as_slice()
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|rec| DeviceRecord {
                id: rec.id,
                kind: rec.kind,
                nickname: rec.nickname,
                created_at: rec.created_at,
                last_used_at: rec.last_used_at,
            })
            .collect())
    }

    /// Soft-revoke a credential. Idempotent if `revoked_at` is already set.
    ///
    /// Missing id or a different XID is [`StoreError::NotFound`].
    pub async fn revoke_device(&self, xid: Xid, credential_id: Uuid) -> Result<(), StoreError> {
        let result = sqlx::query!(
            "UPDATE credentials
             SET revoked_at = COALESCE(revoked_at, now())
             WHERE id = $1 AND xid = $2",
            credential_id,
            xid.as_bytes().as_slice()
        )
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    pub async fn append_consent(&self, entry: ConsentAppend<'_>) -> Result<Uuid, StoreError> {
        let mut tx = self.pool.begin().await?;
        let id = append_consent_tx(&mut tx, entry).await?;
        tx.commit().await?;
        Ok(id)
    }
}

async fn apply_document_update_tx(
    tx: &mut Transaction<'_, Postgres>,
    xid: Xid,
    signer: &impl PublicKeysProvider,
    new_document: &XIDDocument,
    new_bytes: &[u8],
) -> Result<(), StoreError> {
    let xid_bytes = xid.as_bytes().as_slice();
    let row = sqlx::query!(
        "SELECT xid_document, rung FROM custody_records WHERE xid = $1 FOR UPDATE",
        xid_bytes
    )
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Err(StoreError::NotFound);
    };
    let previous = decode_document(&row.xid_document)?;
    if Xid::from(new_document.xid()) != xid || Xid::from(previous.xid()) != xid {
        return Err(StoreError::XidMismatch);
    }
    let stored_rung: CustodyRung = row
        .rung
        .parse()
        .map_err(|e: crate::ParseRungError| StoreError::Document(e.to_string()))?;
    if stored_rung == CustodyRung::C2 && !is_c2(new_document) {
        return Err(StoreError::DocumentRungMismatch);
    }
    if matches!(stored_rung, CustodyRung::C3 | CustodyRung::C4) {
        check_resolution(new_document)?;
    }
    authorize_elect(&previous, signer)?;
    sqlx::query!(
        "UPDATE custody_records SET xid_document = $2, updated_at = now() WHERE xid = $1",
        xid_bytes,
        new_bytes
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn append_consent_tx(
    tx: &mut Transaction<'_, Postgres>,
    entry: ConsentAppend<'_>,
) -> Result<Uuid, StoreError> {
    let xid_bytes = entry.xid.as_bytes().as_slice();
    let prev = sqlx::query!(
        "SELECT seq, entry_hash FROM consent_log WHERE xid = $1 ORDER BY seq DESC LIMIT 1",
        xid_bytes
    )
    .fetch_optional(&mut **tx)
    .await?;

    let (seq, prev_hash) = match prev {
        None => (1_u64, None),
        Some(rec) => {
            let seq = u64::try_from(rec.seq).map_err(|e| StoreError::Document(e.to_string()))? + 1;
            let prev = <[u8; 32]>::try_from(rec.entry_hash.as_slice())
                .map_err(|_| StoreError::Document("consent prev_hash is not 32 bytes".into()))?;
            (seq, Some(prev))
        }
    };

    let proof_hash = hash_proof(entry.proof_bytes);
    let input = ConsentHashInput {
        xid: entry.xid,
        seq,
        prev_hash,
        action: entry.action,
        audience: entry.audience,
        purpose: entry.purpose,
        access_level: entry.access_level,
        credential_id: entry.credential_id,
        proof_kind: entry.proof_kind,
        proof_hash,
        result: entry.result,
    };
    let entry_hash = hash_consent_entry(&input);
    let seq_i64 = i64::try_from(seq).map_err(|e| StoreError::Document(e.to_string()))?;
    let prev_hash_slice: Option<&[u8]> = prev_hash.as_ref().map(|h| h.as_slice());

    let rec = sqlx::query!(
        "INSERT INTO consent_log (
            xid, seq, prev_hash, entry_hash,
            action, audience, purpose,
            access_level, credential_id, proof_kind, proof_bytes, proof_hash, result
         ) VALUES (
            $1, $2, $3, $4,
            $5, $6, $7,
            $8, $9, $10, $11, $12, $13
         )
         RETURNING id",
        xid_bytes,
        seq_i64,
        prev_hash_slice,
        entry_hash.as_slice(),
        entry.action,
        entry.audience,
        entry.purpose,
        entry.access_level.as_str(),
        entry.credential_id,
        entry.proof_kind.as_str(),
        entry.proof_bytes,
        proof_hash.as_slice(),
        entry.result.as_str()
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(rec.id)
}

fn encode_document(document: &XIDDocument) -> Result<Vec<u8>, StoreError> {
    let cbor = CBOR::from(document.clone());
    Ok(cbor.to_cbor_data())
}

fn decode_document(bytes: &[u8]) -> Result<XIDDocument, StoreError> {
    let cbor = CBOR::try_from_data(bytes).map_err(|e| StoreError::Document(e.to_string()))?;
    XIDDocument::try_from(cbor).map_err(|e| StoreError::Document(e.to_string()))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use bc_components::PrivateKeyBase;
    use bc_xid::{Key, Privilege};
    use sqlx::PgPool;

    use super::*;
    use crate::ceremony::CeremonyError;
    use crate::privilege::c2_native;

    fn blob() -> Vec<u8> {
        vec![0x51, 0x47]
    }

    #[sqlx::test]
    async fn create_managed_round_trips_c2(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap();

        assert!(store.get_account(xid).await.unwrap().is_some());
        let got = store.get_custody(xid).await.unwrap().unwrap();
        assert_eq!(got.rung, CustodyRung::C2);
        assert!(is_c2(&got.document));
        assert_eq!(Xid::from(got.document.xid()), xid);
    }

    #[sqlx::test]
    async fn identikey_cannot_persist_a_rotation(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap();
        let before = store.document_bytes(xid).await.unwrap().unwrap();

        let attacker = PrivateKeyBase::new();
        let mut forged = doc.clone();
        let mut extra = Key::new(attacker.public_keys());
        extra.add_permission(Privilege::Elect);
        forged.add_key(extra).unwrap();

        let err = store
            .apply_document_update(&ours, &forged)
            .await
            .unwrap_err();
        assert!(
            matches!(err, StoreError::Privilege(PrivilegeError::ElectDenied)),
            "unexpected error: {err}"
        );
        let after = store.document_bytes(xid).await.unwrap().unwrap();
        assert_eq!(before, after);
    }

    #[sqlx::test]
    async fn user_elect_can_persist_a_rotation(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap();
        let before = store.document_bytes(xid).await.unwrap().unwrap();

        let extra_keys = PrivateKeyBase::new();
        let mut updated = store.get_custody(xid).await.unwrap().unwrap().document;
        let mut extra = Key::new(extra_keys.public_keys());
        extra.add_permission(Privilege::Auth);
        updated.add_key(extra).unwrap();

        store.apply_document_update(&user, &updated).await.unwrap();
        let after = store.document_bytes(xid).await.unwrap().unwrap();
        assert_ne!(before, after);
        let got = store.get_custody(xid).await.unwrap().unwrap();
        assert!(got.document.find_key_by_public_keys(&extra_keys).is_some());
        // Our operational privileges must still be Sign+Auth only.
        let our_key = got.document.find_key_by_public_keys(&ours).unwrap();
        assert!(crate::privilege::key_allows(our_key, Privilege::Sign));
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

    fn c3_doc(c2: &XIDDocument, user: &PrivateKeyBase, ours: &PrivateKeyBase) -> XIDDocument {
        use bc_components::URI;
        use bc_xid::{XIDGenesisMarkOptions, XIDInceptionKeyOptions};

        let mut c3 = c2.clone();
        c3.remove_key(ours).unwrap();
        let mut user_key = c3.take_key(user).unwrap();
        user_key.add_permission(Privilege::Sign);
        user_key.add_permission(Privilege::Auth);
        c3.add_key(user_key).unwrap();
        c3.add_resolution_method(URI::new("https://auth.identikey.me/.well-known/xid").unwrap());
        c3.add_resolution_method(URI::new("https://resolver.example/.well-known/xid").unwrap());
        let tmp = XIDDocument::new(
            XIDInceptionKeyOptions::Default,
            XIDGenesisMarkOptions::Passphrase("c3-mark".to_owned(), None, None, None),
        );
        c3.set_provenance(tmp.provenance().cloned());
        c3
    }

    #[sqlx::test]
    async fn apply_document_update_cannot_drop_our_sign(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap();
        let c3 = c3_doc(&doc, &user, &ours);
        let err = store.apply_document_update(&user, &c3).await.unwrap_err();
        assert!(
            matches!(err, StoreError::DocumentRungMismatch),
            "unexpected error: {err}"
        );
        assert_eq!(store.has_managed_key(xid).await.unwrap(), Some(true));
        assert_eq!(
            store.get_custody(xid).await.unwrap().unwrap().rung,
            CustodyRung::C2
        );
    }

    #[sqlx::test]
    async fn migrate_c2_to_c3_happy_path(pool: PgPool) {
        use bc_components::Signer;

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap();
        let c3 = c3_doc(&doc, &user, &ours);
        let bytes = encode_document(&c3).unwrap();
        let sig = user.sign(&bytes).unwrap();
        store
            .migrate_c2_to_c3(&c3, &sig, &user, climb_consent(xid), None)
            .await
            .unwrap();

        let got = store.get_custody(xid).await.unwrap().unwrap();
        assert_eq!(got.rung, CustodyRung::C3);
        assert_eq!(store.has_managed_key(xid).await.unwrap(), Some(false));
        assert!(!is_c2(&got.document));
        assert!(got.document.find_key_by_public_keys(&ours).is_none());
        assert!(crate::privilege::key_allows(
            got.document.find_key_by_public_keys(&user).unwrap(),
            Privilege::Sign
        ));
    }

    #[sqlx::test]
    async fn migrate_refuses_only_our_resolvers(pool: PgPool) {
        use bc_components::{Signer, URI};

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap();
        let mut c3 = c3_doc(&doc, &user, &ours);
        c3.remove_resolution_method(URI::new("https://resolver.example/.well-known/xid").unwrap());
        c3.add_resolution_method(URI::new("https://identikey.io/.well-known/xid").unwrap());
        let bytes = encode_document(&c3).unwrap();
        let sig = user.sign(&bytes).unwrap();
        let err = store
            .migrate_c2_to_c3(&c3, &sig, &user, climb_consent(xid), None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, StoreError::Ceremony(CeremonyError::Resolution(_))),
            "unexpected error: {err}"
        );
        assert_eq!(
            store.get_custody(xid).await.unwrap().unwrap().rung,
            CustodyRung::C2
        );
        assert_eq!(store.has_managed_key(xid).await.unwrap(), Some(true));
    }

    #[sqlx::test]
    async fn migrate_refuses_our_sign_key(pool: PgPool) {
        use bc_components::Signer;

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap();
        let c3 = c3_doc(&doc, &user, &ours);
        let bytes = encode_document(&c3).unwrap();
        let sig = ours.sign(&bytes).unwrap();
        let err = store
            .migrate_c2_to_c3(&c3, &sig, &ours, climb_consent(xid), None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                StoreError::Ceremony(CeremonyError::ElectDenied | CeremonyError::SignerIsHeldKey)
            ),
            "unexpected error: {err}"
        );
    }

    #[sqlx::test]
    async fn migrate_refuses_c1(pool: PgPool) {
        use bc_components::Signer;

        let store = KeysStore::from_pool(pool);
        let ours = PrivateKeyBase::new();
        let doc = crate::privilege::c1(&ours);
        let xid = store
            .create_managed(CustodyRung::C1, &doc, &blob())
            .await
            .unwrap();
        let bytes = encode_document(&doc).unwrap();
        let sig = ours.sign(&bytes).unwrap();
        let err = store
            .migrate_c2_to_c3(&doc, &sig, &ours, climb_consent(xid), None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, StoreError::Ceremony(CeremonyError::NotC2)),
            "unexpected error: {err}"
        );
    }

    async fn set_row_successor_digest(store: &KeysStore, xid: Xid, digest: &[u8]) {
        sqlx::query("UPDATE custody_records SET successor_digest = $2 WHERE xid = $1")
            .bind(xid.as_bytes().as_slice())
            .bind(digest)
            .execute(store.pool())
            .await
            .unwrap();
    }

    #[sqlx::test]
    async fn migrate_skips_successor_digest_when_unset(pool: PgPool) {
        use bc_components::Signer;

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap();
        let c3 = c3_doc(&doc, &user, &ours);
        let bytes = encode_document(&c3).unwrap();
        let sig = user.sign(&bytes).unwrap();
        store
            .migrate_c2_to_c3(&c3, &sig, &user, climb_consent(xid), Some(b"unused"))
            .await
            .unwrap();
        assert_eq!(
            store.get_custody(xid).await.unwrap().unwrap().rung,
            CustodyRung::C3
        );
    }

    #[sqlx::test]
    async fn migrate_accepts_matching_successor_digest(pool: PgPool) {
        use bc_components::Signer;

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap();
        let local = b"successor-public-or-cbor";
        set_row_successor_digest(&store, xid, &crate::successor_digest(local)).await;
        let c3 = c3_doc(&doc, &user, &ours);
        let bytes = encode_document(&c3).unwrap();
        let sig = user.sign(&bytes).unwrap();
        store
            .migrate_c2_to_c3(&c3, &sig, &user, climb_consent(xid), Some(local))
            .await
            .unwrap();
        assert_eq!(
            store.get_custody(xid).await.unwrap().unwrap().rung,
            CustodyRung::C3
        );
    }

    #[sqlx::test]
    async fn migrate_refuses_mismatched_successor_digest(pool: PgPool) {
        use bc_components::Signer;

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap();
        set_row_successor_digest(&store, xid, &crate::successor_digest(b"generated-here")).await;
        let c3 = c3_doc(&doc, &user, &ours);
        let bytes = encode_document(&c3).unwrap();
        let sig = user.sign(&bytes).unwrap();
        let err = store
            .migrate_c2_to_c3(
                &c3,
                &sig,
                &user,
                climb_consent(xid),
                Some(b"suggested-by-us"),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                StoreError::Ceremony(CeremonyError::SuccessorDigestMismatch)
            ),
            "unexpected error: {err}"
        );
        assert_eq!(
            store.get_custody(xid).await.unwrap().unwrap().rung,
            CustodyRung::C2
        );
        assert_eq!(store.has_managed_key(xid).await.unwrap(), Some(true));
    }

    #[sqlx::test]
    async fn passkey_and_consent_persist(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap();
        let cred = store
            .insert_passkey(xid, &[0xAAu8], &[0xBBu8], 0)
            .await
            .unwrap();
        let id = store
            .append_consent(ConsentAppend {
                xid,
                action: "sign",
                audience: Some("https://rp.example"),
                purpose: Some("login"),
                access_level: AccessLevel::A3,
                credential_id: Some(cred),
                proof_kind: ProofKind::WebauthnAssertion,
                proof_bytes: b"assertion",
                result: ConsentResult::Signed,
            })
            .await
            .unwrap();
        assert_ne!(id, Uuid::nil());
    }

    #[sqlx::test]
    async fn insert_list_revoke_devices(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap();

        assert!(store.list_devices(xid).await.unwrap().is_empty());

        let cred = store
            .insert_passkey(xid, &[0xAAu8], &[0xBBu8], 0)
            .await
            .unwrap();
        let listed = store.list_devices(xid).await.unwrap();
        let device = listed.first().expect("registered credential is listed");
        assert_eq!(listed.len(), 1);
        assert_eq!(device.id, cred);
        assert_eq!(device.kind, "passkey");
        assert_eq!(device.nickname, None);
        assert!(device.last_used_at.is_none());

        store.revoke_device(xid, cred).await.unwrap();
        store.revoke_device(xid, cred).await.unwrap();
        assert!(store.list_devices(xid).await.unwrap().is_empty());

        let missing = store.revoke_device(xid, Uuid::nil()).await.unwrap_err();
        assert!(
            matches!(missing, StoreError::NotFound),
            "unexpected error: {missing}"
        );
    }

    async fn climb_to_c3(
        store: &KeysStore,
        user: &PrivateKeyBase,
        ours: &PrivateKeyBase,
        c2: &XIDDocument,
        xid: Xid,
    ) -> XIDDocument {
        use bc_components::Signer;

        let c3 = c3_doc(c2, user, ours);
        let bytes = encode_document(&c3).unwrap();
        let sig = user.sign(&bytes).unwrap();
        store
            .migrate_c2_to_c3(&c3, &sig, user, climb_consent(xid), None)
            .await
            .unwrap();
        c3
    }

    #[sqlx::test]
    async fn c3_user_can_replace_a_resolver(pool: PgPool) {
        use bc_components::URI;

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let c2 = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &c2, &blob())
            .await
            .unwrap();
        let c3 = climb_to_c3(&store, &user, &ours, &c2, xid).await;
        let before = store.document_bytes(xid).await.unwrap().unwrap();

        let mut relocated = c3;
        relocated.remove_resolution_method(
            URI::new("https://resolver.example/.well-known/xid").unwrap(),
        );
        relocated
            .add_resolution_method(URI::new("https://backup.example/.well-known/xid").unwrap());
        store
            .apply_document_update(&user, &relocated)
            .await
            .unwrap();

        let after = store.document_bytes(xid).await.unwrap().unwrap();
        assert_ne!(before, after);
        let got = store.get_custody(xid).await.unwrap().unwrap();
        assert_eq!(got.rung, CustodyRung::C3);
        assert_eq!(store.has_managed_key(xid).await.unwrap(), Some(false));
    }

    #[sqlx::test]
    async fn c3_cannot_drop_the_last_not_us_host(pool: PgPool) {
        use bc_components::URI;

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let c2 = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &c2, &blob())
            .await
            .unwrap();
        let c3 = climb_to_c3(&store, &user, &ours, &c2, xid).await;
        let before = store.document_bytes(xid).await.unwrap().unwrap();

        let mut only_ours = c3;
        only_ours.remove_resolution_method(
            URI::new("https://resolver.example/.well-known/xid").unwrap(),
        );
        only_ours.add_resolution_method(URI::new("https://identikey.io/.well-known/xid").unwrap());
        let err = store
            .apply_document_update(&user, &only_ours)
            .await
            .unwrap_err();
        assert!(
            matches!(err, StoreError::Ceremony(CeremonyError::Resolution(_))),
            "unexpected error: {err}"
        );
        assert_eq!(store.document_bytes(xid).await.unwrap().unwrap(), before);
        assert_eq!(
            store.get_custody(xid).await.unwrap().unwrap().rung,
            CustodyRung::C3
        );
        assert_eq!(store.has_managed_key(xid).await.unwrap(), Some(false));
    }
}
