//! Durable store. Elect is checked against the row, not the caller.

use bc_components::{PublicKeysProvider, XIDProvider};
use bc_xid::XIDDocument;
use dcbor::prelude::*;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::consent::{
    hash_consent_entry, hash_proof, ConsentHashInput, ConsentResult, ProofKind,
};
use crate::privilege::{authorize_elect, is_c2, PrivilegeError};
use crate::rung::{AccessLevel, CustodyRung};
use crate::xid::Xid;
use crate::MIGRATOR;

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
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(url)
            .await?;
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
        let bytes = encode_document(document)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO accounts (xid) VALUES ($1)")
            .bind(xid.as_bytes().as_slice())
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO custody_records (xid, rung, xid_document, managed_key_blob)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(xid.as_bytes().as_slice())
        .bind(rung.as_str())
        .bind(&bytes)
        .bind(managed_key_blob)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO custody_events (xid, from_rung, to_rung, ceremony)
             VALUES ($1, NULL, $2, 'signup')",
        )
        .bind(xid.as_bytes().as_slice())
        .bind(rung.as_str())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(xid)
    }

    pub async fn get_account(&self, xid: Xid) -> Result<Option<StoredAccount>, StoreError> {
        let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT xid FROM accounts WHERE xid = $1")
            .bind(xid.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await?;
        match row {
            None => Ok(None),
            Some((bytes,)) => Ok(Some(StoredAccount {
                xid: Xid::try_from_slice(&bytes).map_err(|e| StoreError::Document(e.to_string()))?,
            })),
        }
    }

    pub async fn get_custody(&self, xid: Xid) -> Result<Option<StoredCustody>, StoreError> {
        let row: Option<(Vec<u8>, String, Vec<u8>)> = sqlx::query_as(
            "SELECT xid, rung, xid_document FROM custody_records WHERE xid = $1",
        )
        .bind(xid.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some((xid_bytes, rung, doc_bytes)) => Ok(Some(StoredCustody {
                xid: Xid::try_from_slice(&xid_bytes)
                    .map_err(|e| StoreError::Document(e.to_string()))?,
                rung: rung
                    .parse()
                    .map_err(|e: crate::ParseRungError| StoreError::Document(e.to_string()))?,
                document: decode_document(&doc_bytes)?,
            })),
        }
    }

    /// Raw document bytes. Used to prove a denied update did not write.
    pub async fn document_bytes(&self, xid: Xid) -> Result<Option<Vec<u8>>, StoreError> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT xid_document FROM custody_records WHERE xid = $1")
                .bind(xid.as_bytes().as_slice())
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(b,)| b))
    }

    /// Persist a new XID document only if `signer` holds Elect on the stored one.
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

    pub async fn insert_passkey(
        &self,
        xid: Xid,
        webauthn_credential_id: &[u8],
        cose_public_key: &[u8],
        sign_counter: i64,
    ) -> Result<Uuid, StoreError> {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO credentials
                (xid, kind, webauthn_credential_id, cose_public_key, sign_counter)
             VALUES ($1, 'passkey', $2, $3, $4)
             RETURNING id",
        )
        .bind(xid.as_bytes().as_slice())
        .bind(webauthn_credential_id)
        .bind(cose_public_key)
        .bind(sign_counter)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn append_consent(&self, entry: ConsentAppend<'_>) -> Result<Uuid, StoreError> {
        let prev: Option<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT seq, entry_hash FROM consent_log WHERE xid = $1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(entry.xid.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await?;

        let (seq, prev_hash) = match prev {
            None => (1_u64, None),
            Some((s, hash)) => {
                let seq = u64::try_from(s).map_err(|e| StoreError::Document(e.to_string()))? + 1;
                let prev = <[u8; 32]>::try_from(hash.as_slice())
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

        let id: Uuid = sqlx::query_scalar(
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
        )
        .bind(entry.xid.as_bytes().as_slice())
        .bind(seq_i64)
        .bind(prev_hash.as_ref().map(|h| h.as_slice()))
        .bind(entry_hash.as_slice())
        .bind(entry.action)
        .bind(entry.audience)
        .bind(entry.purpose)
        .bind(entry.access_level.as_str())
        .bind(entry.credential_id)
        .bind(entry.proof_kind.as_str())
        .bind(entry.proof_bytes)
        .bind(proof_hash.as_slice())
        .bind(entry.result.as_str())
        .fetch_one(&self.pool)
        .await?;
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
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT xid_document FROM custody_records WHERE xid = $1 FOR UPDATE",
    )
    .bind(xid.as_bytes().as_slice())
    .fetch_optional(&mut **tx)
    .await?;
    let Some((stored_bytes,)) = row else {
        return Err(StoreError::NotFound);
    };
    let previous = decode_document(&stored_bytes)?;
    if Xid::from(new_document.xid()) != xid || Xid::from(previous.xid()) != xid {
        return Err(StoreError::XidMismatch);
    }
    authorize_elect(&previous, signer)?;
    sqlx::query(
        "UPDATE custody_records SET xid_document = $2, updated_at = now() WHERE xid = $1",
    )
    .bind(xid.as_bytes().as_slice())
    .bind(new_bytes)
    .execute(&mut **tx)
    .await?;
    Ok(())
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

        let err = store.apply_document_update(&ours, &forged).await.unwrap_err();
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
}
