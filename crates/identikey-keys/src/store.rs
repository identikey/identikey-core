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
use crate::keyspace::{CachedRosterEntry, CachedWrap, ReplicaSnapshot};
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
    #[error("ssh_git requires a fresh A3 add_device consent, not Elect")]
    SshGitRequiresA3AddDevice,
    #[error("ssh_git device_public_key must not be empty")]
    SshGitEmptyPublicKey,
    #[error("stored XID is not 32 bytes")]
    BadXid,
    #[error("encapsulation export must be logged before climb")]
    EncapsulationExportRequired,
    #[error("email address is invalid")]
    InvalidEmail,
    #[error("email link is invalid, expired, or already redeemed")]
    InvalidEmailLink,
    #[error("email address belongs to another account")]
    EmailInUse,
}

/// Consent-log action for adding a hosted-being git-signing device.
pub const ADD_DEVICE_ACTION: &str = "add_device";

/// Inputs for [`KeysStore::insert_ssh_git`]. Private key material is never stored.
pub struct SshGitInsert<'a> {
    pub xid: Xid,
    pub device_public_key: &'a [u8],
    pub nickname: Option<&'a str>,
    pub consent: ConsentAppend<'a>,
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

/// Passkey fields safe to show in account-management UI. No key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyPresentation {
    pub id: Uuid,
    pub credential_id: Vec<u8>,
    pub aaguid: Option<[u8; 16]>,
    pub backed_up: Option<bool>,
    pub nickname: Option<String>,
    pub last_used_at: Option<OffsetDateTime>,
}

/// Result of an atomic account-access revocation decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountAccessRevocation {
    Revoked,
    LastAccessConfirmationRequired,
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

fn presentation_from_row(row: sqlx::postgres::PgRow) -> Result<PasskeyPresentation, StoreError> {
    use sqlx::Row;

    let raw: Option<Vec<u8>> = row.try_get("aaguid")?;
    let aaguid = raw
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| StoreError::Document("stored AAGUID is not 16 bytes".into()))
        })
        .transpose()?;
    Ok(PasskeyPresentation {
        id: row.try_get("id")?,
        credential_id: row.try_get("webauthn_credential_id")?,
        aaguid,
        backed_up: row.try_get("backed_up")?,
        nickname: row.try_get("nickname")?,
        last_used_at: row.try_get("last_used_at")?,
    })
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

    /// Begin address verification for an authenticated account. The caller must
    /// deliver the returned bearer secret only to that account holder.
    pub async fn begin_email_magic_link(
        &self,
        xid: Xid,
        email: &str,
    ) -> Result<String, StoreError> {
        use rand::RngCore;
        use sha2::{Digest, Sha256};

        let email = email.trim();
        let Some((local, domain)) = email.split_once('@') else {
            return Err(StoreError::InvalidEmail);
        };
        if email.len() > 254
            || local.is_empty()
            || domain.is_empty()
            || domain.contains('@')
            || email.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(StoreError::InvalidEmail);
        }
        let mut random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let token = bs58::encode(random).into_string();
        let hash = Sha256::digest(token.as_bytes());
        let inserted = sqlx::query(
            "INSERT INTO email_magic_links (token_hash, xid, email)
             SELECT $1, xid, $3 FROM accounts WHERE xid = $2 AND disabled_at IS NULL",
        )
        .bind(hash.as_slice())
        .bind(xid.as_bytes().as_slice())
        .bind(email)
        .execute(&self.pool)
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(StoreError::NotFound);
        }
        Ok(token)
    }

    /// Consume the token and write only its bound account's recovery address.
    /// No custody or credentials query belongs in this transaction.
    pub async fn redeem_email_magic_link(&self, token: &str) -> Result<Xid, StoreError> {
        use sha2::{Digest, Sha256};

        let hash = Sha256::digest(token.as_bytes());
        let mut tx = self.pool.begin().await?;
        let row: Option<(Vec<u8>, String)> = sqlx::query_as(
            "DELETE FROM email_magic_links WHERE token_hash = $1 AND expires_at > now()
             RETURNING xid, email",
        )
        .bind(hash.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        let (bytes, email) = row.ok_or(StoreError::InvalidEmailLink)?;
        let xid = Xid::try_from_slice(&bytes).map_err(|_| StoreError::BadXid)?;
        let updated = sqlx::query(
            "UPDATE accounts SET email = $2, email_verified_at = now(), updated_at = now()
             WHERE xid = $1 AND disabled_at IS NULL",
        )
        .bind(&bytes)
        .bind(email)
        .execute(&mut *tx)
        .await;
        let updated = match updated {
            Err(sqlx::Error::Database(error))
                if error.constraint() == Some("accounts_email_lower_unique") =>
            {
                return Err(StoreError::EmailInUse);
            }
            result => result?,
        };
        if updated.rows_affected() != 1 {
            return Err(StoreError::NotFound);
        }
        tx.commit().await?;
        Ok(xid)
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

    /// Same as [`Self::create_managed`], plus the optional user X25519 seal.
    /// The seal is C2-only. `None` leaves older rows inert.
    pub async fn create_managed_with_encapsulation(
        &self,
        rung: CustodyRung,
        document: &XIDDocument,
        managed_key_blob: &[u8],
        encapsulation_key_blob: Option<&[u8]>,
    ) -> Result<Xid, StoreError> {
        if encapsulation_key_blob.is_some() && rung != CustodyRung::C2 {
            return Err(StoreError::DocumentRungMismatch);
        }
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
        sqlx::query("INSERT INTO accounts (xid) VALUES ($1)")
            .bind(xid_bytes)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO custody_records
                (xid, rung, xid_document, managed_key_blob, encapsulation_key_blob)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(xid_bytes)
        .bind(rung_s)
        .bind(&bytes)
        .bind(managed_key_blob)
        .bind(encapsulation_key_blob)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO custody_events (xid, from_rung, to_rung, ceremony)
             VALUES ($1, NULL, $2, 'signup')",
        )
        .bind(xid_bytes)
        .bind(rung_s)
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

        let has_seal = sqlx::query_scalar::<_, bool>(
            "SELECT encapsulation_key_blob IS NOT NULL FROM custody_records WHERE xid = $1",
        )
        .bind(xid_bytes)
        .fetch_one(&mut *tx)
        .await?;
        if has_seal {
            let exports: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM consent_log
                 WHERE xid = $1 AND action = 'encapsulation_export' AND result = 'signed'",
            )
            .bind(xid_bytes)
            .fetch_one(&mut *tx)
            .await?;
            if exports == 0 {
                return Err(StoreError::EncapsulationExportRequired);
            }
        }

        let consent_id = append_consent_tx(&mut tx, consent).await?;
        sqlx::query(
            "UPDATE custody_records
             SET xid_document = $2, managed_key_blob = NULL, encapsulation_key_blob = NULL,
                 rung = 'c3', updated_at = now()
             WHERE xid = $1",
        )
        .bind(xid_bytes)
        .bind(&new_bytes)
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
        self.insert_passkey_with_metadata(
            xid,
            webauthn_credential_id,
            cose_public_key,
            sign_counter,
            None,
            false,
            None,
        )
        .await
    }

    /// Insert a verified passkey plus presentation-only registration metadata.
    ///
    /// AAGUID is deliberately written but never read by ceremony lookup.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_passkey_with_metadata(
        &self,
        xid: Xid,
        webauthn_credential_id: &[u8],
        cose_public_key: &[u8],
        sign_counter: i64,
        aaguid: Option<[u8; 16]>,
        backed_up: bool,
        nickname: Option<&str>,
    ) -> Result<Uuid, StoreError> {
        let nickname = nickname.map(str::trim).filter(|value| !value.is_empty());
        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO credentials
                (xid, kind, webauthn_credential_id, cose_public_key, sign_counter,
                 aaguid, backed_up, nickname)
             VALUES ($1, 'passkey', $2, $3, $4, $5, $6, $7)
             RETURNING id",
        )
        .bind(xid.as_bytes().as_slice())
        .bind(webauthn_credential_id)
        .bind(cose_public_key)
        .bind(sign_counter)
        .bind(aaguid.as_ref().map(<[u8; 16]>::as_slice))
        .bind(backed_up)
        .bind(nickname)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
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

    /// Presentation for one live passkey. No key material. `None` when revoked or absent.
    pub async fn passkey_presentation_by_credential_id(
        &self,
        webauthn_credential_id: &[u8],
    ) -> Result<Option<PasskeyPresentation>, StoreError> {
        let row = sqlx::query(
            "SELECT id, webauthn_credential_id, aaguid, backed_up, nickname, last_used_at
             FROM credentials
             WHERE webauthn_credential_id = $1
               AND kind = 'passkey'
               AND revoked_at IS NULL",
        )
        .bind(webauthn_credential_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(presentation_from_row).transpose()
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

    /// Non-revoked passkeys for account presentation. Never returns key material.
    pub async fn list_passkey_presentations(
        &self,
        xid: Xid,
    ) -> Result<Vec<PasskeyPresentation>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, webauthn_credential_id, aaguid, backed_up, nickname, last_used_at
             FROM credentials
             WHERE xid = $1
               AND kind = 'passkey'
               AND revoked_at IS NULL
             ORDER BY created_at ASC",
        )
        .bind(xid.as_bytes().as_slice())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(presentation_from_row).collect()
    }

    pub async fn update_passkey_sign_counter(
        &self,
        webauthn_credential_id: &[u8],
        sign_counter: i64,
    ) -> Result<(), StoreError> {
        let result = sqlx::query!(
            "UPDATE credentials
             SET sign_counter = GREATEST(sign_counter, $2), last_used_at = now()
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

    /// Rename only a live passkey belonging to this account.
    pub async fn rename_passkey(
        &self,
        xid: Xid,
        credential_id: Uuid,
        nickname: Option<&str>,
    ) -> Result<(), StoreError> {
        let nickname = nickname.map(str::trim).filter(|value| !value.is_empty());
        let result = sqlx::query(
            "UPDATE credentials SET nickname = $3
             WHERE xid = $1 AND id = $2 AND kind = 'passkey' AND revoked_at IS NULL",
        )
        .bind(xid.as_bytes().as_slice())
        .bind(credential_id)
        .bind(nickname)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Revoke any credential, requiring explicit confirmation for the last login.
    /// The custody lock serializes decisions for an XID, including concurrent
    /// revokes of different rows. Keep custody → credential lock order shared
    /// with managed signing and the unconditional `revoke_device` primitive.
    pub async fn revoke_account_access(
        &self,
        xid: Xid,
        credential_id: Uuid,
        confirm_last_access: bool,
    ) -> Result<AccountAccessRevocation, StoreError> {
        let mut tx = self.pool.begin().await?;
        let custody = sqlx::query("SELECT xid FROM custody_records WHERE xid = $1 FOR UPDATE")
            .bind(xid.as_bytes().as_slice())
            .fetch_optional(&mut *tx)
            .await?;
        if custody.is_none() {
            return Err(StoreError::NotFound);
        }
        let (kind, revoked): (String, bool) = sqlx::query_as(
            "SELECT kind, revoked_at IS NOT NULL FROM credentials
             WHERE xid = $1 AND id = $2 FOR UPDATE",
        )
        .bind(xid.as_bytes().as_slice())
        .bind(credential_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::NotFound)?;
        if !revoked
            && !confirm_last_access
            && matches!(
                kind.as_str(),
                "passkey" | "oidc_apple" | "oidc_google" | "identikey_auth" | "password"
            )
        {
            let surviving: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM credentials
                 WHERE xid = $1 AND id <> $2 AND revoked_at IS NULL
                 AND kind IN ('passkey', 'oidc_apple', 'oidc_google', 'identikey_auth', 'password'))",
            )
            .bind(xid.as_bytes().as_slice())
            .bind(credential_id)
            .fetch_one(&mut *tx)
            .await?;
            if !surviving {
                tx.commit().await?;
                return Ok(AccountAccessRevocation::LastAccessConfirmationRequired);
            }
        }
        sqlx::query("UPDATE credentials SET revoked_at = COALESCE(revoked_at, now()) WHERE xid = $1 AND id = $2")
            .bind(xid.as_bytes().as_slice())
            .bind(credential_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(AccountAccessRevocation::Revoked)
    }

    /// Soft-revoke a credential. Idempotent if `revoked_at` is already set.
    ///
    /// Missing id or a different XID is [`StoreError::NotFound`].
    pub async fn revoke_device(&self, xid: Xid, credential_id: Uuid) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        // Same custody→credential lock order as an A3 managed-signing claim.
        // Whichever transaction wins defines whether the key may be used.
        let custody = sqlx::query("SELECT xid FROM custody_records WHERE xid = $1 FOR UPDATE")
            .bind(xid.as_bytes().as_slice())
            .fetch_optional(&mut *tx)
            .await?;
        if custody.is_none() {
            return Err(StoreError::NotFound);
        }
        let result = sqlx::query(
            "UPDATE credentials
             SET revoked_at = COALESCE(revoked_at, now())
             WHERE id = $1 AND xid = $2",
        )
        .bind(credential_id)
        .bind(xid.as_bytes().as_slice())
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Soft-revoke an `ssh_git` device only. Will not touch passkeys.
    ///
    /// Missing id, a different XID, or a non-`ssh_git` kind is [`StoreError::NotFound`].
    pub async fn revoke_ssh_git(&self, xid: Xid, credential_id: Uuid) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE credentials
             SET revoked_at = COALESCE(revoked_at, now())
             WHERE id = $1 AND xid = $2 AND kind = 'ssh_git'",
        )
        .bind(credential_id)
        .bind(xid.as_bytes().as_slice())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// UUID of a live passkey row by WebAuthn credential id.
    pub async fn passkey_id(&self, webauthn_credential_id: &[u8]) -> Result<Uuid, StoreError> {
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM credentials
             WHERE webauthn_credential_id = $1
               AND kind = 'passkey'
               AND revoked_at IS NULL",
        )
        .bind(webauthn_credential_id)
        .fetch_optional(&self.pool)
        .await?;
        id.ok_or(StoreError::NotFound)
    }

    /// Insert `kind = ssh_git` under a fresh A3 `add_device` consent.
    ///
    /// Elect-only (or any non-A3 / non-WebAuthn proof) is refused. The
    /// private SSH key never enters this store.
    pub async fn insert_ssh_git(&self, insert: SshGitInsert<'_>) -> Result<Uuid, StoreError> {
        if insert.device_public_key.is_empty() {
            return Err(StoreError::SshGitEmptyPublicKey);
        }
        if insert.consent.xid != insert.xid {
            return Err(StoreError::XidMismatch);
        }
        if insert.consent.action != ADD_DEVICE_ACTION
            || insert.consent.result != ConsentResult::Signed
        {
            return Err(StoreError::SshGitRequiresA3AddDevice);
        }
        match (insert.consent.access_level, insert.consent.proof_kind) {
            (AccessLevel::A3, ProofKind::WebauthnAssertion) => {}
            _ => return Err(StoreError::SshGitRequiresA3AddDevice),
        }
        if self.get_account(insert.xid).await?.is_none() {
            return Err(StoreError::NotFound);
        }

        let mut tx = self.pool.begin().await?;
        let xid_bytes = insert.xid.as_bytes().as_slice();
        let rec_id: Uuid = sqlx::query_scalar(
            "INSERT INTO credentials (xid, kind, device_public_key, nickname)
             VALUES ($1, 'ssh_git', $2, $3)
             RETURNING id",
        )
        .bind(xid_bytes)
        .bind(insert.device_public_key)
        .bind(insert.nickname)
        .fetch_one(&mut *tx)
        .await?;
        append_consent_tx(&mut tx, insert.consent).await?;
        tx.commit().await?;
        Ok(rec_id)
    }

    pub async fn append_consent(&self, entry: ConsentAppend<'_>) -> Result<Uuid, StoreError> {
        let mut tx = self.pool.begin().await?;
        let id = append_consent_tx(&mut tx, entry).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Cache of an applied replica. Deleting the row does not kill the keyspace.
    pub async fn put_keyspace_cache(&self, snap: &ReplicaSnapshot) -> Result<(), StoreError> {
        let epoch = i64::try_from(snap.epoch).map_err(|e| StoreError::Document(e.to_string()))?;
        let roster = cache_roster_json(snap);
        let wraps = cache_wraps_json(snap);
        sqlx::query!(
            r#"INSERT INTO keyspace_cache (keyspace_id, epoch, profile, faded, roster, wraps)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (keyspace_id) DO UPDATE SET
                 epoch = EXCLUDED.epoch,
                 profile = EXCLUDED.profile,
                 faded = EXCLUDED.faded,
                 roster = EXCLUDED.roster,
                 wraps = EXCLUDED.wraps,
                 updated_at = now()"#,
            snap.keyspace.as_slice(),
            epoch,
            &snap.profile,
            snap.faded,
            roster,
            wraps
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_keyspace_cache(
        &self,
        id: identikey_log::Hash32,
    ) -> Result<Option<ReplicaSnapshot>, StoreError> {
        let row = sqlx::query!(
            r#"SELECT keyspace_id, epoch, profile, faded, roster, wraps
               FROM keyspace_cache WHERE keyspace_id = $1"#,
            id.as_slice()
        )
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let keyspace: identikey_log::Hash32 = row
            .keyspace_id
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Document("keyspace_id is not 32 bytes".into()))?;
        let epoch = u64::try_from(row.epoch).map_err(|e| StoreError::Document(e.to_string()))?;
        Ok(Some(ReplicaSnapshot {
            keyspace,
            epoch,
            profile: row.profile,
            faded: row.faded,
            roster: parse_roster_json(&row.roster)?,
            wraps: parse_wraps_json(&row.wraps)?,
        }))
    }

    pub async fn delete_keyspace_cache(&self, id: identikey_log::Hash32) -> Result<(), StoreError> {
        sqlx::query!(
            "DELETE FROM keyspace_cache WHERE keyspace_id = $1",
            id.as_slice()
        )
        .execute(&self.pool)
        .await?;
        Ok(())
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
    if crate::encapsulation::wrap_recipient_changed(&previous, new_document) {
        sqlx::query(
            "UPDATE custody_records
             SET xid_document = $2, encapsulation_key_blob = NULL, updated_at = now()
             WHERE xid = $1",
        )
        .bind(xid_bytes)
        .bind(new_bytes)
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query!(
            "UPDATE custody_records SET xid_document = $2, updated_at = now() WHERE xid = $1",
            xid_bytes,
            new_bytes
        )
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

pub(crate) async fn append_consent_tx(
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

fn cache_roster_json(snap: &ReplicaSnapshot) -> serde_json::Value {
    serde_json::Value::Array(
        snap.roster
            .iter()
            .map(|e| {
                serde_json::json!({
                    "admin": e.admin,
                    "actor": e.actor.map(|a| a.to_vec()),
                })
            })
            .collect(),
    )
}

fn cache_wraps_json(snap: &ReplicaSnapshot) -> serde_json::Value {
    serde_json::Value::Array(
        snap.wraps
            .iter()
            .map(|w| {
                serde_json::json!({
                    "alg": w.alg,
                    "recipient": w.recipient,
                    "epoch": w.epoch,
                })
            })
            .collect(),
    )
}

fn json_to_bytes(v: &serde_json::Value) -> Result<Vec<u8>, StoreError> {
    let Some(items) = v.as_array() else {
        return Err(StoreError::Document("expected JSON byte array".into()));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let n = item
            .as_u64()
            .ok_or_else(|| StoreError::Document("byte array entry is not a number".into()))?;
        out.push(
            u8::try_from(n)
                .map_err(|_| StoreError::Document("byte array entry exceeds u8".into()))?,
        );
    }
    Ok(out)
}

fn parse_roster_json(v: &serde_json::Value) -> Result<Vec<CachedRosterEntry>, StoreError> {
    let Some(arr) = v.as_array() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for item in arr {
        let admin = item
            .get("admin")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let actor = match item.get("actor") {
            None | Some(serde_json::Value::Null) => None,
            Some(bytes) => Some(
                identikey_log::Hash32::try_from(json_to_bytes(bytes)?.as_slice())
                    .map_err(|_| StoreError::Document("roster actor is not 32 bytes".into()))?,
            ),
        };
        out.push(CachedRosterEntry { admin, actor });
    }
    Ok(out)
}

fn parse_wraps_json(v: &serde_json::Value) -> Result<Vec<CachedWrap>, StoreError> {
    let Some(arr) = v.as_array() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for item in arr {
        let alg = item
            .get("alg")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned();
        let recipient = match item.get("recipient") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(bytes) => json_to_bytes(bytes)?,
        };
        let epoch = item
            .get("epoch")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        out.push(CachedWrap {
            alg,
            recipient,
            epoch,
        });
    }
    Ok(out)
}

fn encode_document(document: &XIDDocument) -> Result<Vec<u8>, StoreError> {
    let cbor = CBOR::from(document.clone());
    Ok(cbor.to_cbor_data())
}

pub(crate) fn decode_document(bytes: &[u8]) -> Result<XIDDocument, StoreError> {
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

    async fn email_magic_link_account(store: &KeysStore) -> Xid {
        let doc = c2_native(&PrivateKeyBase::new(), &PrivateKeyBase::new()).unwrap();
        store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap()
    }

    #[sqlx::test]
    async fn email_magic_link_single_use_and_no_key_or_credential_changes(pool: PgPool) {
        use sha2::{Digest, Sha256};
        let store = KeysStore::from_pool(pool);
        let xid = email_magic_link_account(&store).await;
        let other = email_magic_link_account(&store).await;
        let token = store
            .begin_email_magic_link(xid, "Person@example.com")
            .await
            .unwrap();
        let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM email_magic_links")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(stored, Sha256::digest(token.as_bytes()).as_slice());
        assert_ne!(stored, token.as_bytes());
        let (first, second) = tokio::join!(
            store.redeem_email_magic_link(&token),
            store.redeem_email_magic_link(&token)
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert_eq!(first.or(second).unwrap(), xid);
        assert!(matches!(
            store.redeem_email_magic_link(&token).await,
            Err(StoreError::InvalidEmailLink)
        ));
        let row: (String, bool) = sqlx::query_as(
            "SELECT email, email_verified_at IS NOT NULL FROM accounts WHERE xid = $1",
        )
        .bind(xid.as_bytes().as_slice())
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(row, ("Person@example.com".into(), true));
        let other_email: Option<String> =
            sqlx::query_scalar("SELECT email FROM accounts WHERE xid = $1")
                .bind(other.as_bytes().as_slice())
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(other_email.is_none());
        let held: Vec<u8> =
            sqlx::query_scalar("SELECT managed_key_blob FROM custody_records WHERE xid = $1")
                .bind(xid.as_bytes().as_slice())
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(held, blob());
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM credentials")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[sqlx::test]
    async fn email_magic_link_refuses_case_insensitive_conflict_atomically(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let first = email_magic_link_account(&store).await;
        let second = email_magic_link_account(&store).await;
        let token = store
            .begin_email_magic_link(first, "Same@example.com")
            .await
            .unwrap();
        store.redeem_email_magic_link(&token).await.unwrap();
        let original = store
            .begin_email_magic_link(second, "original@example.com")
            .await
            .unwrap();
        store.redeem_email_magic_link(&original).await.unwrap();
        let before: Vec<(Vec<u8>, Option<String>, OffsetDateTime)> =
            sqlx::query_as("SELECT xid, email, updated_at FROM accounts ORDER BY xid")
                .fetch_all(store.pool())
                .await
                .unwrap();
        let conflict = store
            .begin_email_magic_link(second, "SAME@EXAMPLE.COM")
            .await
            .unwrap();
        assert!(matches!(
            store.redeem_email_magic_link(&conflict).await,
            Err(StoreError::EmailInUse)
        ));
        let after: Vec<(Vec<u8>, Option<String>, OffsetDateTime)> =
            sqlx::query_as("SELECT xid, email, updated_at FROM accounts ORDER BY xid")
                .fetch_all(store.pool())
                .await
                .unwrap();
        assert_eq!(before, after);
    }

    #[sqlx::test]
    async fn email_magic_link_invalid_expired_and_unknown_account(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let xid = email_magic_link_account(&store).await;
        for email in [
            "",
            "missing-at",
            "@example.com",
            "a@",
            "a@@b",
            "a b@example.com",
        ] {
            assert!(matches!(
                store.begin_email_magic_link(xid, email).await,
                Err(StoreError::InvalidEmail)
            ));
        }
        assert!(matches!(
            store
                .begin_email_magic_link(Xid::from_bytes([0xff; 32]), "a@example.com")
                .await,
            Err(StoreError::NotFound)
        ));
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM email_magic_links")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count, 0);
        let token = store
            .begin_email_magic_link(xid, "a@example.com")
            .await
            .unwrap();
        sqlx::query("UPDATE email_magic_links SET expires_at = now() - interval '1 second'")
            .execute(store.pool())
            .await
            .unwrap();
        for token in [&token, "unknown"] {
            assert!(matches!(
                store.redeem_email_magic_link(token).await,
                Err(StoreError::InvalidEmailLink)
            ));
        }
        let email: Option<String> = sqlx::query_scalar("SELECT email FROM accounts WHERE xid = $1")
            .bind(xid.as_bytes().as_slice())
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert!(email.is_none());
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

    async fn passkey_account_mgmt_credential(store: &KeysStore, xid: Xid, kind: &str) -> Uuid {
        match kind {
            "passkey" => store.insert_passkey(xid, Uuid::new_v4().as_bytes(), b"public", 0).await.unwrap(),
            "oidc_apple" | "oidc_google" => sqlx::query_scalar(
                "INSERT INTO credentials (xid, kind, issuer, subject_at_issuer) VALUES ($1, $2, $3, $4) RETURNING id",
            ).bind(xid.as_bytes().as_slice()).bind(kind).bind(kind).bind(Uuid::new_v4().to_string())
                .fetch_one(store.pool()).await.unwrap(),
            _ => sqlx::query_scalar(
                "INSERT INTO credentials (xid, kind, device_public_key) VALUES ($1, $2, $3) RETURNING id",
            ).bind(xid.as_bytes().as_slice()).bind(kind).bind(b"public".as_slice())
                .fetch_one(store.pool()).await.unwrap(),
        }
    }

    #[sqlx::test]
    async fn passkey_account_mgmt_all_login_kinds_and_unconditional_primitive(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        // Password is not yet a schema kind. Simulate its future presence only
        // in this sqlx test's isolated database, without changing migrations.
        sqlx::query("ALTER TABLE credentials DROP CONSTRAINT credentials_kind_known, DROP CONSTRAINT credentials_kind_shape")
            .execute(store.pool()).await.unwrap();
        for kind in [
            "passkey",
            "oidc_apple",
            "oidc_google",
            "identikey_auth",
            "password",
        ] {
            let xid = email_magic_link_account(&store).await;
            let passkey = passkey_account_mgmt_credential(&store, xid, "passkey").await;
            let other = passkey_account_mgmt_credential(&store, xid, kind).await;
            let ssh = passkey_account_mgmt_credential(&store, xid, "ssh_git").await;
            assert_eq!(
                store
                    .revoke_account_access(xid, passkey, false)
                    .await
                    .unwrap(),
                AccountAccessRevocation::Revoked
            );
            assert_eq!(
                store
                    .revoke_account_access(xid, other, false)
                    .await
                    .unwrap(),
                AccountAccessRevocation::LastAccessConfirmationRequired
            );
            assert_eq!(store.list_devices(xid).await.unwrap().len(), 2);
            assert_eq!(
                store.revoke_account_access(xid, other, true).await.unwrap(),
                AccountAccessRevocation::Revoked
            );
            assert_eq!(
                store
                    .revoke_account_access(xid, other, false)
                    .await
                    .unwrap(),
                AccountAccessRevocation::Revoked
            );
            assert_eq!(store.list_devices(xid).await.unwrap()[0].id, ssh);
            assert_eq!(
                store.revoke_account_access(xid, ssh, false).await.unwrap(),
                AccountAccessRevocation::Revoked
            );
        }
        let xid = email_magic_link_account(&store).await;
        let sole = passkey_account_mgmt_credential(&store, xid, "passkey").await;
        assert_eq!(
            store.revoke_account_access(xid, sole, false).await.unwrap(),
            AccountAccessRevocation::LastAccessConfirmationRequired
        );
        store.revoke_device(xid, sole).await.unwrap();
        assert!(store.list_devices(xid).await.unwrap().is_empty());
    }

    #[sqlx::test]
    async fn passkey_account_mgmt_concurrent_last_two_and_foreign_ids(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        for kind in ["passkey", "oidc_apple", "oidc_google", "identikey_auth"] {
            let xid = email_magic_link_account(&store).await;
            let first = passkey_account_mgmt_credential(&store, xid, "passkey").await;
            let second = passkey_account_mgmt_credential(&store, xid, kind).await;
            let (a, b) = tokio::join!(
                store.revoke_account_access(xid, first, false),
                store.revoke_account_access(xid, second, false),
            );
            let outcomes = [a.unwrap(), b.unwrap()];
            assert!(outcomes.contains(&AccountAccessRevocation::Revoked));
            assert!(outcomes.contains(&AccountAccessRevocation::LastAccessConfirmationRequired));
            assert_eq!(store.list_devices(xid).await.unwrap().len(), 1);
            let other = email_magic_link_account(&store).await;
            assert!(matches!(
                store.revoke_account_access(other, second, true).await,
                Err(StoreError::NotFound)
            ));
            assert!(matches!(
                store.revoke_account_access(xid, Uuid::nil(), true).await,
                Err(StoreError::NotFound)
            ));
        }
    }

    #[sqlx::test]
    async fn passkey_account_mgmt_rename_scope(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let xid = email_magic_link_account(&store).await;
        let other = email_magic_link_account(&store).await;
        let id = passkey_account_mgmt_credential(&store, xid, "passkey").await;
        store
            .rename_passkey(xid, id, Some(" Home <key> "))
            .await
            .unwrap();
        assert_eq!(
            store.list_devices(xid).await.unwrap()[0]
                .nickname
                .as_deref(),
            Some("Home <key>")
        );
        store.rename_passkey(xid, id, Some("Work")).await.unwrap();
        assert_eq!(
            store.list_devices(xid).await.unwrap()[0]
                .nickname
                .as_deref(),
            Some("Work")
        );
        assert!(matches!(
            store.rename_passkey(other, id, Some("stolen")).await,
            Err(StoreError::NotFound)
        ));
        let ssh = passkey_account_mgmt_credential(&store, xid, "ssh_git").await;
        assert!(matches!(
            store.rename_passkey(xid, ssh, Some("wrong kind")).await,
            Err(StoreError::NotFound)
        ));
        store.revoke_device(xid, id).await.unwrap();
        assert!(matches!(
            store.rename_passkey(xid, id, Some("revoked")).await,
            Err(StoreError::NotFound)
        ));
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

    #[sqlx::test]
    async fn passkey_legibility_persists_metadata_without_filtering_ceremony_loads(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap();
        let first_aaguid = [0x11; 16];
        let second_aaguid = [0x22; 16];

        store
            .insert_passkey_with_metadata(
                xid,
                b"first-credential",
                b"first-key-json",
                0,
                Some(first_aaguid),
                true,
                Some("  Work key  "),
            )
            .await
            .unwrap();
        store
            .insert_passkey_with_metadata(
                xid,
                b"second-credential",
                b"second-key-json",
                0,
                Some(second_aaguid),
                false,
                Some("   "),
            )
            .await
            .unwrap();

        let presented = store.list_passkey_presentations(xid).await.unwrap();
        let presented: Vec<_> = presented
            .iter()
            .map(|row| (row.aaguid, row.backed_up, row.nickname.as_deref()))
            .collect();
        assert_eq!(
            presented,
            [
                (Some(first_aaguid), Some(true), Some("Work key")),
                (Some(second_aaguid), Some(false), None),
            ]
        );

        // Ceremony loading remains keyed only by XID / credential id. Different
        // presentation AAGUIDs neither filter nor rank the accepted passkeys.
        let ceremony_rows = store.list_passkeys(xid).await.unwrap();
        let ceremony_ids: Vec<&[u8]> = ceremony_rows
            .iter()
            .map(|row| row.credential_id.as_slice())
            .collect();
        assert_eq!(
            ceremony_ids,
            [
                b"first-credential".as_slice(),
                b"second-credential".as_slice()
            ]
        );
        assert!(
            store
                .get_passkey_by_credential_id(b"first-credential")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .get_passkey_by_credential_id(b"second-credential")
                .await
                .unwrap()
                .is_some()
        );
    }

    fn add_device_consent(xid: Xid, passkey: Uuid) -> ConsentAppend<'static> {
        ConsentAppend {
            xid,
            action: ADD_DEVICE_ACTION,
            audience: Some("mjolnir-hosted-being"),
            purpose: Some("ssh git-signing device"),
            access_level: AccessLevel::A3,
            credential_id: Some(passkey),
            proof_kind: ProofKind::WebauthnAssertion,
            proof_bytes: b"assertion",
            result: ConsentResult::Signed,
        }
    }

    #[sqlx::test]
    async fn insert_ssh_git_requires_a3_add_device_not_elect(pool: PgPool) {
        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &blob())
            .await
            .unwrap();
        let passkey = store
            .insert_passkey(xid, &[0xAAu8], &[0xBBu8], 0)
            .await
            .unwrap();
        let pub_bytes = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake";

        let elect_only = ConsentAppend {
            xid,
            action: ADD_DEVICE_ACTION,
            audience: None,
            purpose: Some("elect"),
            access_level: AccessLevel::A4,
            credential_id: Some(passkey),
            proof_kind: ProofKind::IdentikeyAuthResponse,
            proof_bytes: b"elect-sig",
            result: ConsentResult::Signed,
        };
        let err = store
            .insert_ssh_git(SshGitInsert {
                xid,
                device_public_key: pub_bytes,
                nickname: Some("vm-1"),
                consent: elect_only,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, StoreError::SshGitRequiresA3AddDevice),
            "unexpected error: {err}"
        );

        let wrong_action = ConsentAppend {
            action: "sign",
            ..add_device_consent(xid, passkey)
        };
        let err = store
            .insert_ssh_git(SshGitInsert {
                xid,
                device_public_key: pub_bytes,
                nickname: None,
                consent: wrong_action,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, StoreError::SshGitRequiresA3AddDevice),
            "unexpected error: {err}"
        );

        assert_eq!(
            store
                .list_devices(xid)
                .await
                .unwrap()
                .iter()
                .filter(|d| d.kind == "ssh_git")
                .count(),
            0
        );

        let id = store
            .insert_ssh_git(SshGitInsert {
                xid,
                device_public_key: pub_bytes,
                nickname: Some("vm-1"),
                consent: add_device_consent(xid, passkey),
            })
            .await
            .unwrap();
        let listed = store.list_devices(xid).await.unwrap();
        let git = listed
            .iter()
            .find(|d| d.kind == "ssh_git")
            .expect("ssh_git row");
        assert_eq!(git.id, id);
        assert_eq!(git.nickname.as_deref(), Some("vm-1"));

        let action: String = sqlx::query_scalar(
            "SELECT action FROM consent_log WHERE xid = $1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(xid.as_bytes().as_slice())
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(action, ADD_DEVICE_ACTION);

        store.revoke_ssh_git(xid, id).await.unwrap();
        store.revoke_ssh_git(xid, id).await.unwrap();
        assert!(
            store
                .list_devices(xid)
                .await
                .unwrap()
                .iter()
                .all(|d| d.kind != "ssh_git")
        );
        // Passkeys must not be revocable via the ssh_git path.
        let err = store.revoke_ssh_git(xid, passkey).await.unwrap_err();
        assert!(
            matches!(err, StoreError::NotFound),
            "unexpected error: {err}"
        );
        assert_eq!(
            store
                .list_devices(xid)
                .await
                .unwrap()
                .iter()
                .filter(|d| d.kind == "passkey")
                .count(),
            1
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

    #[sqlx::test]
    async fn keyspace_cache_delete_does_not_kill_replica(pool: PgPool) {
        use identikey_log::{Author, Hlc, Op};

        let store = KeysStore::from_pool(pool);
        let author = Author::from_seed(&[7u8; 32]);
        let actor = author.actor();
        let body =
            crate::keyspace::encode_genesis(actor, "ed25519", &[1u8; 32], &[2u8; 32]).unwrap();
        let genesis =
            Op::new("keyspace.join", actor, Hlc::new(1_700_000_000_000, 1)).with_body(body);
        let mut replica = crate::keyspace::KeyspaceReplica::new();
        let id = replica.apply(&genesis).unwrap();
        let snap = replica.get(&id).expect("applied genesis");
        store.put_keyspace_cache(&snap).await.unwrap();
        let cached = store
            .get_keyspace_cache(id)
            .await
            .unwrap()
            .expect("cache row");
        assert_eq!(cached, snap);

        store.delete_keyspace_cache(id).await.unwrap();
        assert!(store.get_keyspace_cache(id).await.unwrap().is_none());
        assert_eq!(replica.get(&id).expect("replica is home"), snap);

        let mut leave_body = Map::new();
        leave_body.insert("keyspace", CBOR::to_byte_string(id));
        leave_body.insert("actor", CBOR::to_byte_string(actor));
        let leave = Op::new("keyspace.leave", actor, Hlc::new(1_700_000_000_001, 1))
            .with_body(CBOR::from(leave_body).to_cbor_data())
            .with_parents([id]);
        replica.apply(&leave).unwrap();
        assert!(replica.get(&id).expect("still applied").faded);
        assert!(store.get_keyspace_cache(id).await.unwrap().is_none());
    }
}
