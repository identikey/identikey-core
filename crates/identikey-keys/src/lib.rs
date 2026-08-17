//! Managed custody — the C2 rung, and the store everything else sits on.
//!
//! # What belongs here
//!
//! Accounts, credentials, XID documents, custody records, the consent log, and
//! the C2 → C3 migration ceremony.
//!
//! # The line this crate exists to hold
//!
//! C1 means we can sign without you. C2 means we **cannot** sign without an
//! authenticated instruction that we log and you can audit. That line is the
//! product's integrity, and it is enforced here or nowhere.
//!
//! Two mechanisms make it real rather than a promise:
//!
//! - **Privilege separation** (ADR-008, `identikey-core-av9`). At C2 the user's
//!   key holds `Elect` and `Transfer`; IdentiKey's key holds `Sign` and `Auth`.
//!   A breach of IdentiKey therefore yields the ability to sign *now* but not to
//!   take over the identity — and exit is unilateral, because the user can rotate
//!   our key out without our cooperation. This is the exit test enforced
//!   cryptographically instead of by policy.
//! - **The migration ceremony ships with C2, not after it** (invariant I3,
//!   `identikey-core-zan.2`). A managed-custody product without an exit is the
//!   thing this project exists to oppose, and it is far harder to retrofit than
//!   to design in.
//!
//! # Invariant I2, which is a release blocker
//!
//! Account recovery (email, SMS, social re-verification) and key recovery
//! (guardian quorum, Shamir, MPC) are different systems and must never merge.
//! If an email link can reach a key, the email provider is the real root of
//! trust and the whole ladder silently collapses to C1.
//!
//! # Schema (`identikey-core-zan.1`)
//!
//! The migration in `migrations/` is the schema. The facts it encodes:
//!
//! | Table | Holds |
//! |---|---|
//! | `accounts` | One row per identity, keyed by 32-byte XID |
//! | `credentials` | Access methods (A2/A3/A4). Not the identity. |
//! | `custody_records` | Current rung + current XID document + managed key blob |
//! | `custody_events` | Append-only rung changes (I3/I4) |
//! | `consent_log` | Append-only, hash-chained C2 instructions |
//! | `challenges` | Short-lived WebAuthn / identikey-auth nonces |
//!
//! **Consent record, settled at the schema layer** (open question 5).
//! Signed/proved by the *access* credential — a WebAuthn assertion at A3 or an
//! `identikey-auth` Response at A4 — never by the managed Sign key. Stored in
//! `consent_log`, hash-chained per account, UPDATE/DELETE refused. Shown from
//! the row: when, what action, for whom, which credential, outcome.
//!
//! We take the hash-chain *pattern* from `identikey-storage-auth` and do not
//! depend on that crate (AGPL + recrypt; LEARNINGS 2026-07-28).
//!
//! Privilege assignments live in the XID document, not in extra columns. Device
//! records (`zan.8`), OIDC tokens (`ccf.*`), and guardian tables (`vt4`) are
//! later migrations.
//!
//! # Privilege split (`identikey-core-av9`, ADR-010)
//!
//! C2 *is* the split: the user's key holds `Elect` + `Transfer`, ours holds
//! `Sign` + `Auth`. No user-held `Elect` is C1, and we will say so. `bc-xid`
//! does not enforce this — [`authorize_elect`] is the check, and after
//! promotion we Transfer the inception key out so `XIDVerifySignature::Inception`
//! cannot undo the split.
//!
//! # Store (`add-keys-store`)
//!
//! [`KeysStore`] is the durable face. A C2 document write goes through
//! [`KeysStore::apply_document_update`] and must stay C2. The climb is
//! [`KeysStore::migrate_c2_to_c3`] (ADR-011). The server requires
//! `DATABASE_URL` and runs [`MIGRATOR`] at boot.

pub mod ceremony;
pub mod consent;
pub mod privilege;
pub mod resolve;
pub mod rung;
pub mod store;
pub mod xid;

pub use ceremony::{CeremonyError, held_publics, validate_c2_to_c3};
pub use consent::{
    CONSENT_HASH_V1, ConsentHashInput, ConsentResult, ProofKind, hash_consent_entry, hash_proof,
};
pub use privilege::{
    IDENTIKEY_C2_PRIVILEGES, PrivilegeError, USER_C2_PRIVILEGES, authorize_elect, c1, c2_native,
    is_c2, key_allows, promote_c1_to_c2,
};
pub use resolve::{FetchedDocument, ResolutionTier, ResolveError, WinningDoc, resolve_documents};
pub use rung::{AccessLevel, CustodyRung, ParseRungError};
pub use store::{
    ConsentAppend, KeysStore, PublishedDocument, StoreError, StoredAccount, StoredCustody,
};
pub use xid::{Xid, XidError};

/// sqlx migrator for the schema in `migrations/`.
///
/// The server runs this at boot. Tests use `#[sqlx::test]`, which applies the
/// same files against a fresh database.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use sha2::{Digest, Sha256};
    use sqlx::PgPool;

    use super::*;

    fn xid(seed: u8) -> Xid {
        Xid::from_bytes([seed; 32])
    }

    async fn insert_account(pool: &PgPool, id: Xid) {
        sqlx::query("INSERT INTO accounts (xid) VALUES ($1)")
            .bind(id.as_bytes().as_slice())
            .execute(pool)
            .await
            .unwrap();
    }

    #[sqlx::test]
    async fn migration_creates_the_tables(pool: PgPool) {
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT tablename FROM pg_tables
             WHERE schemaname = 'public'
             ORDER BY tablename",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        for needed in [
            "accounts",
            "challenges",
            "consent_log",
            "credentials",
            "custody_events",
            "custody_records",
        ] {
            assert!(
                tables.iter().any(|t| t == needed),
                "missing table {needed}, have {tables:?}"
            );
        }
    }

    #[sqlx::test]
    async fn xid_must_be_32_bytes(pool: PgPool) {
        let err = sqlx::query("INSERT INTO accounts (xid) VALUES ($1)")
            .bind([0u8; 16].as_slice())
            .execute(&pool)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("accounts_xid_len"),
            "unexpected error: {err}"
        );
    }

    #[sqlx::test]
    async fn c3_cannot_keep_a_managed_key(pool: PgPool) {
        insert_account(&pool, xid(1)).await;
        let err = sqlx::query(
            "INSERT INTO custody_records (xid, rung, xid_document, managed_key_blob)
             VALUES ($1, 'c3', $2, $3)",
        )
        .bind(xid(1).as_bytes().as_slice())
        .bind([1u8, 2, 3].as_slice())
        .bind([9u8; 8].as_slice())
        .execute(&pool)
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("custody_managed_key_matches_rung"),
            "unexpected error: {err}"
        );
    }

    #[sqlx::test]
    async fn c2_requires_a_managed_key(pool: PgPool) {
        insert_account(&pool, xid(2)).await;
        let err = sqlx::query(
            "INSERT INTO custody_records (xid, rung, xid_document, managed_key_blob)
             VALUES ($1, 'c2', $2, NULL)",
        )
        .bind(xid(2).as_bytes().as_slice())
        .bind([1u8].as_slice())
        .execute(&pool)
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("custody_managed_key_matches_rung"),
            "unexpected error: {err}"
        );
    }

    #[sqlx::test]
    async fn c2_with_managed_key_is_accepted(pool: PgPool) {
        insert_account(&pool, xid(3)).await;
        sqlx::query(
            "INSERT INTO custody_records (xid, rung, xid_document, managed_key_blob)
             VALUES ($1, 'c2', $2, $3)",
        )
        .bind(xid(3).as_bytes().as_slice())
        .bind([1u8].as_slice())
        .bind([9u8; 8].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    }

    #[sqlx::test]
    async fn c3_without_managed_key_is_accepted(pool: PgPool) {
        insert_account(&pool, xid(4)).await;
        sqlx::query(
            "INSERT INTO custody_records (xid, rung, xid_document, managed_key_blob)
             VALUES ($1, 'c3', $2, NULL)",
        )
        .bind(xid(4).as_bytes().as_slice())
        .bind([1u8].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    }

    #[sqlx::test]
    async fn passkey_shape_is_enforced(pool: PgPool) {
        insert_account(&pool, xid(5)).await;
        let err = sqlx::query(
            "INSERT INTO credentials (xid, kind, webauthn_credential_id)
             VALUES ($1, 'passkey', $2)",
        )
        .bind(xid(5).as_bytes().as_slice())
        .bind([0xAAu8].as_slice())
        .execute(&pool)
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("credentials_kind_shape"),
            "unexpected error: {err}"
        );
    }

    #[sqlx::test]
    async fn passkey_insert_and_aaguid_length(pool: PgPool) {
        insert_account(&pool, xid(6)).await;
        sqlx::query(
            "INSERT INTO credentials
                (xid, kind, webauthn_credential_id, cose_public_key, sign_counter, aaguid, backed_up)
             VALUES ($1, 'passkey', $2, $3, 0, $4, false)",
        )
        .bind(xid(6).as_bytes().as_slice())
        .bind([0xAAu8, 0xBB].as_slice())
        .bind([0xCCu8].as_slice())
        .bind([0u8; 16].as_slice())
        .execute(&pool)
        .await
        .unwrap();

        let err = sqlx::query(
            "INSERT INTO credentials
                (xid, kind, webauthn_credential_id, cose_public_key, sign_counter, aaguid)
             VALUES ($1, 'passkey', $2, $3, 0, $4)",
        )
        .bind(xid(6).as_bytes().as_slice())
        .bind([0xDDu8].as_slice())
        .bind([0xCCu8].as_slice())
        .bind([0u8; 8].as_slice())
        .execute(&pool)
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("credentials_aaguid_len"),
            "unexpected error: {err}"
        );
    }

    #[sqlx::test]
    async fn aaguid_is_not_a_policy_constraint(pool: PgPool) {
        // Any 16-byte AAGUID, including all-zeroes (the usual `none` attestation
        // value), is acceptable. The column must not grow a CHECK that treats
        // some authenticators as more trustworthy than others.
        insert_account(&pool, xid(7)).await;
        sqlx::query(
            "INSERT INTO credentials
                (xid, kind, webauthn_credential_id, cose_public_key, sign_counter, aaguid)
             VALUES ($1, 'passkey', $2, $3, 0, $4)",
        )
        .bind(xid(7).as_bytes().as_slice())
        .bind([0x01u8].as_slice())
        .bind([0x02u8].as_slice())
        .bind([0u8; 16].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    }

    async fn insert_passkey(pool: &PgPool, id: Xid, cred: &[u8]) -> uuid::Uuid {
        sqlx::query_scalar(
            "INSERT INTO credentials
                (xid, kind, webauthn_credential_id, cose_public_key, sign_counter)
             VALUES ($1, 'passkey', $2, $3, 0)
             RETURNING id",
        )
        .bind(id.as_bytes().as_slice())
        .bind(cred)
        .bind([0xCCu8].as_slice())
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[sqlx::test]
    async fn consent_log_is_hash_chained_and_append_only(pool: PgPool) {
        let id = xid(8);
        insert_account(&pool, id).await;
        let cred = insert_passkey(&pool, id, &[0xAAu8]).await;

        let proof = b"assertion-bytes";
        let proof_hash = hash_proof(proof);
        let entry = ConsentHashInput {
            xid: id,
            seq: 1,
            prev_hash: None,
            action: "sign",
            audience: Some("https://rp.example"),
            purpose: Some("login"),
            access_level: AccessLevel::A3,
            credential_id: Some(cred),
            proof_kind: ProofKind::WebauthnAssertion,
            proof_hash,
            result: ConsentResult::Signed,
        };
        let entry_hash = hash_consent_entry(&entry);

        sqlx::query(
            "INSERT INTO consent_log (
                xid, seq, prev_hash, entry_hash,
                action, audience, purpose,
                access_level, credential_id, proof_kind, proof_bytes, proof_hash, result
             ) VALUES (
                $1, 1, NULL, $2,
                'sign', 'https://rp.example', 'login',
                'a3', $3, 'webauthn_assertion', $4, $5, 'signed'
             )",
        )
        .bind(id.as_bytes().as_slice())
        .bind(entry_hash.as_slice())
        .bind(cred)
        .bind(proof.as_slice())
        .bind(proof_hash.as_slice())
        .execute(&pool)
        .await
        .unwrap();

        let second = ConsentHashInput {
            seq: 2,
            prev_hash: Some(entry_hash),
            ..entry
        };
        let second_hash = hash_consent_entry(&second);
        sqlx::query(
            "INSERT INTO consent_log (
                xid, seq, prev_hash, entry_hash,
                action, audience, purpose,
                access_level, credential_id, proof_kind, proof_bytes, proof_hash, result
             ) VALUES (
                $1, 2, $2, $3,
                'sign', 'https://rp.example', 'login',
                'a3', $4, 'webauthn_assertion', $5, $6, 'signed'
             )",
        )
        .bind(id.as_bytes().as_slice())
        .bind(entry_hash.as_slice())
        .bind(second_hash.as_slice())
        .bind(cred)
        .bind(proof.as_slice())
        .bind(proof_hash.as_slice())
        .execute(&pool)
        .await
        .unwrap();

        let skipped = sqlx::query(
            "INSERT INTO consent_log (
                xid, seq, prev_hash, entry_hash,
                action, access_level, proof_kind, proof_bytes, proof_hash, result
             ) VALUES (
                $1, 4, $2, $3,
                'sign', 'a3', 'webauthn_assertion', $4, $5, 'signed'
             )",
        )
        .bind(id.as_bytes().as_slice())
        .bind(second_hash.as_slice())
        .bind([0u8; 32].as_slice())
        .bind(proof.as_slice())
        .bind(proof_hash.as_slice())
        .execute(&pool)
        .await
        .unwrap_err();
        assert!(
            skipped.to_string().contains("contiguous"),
            "unexpected error: {skipped}"
        );

        let update = sqlx::query("UPDATE consent_log SET action = 'export' WHERE seq = 1")
            .execute(&pool)
            .await
            .unwrap_err();
        assert!(
            update.to_string().contains("append-only"),
            "unexpected error: {update}"
        );

        let delete = sqlx::query("DELETE FROM consent_log WHERE seq = 1")
            .execute(&pool)
            .await
            .unwrap_err();
        assert!(
            delete.to_string().contains("append-only"),
            "unexpected error: {delete}"
        );
    }

    #[sqlx::test]
    async fn first_consent_rejects_a_prev_hash(pool: PgPool) {
        let id = xid(9);
        insert_account(&pool, id).await;
        let err = sqlx::query(
            "INSERT INTO consent_log (
                xid, seq, prev_hash, entry_hash,
                action, access_level, proof_kind, proof_bytes, proof_hash, result
             ) VALUES (
                $1, 1, $2, $3,
                'sign', 'a3', 'webauthn_assertion', $4, $5, 'signed'
             )",
        )
        .bind(id.as_bytes().as_slice())
        .bind([0u8; 32].as_slice())
        .bind([1u8; 32].as_slice())
        .bind([2u8].as_slice())
        .bind(Sha256::digest(b"x").as_slice())
        .execute(&pool)
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("NULL prev_hash"),
            "unexpected error: {err}"
        );
    }

    #[sqlx::test]
    async fn discoverable_challenge_allows_null_xid(pool: PgPool) {
        sqlx::query(
            "INSERT INTO challenges (challenge, kind, expires_at)
             VALUES ($1, 'webauthn_authenticate', now() + interval '5 minutes')",
        )
        .bind([0x42u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    }

    #[sqlx::test]
    async fn custody_events_are_append_only(pool: PgPool) {
        insert_account(&pool, xid(10)).await;
        sqlx::query(
            "INSERT INTO custody_events (xid, from_rung, to_rung, ceremony)
             VALUES ($1, NULL, 'c2', 'signup')",
        )
        .bind(xid(10).as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();

        let err = sqlx::query("DELETE FROM custody_events")
            .execute(&pool)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("append-only"),
            "unexpected error: {err}"
        );
    }

    #[sqlx::test]
    async fn email_is_unique_case_insensitive(pool: PgPool) {
        insert_account(&pool, xid(11)).await;
        sqlx::query("UPDATE accounts SET email = 'a@example.com' WHERE xid = $1")
            .bind(xid(11).as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        insert_account(&pool, xid(12)).await;
        let err = sqlx::query("UPDATE accounts SET email = 'A@example.com' WHERE xid = $1")
            .bind(xid(12).as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("accounts_email_lower_unique"),
            "unexpected error: {err}"
        );
    }
}
