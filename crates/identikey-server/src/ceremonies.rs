//! WebAuthn registration and assertion (`add-passkey-ceremonies`).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use identikey_keys::{
    ADD_DEVICE_ACTION, AccessLevel, ConsentAppend, ConsentResult, KeysStore, ProofKind,
    SshGitInsert, StoreError, Xid, XidError,
};
use identikey_oidc::PendingAuthorization;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, DiscoverableKey, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, Webauthn,
};

use crate::webauthn::WebAuthnConfig;

const SESSION_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    #[error("unknown or expired ceremony")]
    UnknownSession,
    #[error("account not found")]
    UnknownAccount,
    #[error("credential not found")]
    UnknownCredential,
    #[error("ssh_git requires a fresh A3 assertion, not Elect")]
    ElectCannotAddDevice,
    #[error("webauthn: {0}")]
    Webauthn(String),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("xid: {0}")]
    Xid(#[from] XidError),
    #[error("lock poisoned")]
    Poison,
}

/// Stable WebAuthn user.id for an XID (same XID → same UUID, like the TS suite).
#[must_use]
pub fn xid_user_id(xid: Xid) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_URL, xid.as_bytes())
}

enum AssertKind {
    Known(PasskeyAuthentication),
    Discoverable(DiscoverableAuthentication),
}

enum InFlight {
    Register {
        xid: Xid,
        state: PasskeyRegistration,
        expires_at: Instant,
    },
    Assert {
        xid: Option<Xid>,
        kind: AssertKind,
        pending: Option<PendingAuthorization>,
        expires_at: Instant,
    },
}

pub struct CeremonyHub {
    webauthn: Webauthn,
    sessions: Mutex<HashMap<String, InFlight>>,
}

impl CeremonyHub {
    pub fn new(cfg: &WebAuthnConfig) -> Result<Self, crate::webauthn::Error> {
        Ok(Self {
            webauthn: cfg.verifier()?,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    #[allow(
        clippy::unwrap_used,
        reason = "http://localhost is a valid webauthn-rs RP origin"
    )]
    pub fn from_config(cfg: &WebAuthnConfig) -> Self {
        Self::new(cfg).unwrap_or_else(|_| {
            let fallback = WebAuthnConfig {
                rp_id: "localhost".into(),
                expected_origins: vec!["http://localhost".into()],
            };
            Self::new(&fallback).unwrap()
        })
    }

    fn session_id() -> String {
        Uuid::new_v4().as_simple().to_string()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, InFlight>>, CeremonyError> {
        self.sessions.lock().map_err(|_| CeremonyError::Poison)
    }

    pub async fn begin_register(
        &self,
        store: &KeysStore,
        xid: Xid,
    ) -> Result<(String, serde_json::Value), CeremonyError> {
        if store.get_account(xid).await?.is_none() {
            return Err(CeremonyError::UnknownAccount);
        }
        let exclude: Vec<_> = store
            .list_passkeys(xid)
            .await?
            .into_iter()
            .map(|row| row.credential_id.into())
            .collect();
        let exclude = if exclude.is_empty() {
            None
        } else {
            Some(exclude)
        };
        let name = xid.to_base58();
        let (ccr, state) = self
            .webauthn
            .start_passkey_registration(xid_user_id(xid), &name, &name, exclude)
            .map_err(|e| CeremonyError::Webauthn(e.to_string()))?;
        let session = Self::session_id();
        self.lock()?.insert(
            session.clone(),
            InFlight::Register {
                xid,
                state,
                expires_at: Instant::now() + SESSION_TTL,
            },
        );
        Ok((session, client_public_key(&ccr)?))
    }

    pub async fn finish_register(
        &self,
        store: &KeysStore,
        session: &str,
        xid: Xid,
        credential: RegisterPublicKeyCredential,
    ) -> Result<(), CeremonyError> {
        if store.get_account(xid).await?.is_none() {
            return Err(CeremonyError::UnknownAccount);
        }
        let inflight = self.lock()?.remove(session);
        let Some(InFlight::Register {
            xid: bound,
            state,
            expires_at,
        }) = inflight
        else {
            return Err(CeremonyError::UnknownSession);
        };
        if Instant::now() >= expires_at || bound != xid {
            return Err(CeremonyError::UnknownSession);
        }
        let passkey = self
            .webauthn
            .finish_passkey_registration(&credential, &state)
            .map_err(|e| CeremonyError::Webauthn(e.to_string()))?;
        let json =
            serde_json::to_vec(&passkey).map_err(|e| CeremonyError::Webauthn(e.to_string()))?;
        store
            .insert_passkey(xid, passkey.cred_id().as_slice(), &json, 0)
            .await?;
        Ok(())
    }

    pub async fn begin_assert(
        &self,
        store: &KeysStore,
        xid: Option<Xid>,
        pending: Option<PendingAuthorization>,
    ) -> Result<(String, serde_json::Value), CeremonyError> {
        let (rcr, kind) = if let Some(xid) = xid {
            let passkeys = load_passkeys(store, xid).await?;
            if passkeys.is_empty() {
                return Err(CeremonyError::UnknownCredential);
            }
            let (rcr, state) = self
                .webauthn
                .start_passkey_authentication(&passkeys)
                .map_err(|e| CeremonyError::Webauthn(e.to_string()))?;
            (rcr, AssertKind::Known(state))
        } else {
            let (rcr, state) = self
                .webauthn
                .start_discoverable_authentication()
                .map_err(|e| CeremonyError::Webauthn(e.to_string()))?;
            (rcr, AssertKind::Discoverable(state))
        };
        let session = Self::session_id();
        self.lock()?.insert(
            session.clone(),
            InFlight::Assert {
                xid,
                kind,
                pending,
                expires_at: Instant::now() + SESSION_TTL,
            },
        );
        Ok((session, client_public_key(&rcr)?))
    }

    pub async fn finish_assert(
        &self,
        store: &KeysStore,
        session: &str,
        credential: PublicKeyCredential,
    ) -> Result<(Xid, Option<PendingAuthorization>), CeremonyError> {
        let inflight = self.lock()?.remove(session);
        let Some(InFlight::Assert {
            xid: bound,
            kind,
            pending,
            expires_at,
        }) = inflight
        else {
            return Err(CeremonyError::UnknownSession);
        };
        if Instant::now() >= expires_at {
            return Err(CeremonyError::UnknownSession);
        }

        let cred_id = credential.get_credential_id().to_vec();
        let stored = store
            .get_passkey_by_credential_id(&cred_id)
            .await?
            .ok_or(CeremonyError::UnknownCredential)?;
        if let Some(bound) = bound {
            if bound != stored.xid {
                return Err(CeremonyError::UnknownCredential);
            }
        }
        let passkey: Passkey = serde_json::from_slice(&stored.passkey_json)
            .map_err(|e| CeremonyError::Webauthn(e.to_string()))?;

        let result = match kind {
            AssertKind::Known(state) => self
                .webauthn
                .finish_passkey_authentication(&credential, &state)
                .map_err(|e| CeremonyError::Webauthn(e.to_string()))?,
            AssertKind::Discoverable(state) => {
                let dk: DiscoverableKey = passkey.clone().into();
                self.webauthn
                    .finish_discoverable_authentication(&credential, state, &[dk])
                    .map_err(|e| CeremonyError::Webauthn(e.to_string()))?
            }
        };
        if result.counter() > 0 && i64::from(result.counter()) <= stored.sign_counter {
            return Err(CeremonyError::Webauthn(
                "sign counter did not increase".into(),
            ));
        }
        store
            .update_passkey_sign_counter(&cred_id, i64::from(result.counter()))
            .await?;
        Ok((stored.xid, pending))
    }

    /// Finish a WebAuthn assertion and insert `kind = ssh_git`.
    ///
    /// Elect-only (missing assertion, or an OIDC-login session) is refused.
    /// The private SSH key is never sent here — `device_public_key` only.
    pub async fn add_ssh_git_device(
        &self,
        store: &KeysStore,
        session: &str,
        credential: PublicKeyCredential,
        device_public_key: &[u8],
        nickname: Option<&str>,
    ) -> Result<(Xid, Uuid), CeremonyError> {
        let cred_id = credential.get_credential_id().to_vec();
        let proof_bytes =
            serde_json::to_vec(&credential).map_err(|e| CeremonyError::Webauthn(e.to_string()))?;
        let (xid, pending) = self.finish_assert(store, session, credential).await?;
        if pending.is_some() {
            return Err(CeremonyError::ElectCannotAddDevice);
        }
        let passkey_id = store.passkey_id(&cred_id).await?;
        let id = store
            .insert_ssh_git(SshGitInsert {
                xid,
                device_public_key,
                nickname,
                consent: ConsentAppend {
                    xid,
                    action: ADD_DEVICE_ACTION,
                    audience: Some("mjolnir-hosted-being"),
                    purpose: Some("ssh git-signing device"),
                    access_level: AccessLevel::A3,
                    credential_id: Some(passkey_id),
                    proof_kind: ProofKind::WebauthnAssertion,
                    proof_bytes: &proof_bytes,
                    result: ConsentResult::Signed,
                },
            })
            .await?;
        Ok((xid, id))
    }
}

fn client_public_key(challenge: &impl Serialize) -> Result<serde_json::Value, CeremonyError> {
    let value =
        serde_json::to_value(challenge).map_err(|e| CeremonyError::Webauthn(e.to_string()))?;
    let public_key = match value {
        serde_json::Value::Object(mut map) => map
            .remove("publicKey")
            .unwrap_or(serde_json::Value::Object(map)),
        other => other,
    };
    Ok(passkey_manager_compat(public_key))
}

/// Options 1Password (and iCloud / Google Password Manager) can intercept.
///
/// Do not set `authenticatorAttachment` or `hints: ["client-device"]` — those
/// hide synced passkey providers behind platform authenticators. Discoverable
/// credentials are required so usernameless login works from a vault.
fn passkey_manager_compat(mut public_key: serde_json::Value) -> serde_json::Value {
    let Some(obj) = public_key.as_object_mut() else {
        return public_key;
    };
    obj.remove("hints");
    let creation = obj.contains_key("user");
    if creation {
        let mut selection = obj
            .remove("authenticatorSelection")
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        selection.remove("authenticatorAttachment");
        selection.insert("residentKey".into(), serde_json::json!("required"));
        selection.insert("requireResidentKey".into(), serde_json::json!(true));
        selection.insert("userVerification".into(), serde_json::json!("required"));
        obj.insert(
            "authenticatorSelection".into(),
            serde_json::Value::Object(selection),
        );
    } else if let Some(selection) = obj.get_mut("authenticatorSelection")
        && let Some(sel) = selection.as_object_mut()
    {
        sel.remove("authenticatorAttachment");
        sel.insert("userVerification".into(), serde_json::json!("required"));
    }
    public_key
}

async fn load_passkeys(store: &KeysStore, xid: Xid) -> Result<Vec<Passkey>, CeremonyError> {
    let mut out = Vec::new();
    for row in store.list_passkeys(xid).await? {
        if let Ok(pk) = serde_json::from_slice::<Passkey>(&row.passkey_json) {
            out.push(pk);
        }
    }
    Ok(out)
}

#[derive(Debug, Deserialize)]
pub struct RegisterBegin {
    pub xid: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterFinish {
    pub session: String,
    pub xid: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Deserialize)]
pub struct AssertBegin {
    pub xid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssertFinish {
    pub session: String,
    pub credential: PublicKeyCredential,
}

#[derive(Debug, Deserialize)]
pub struct AddSshGit {
    pub session: Option<String>,
    pub credential: Option<PublicKeyCredential>,
    pub elect_signature: Option<String>,
    pub device_public_key: String,
    pub nickname: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeSshGit {
    pub xid: String,
    pub credential_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct CeremonyOptions {
    pub session: String,
    #[serde(rename = "publicKey")]
    pub public_key: serde_json::Value,
}

/// Registration options after hosted signup created the C2 account.
#[derive(Debug, Serialize)]
pub struct SignupOptions {
    pub xid: String,
    pub session: String,
    #[serde(rename = "publicKey")]
    pub public_key: serde_json::Value,
}
