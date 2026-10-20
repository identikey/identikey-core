//! HTTP ceremony for consent-gated C2 challenge responses.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use identikey_keys::{
    A3Authorization, ManagedChallengeError, ManagedChallengeProof, ManagedSessionBind,
    RetrievedManagedChallenge, Xid,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::PublicKeyCredential;

use crate::AppState;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginRequest {
    xid: String,
    challenge: String,
    verifier_commitment: String,
    proof: String,
    session_public_key: SessionPublicKey,
    operation: Vec<String>,
    resource: Vec<String>,
    channel: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPublicKey {
    alg: String,
    key: String,
}

#[derive(Serialize)]
pub struct BindFields {
    session_public_key: SessionPublicKey,
    operation: Vec<String>,
    resource: Vec<String>,
    channel: String,
}

impl From<ManagedSessionBind> for BindFields {
    fn from(bind: ManagedSessionBind) -> Self {
        Self {
            session_public_key: SessionPublicKey {
                alg: "ed25519".into(),
                key: URL_SAFE_NO_PAD.encode(bind.session_public_key.bytes),
            },
            operation: bind.operation,
            resource: bind.resource,
            channel: URL_SAFE_NO_PAD.encode(bind.channel),
        }
    }
}

#[derive(Serialize)]
pub struct BeginResponse {
    request_id: Uuid,
    consent_challenge: String,
    #[serde(flatten)]
    fields: BindFields,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishA3Request {
    request_id: Uuid,
    credential: PublicKeyCredential,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishA4Request {
    request_id: Uuid,
    response: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrieveRequest {
    request_id: Uuid,
    verifier: String,
}

#[derive(Serialize)]
pub struct RetrieveResponse {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bind: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    fields: Option<BindFields>,
}

fn now() -> Result<u64, ManagedChallengeError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ManagedChallengeError::ChallengeAdmission("system time precedes epoch"))
}

fn decode(value: &str) -> Result<Vec<u8>, ManagedChallengeError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ManagedChallengeError::InvalidProof)
}

fn http_error(error: ManagedChallengeError) -> Response {
    let status = match error {
        ManagedChallengeError::NotFound => StatusCode::NOT_FOUND,
        ManagedChallengeError::Replay
        | ManagedChallengeError::InvalidState
        | ManagedChallengeError::AlreadyClaimed => StatusCode::CONFLICT,
        ManagedChallengeError::Sql(_) | ManagedChallengeError::Document(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        Json(serde_json::json!({ "error": error.to_string() })),
    )
        .into_response()
}

pub async fn begin(State(state): State<AppState>, Json(body): Json<BeginRequest>) -> Response {
    let xid: Xid = match body.xid.parse() {
        Ok(xid) => xid,
        Err(_) => return http_error(ManagedChallengeError::InvalidProof),
    };
    let challenge = match decode(&body.challenge) {
        Ok(value) => value,
        Err(error) => return http_error(error),
    };
    let commitment: [u8; 32] = match decode(&body.verifier_commitment).and_then(|value| {
        value
            .try_into()
            .map_err(|_| ManagedChallengeError::InvalidProof)
    }) {
        Ok(value) => value,
        Err(error) => return http_error(error),
    };
    let bind = match (decode(&body.session_public_key.key), decode(&body.channel)) {
        (Ok(key), Ok(channel)) if body.session_public_key.alg == "ed25519" => ManagedSessionBind {
            session_public_key: identikey_auth::ClassicalPublicKey {
                alg: identikey_auth::ClassicalAlg::Ed25519,
                bytes: key,
            },
            operation: body.operation,
            resource: body.resource,
            channel,
        },
        _ => return http_error(ManagedChallengeError::InvalidProof),
    };
    if let Err(error) = bind.validate() {
        return http_error(error);
    }
    let (proof, public_key, webauthn_state) = match body.proof.as_str() {
        "a3" => match state
            .ceremonies
            .begin_managed_assert(&state.store, xid)
            .await
        {
            Ok((public_key, verifier_state)) => (
                ManagedChallengeProof::A3,
                Some(public_key),
                Some(verifier_state),
            ),
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": error.to_string() })),
                )
                    .into_response();
            }
        },
        "a4" => (ManagedChallengeProof::A4, None, None),
        _ => return http_error(ManagedChallengeError::InvalidProof),
    };
    match state
        .store
        .begin_managed_challenge(
            xid,
            &challenge,
            commitment,
            proof,
            webauthn_state.as_deref(),
            match now() {
                Ok(now) => now,
                Err(error) => return http_error(error),
            },
            &bind,
        )
        .await
    {
        Ok(result) => Json(BeginResponse {
            request_id: result.request_id,
            consent_challenge: URL_SAFE_NO_PAD.encode(result.consent_challenge),
            public_key,
            fields: result.bind.into(),
        })
        .into_response(),
        Err(error) => http_error(error),
    }
}

pub async fn finish_a3(
    State(state): State<AppState>,
    Json(body): Json<FinishA3Request>,
) -> Response {
    let (xid, verifier_state) = match state.store.managed_a3_state(body.request_id).await {
        Ok(value) => value,
        Err(error) => return http_error(error),
    };
    let (credential_id, proof) = match state
        .ceremonies
        .finish_managed_assert(&state.store, xid, &verifier_state, body.credential)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": error.to_string() })),
            )
                .into_response();
        }
    };
    if let Err(error) = state
        .store
        .authorize_managed_a3(
            body.request_id,
            A3Authorization {
                credential_id,
                proof_bytes: &proof,
            },
        )
        .await
    {
        return http_error(error);
    }
    sign_once(&state, body.request_id).await
}

pub async fn finish_a4(
    State(state): State<AppState>,
    Json(body): Json<FinishA4Request>,
) -> Response {
    let response = match decode(&body.response) {
        Ok(value) => value,
        Err(error) => return http_error(error),
    };
    if let Err(error) = state
        .store
        .authorize_managed_a4(body.request_id, &response)
        .await
    {
        return http_error(error);
    }
    sign_once(&state, body.request_id).await
}

async fn sign_once(state: &AppState, request_id: Uuid) -> Response {
    match state
        .store
        .finish_authorized_managed_challenge(
            &state.managed_keys,
            request_id,
            match now() {
                Ok(now) => now,
                Err(error) => return http_error(error),
            },
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => http_error(error),
    }
}

pub async fn retrieve(
    State(state): State<AppState>,
    Json(body): Json<RetrieveRequest>,
) -> Response {
    // The verifier itself is the only retrieval proof. Unknown fields (for
    // example a holder public) are rejected by the request deserializer.
    match state
        .store
        .retrieve_managed_challenge(body.request_id, &body.verifier)
        .await
    {
        Ok(RetrievedManagedChallenge::Completed(response)) => Json(RetrieveResponse {
            state: "completed",
            response: Some(URL_SAFE_NO_PAD.encode(response.response)),
            bind: Some(URL_SAFE_NO_PAD.encode(response.bind)),
            fields: Some(response.fields.into()),
        })
        .into_response(),
        Ok(RetrievedManagedChallenge::Failed) => Json(RetrieveResponse {
            state: "failed",
            response: None,
            bind: None,
            fields: None,
        })
        .into_response(),
        Ok(RetrievedManagedChallenge::Indeterminate) => Json(RetrieveResponse {
            state: "indeterminate",
            response: None,
            bind: None,
            fields: None,
        })
        .into_response(),
        Ok(RetrievedManagedChallenge::Pending) => Json(RetrieveResponse {
            state: "pending",
            response: None,
            bind: None,
            fields: None,
        })
        .into_response(),
        Err(error) => http_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_challenge_begin_requires_all_bind_fields() {
        let valid = serde_json::json!({
            "xid": "account", "challenge": "challenge", "verifier_commitment": "commitment", "proof": "a4",
            "session_public_key": {"alg": "ed25519", "key": URL_SAFE_NO_PAD.encode([0x11;32])},
            "operation": ["vms", "stop"], "resource": ["vm", "A"], "channel": URL_SAFE_NO_PAD.encode([0x22;32])
        });
        assert!(serde_json::from_value::<BeginRequest>(valid.clone()).is_ok());
        for field in ["session_public_key", "operation", "resource", "channel"] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<BeginRequest>(missing).is_err());
        }
        let bare = serde_json::json!({"xid":"account", "challenge":"challenge", "verifier_commitment":"commitment", "proof":"a4"});
        assert!(serde_json::from_value::<BeginRequest>(bare).is_err());
        let mut string_tuple = valid;
        string_tuple["operation"] = serde_json::json!("vms:stop");
        assert!(serde_json::from_value::<BeginRequest>(string_tuple).is_err());
    }

    #[test]
    fn managed_challenge_retrieve_wire_is_raw_signature_and_stored_fields() {
        let fields = ManagedSessionBind {
            session_public_key: identikey_auth::ClassicalPublicKey {
                alg: identikey_auth::ClassicalAlg::Ed25519,
                bytes: vec![0x11; 32],
            },
            operation: vec!["vms".into(), "stop".into()],
            resource: vec!["vm".into(), "A".into()],
            channel: vec![0x22; 32],
        };
        let wire = serde_json::to_value(RetrieveResponse {
            state: "completed",
            response: Some("response".into()),
            bind: Some(URL_SAFE_NO_PAD.encode([0x33; 64])),
            fields: Some(fields.into()),
        })
        .unwrap();
        assert_eq!(
            wire,
            serde_json::json!({
                "state":"completed", "response":"response", "bind":URL_SAFE_NO_PAD.encode([0x33;64]),
                "session_public_key":{"alg":"ed25519", "key":URL_SAFE_NO_PAD.encode([0x11;32])},
                "operation":["vms","stop"], "resource":["vm","A"], "channel":URL_SAFE_NO_PAD.encode([0x22;32])
            })
        );
        let pending = serde_json::to_value(RetrieveResponse {
            state: "pending",
            response: None,
            bind: None,
            fields: None,
        })
        .unwrap();
        assert_eq!(pending, serde_json::json!({"state":"pending"}));
        assert!(
            serde_json::from_value::<FinishA4Request>(serde_json::json!({
                "request_id":Uuid::nil(), "response":"proof", "operation":["vms","start"]
            }))
            .is_err()
        );
    }
}
