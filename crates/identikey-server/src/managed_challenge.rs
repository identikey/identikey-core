//! HTTP ceremony for consent-gated C2 challenge responses.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use identikey_keys::{
    A3Authorization, ManagedChallengeError, ManagedChallengeProof, RetrievedManagedChallenge, Xid,
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
}

#[derive(Serialize)]
pub struct BeginResponse {
    request_id: Uuid,
    consent_challenge: String,
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
        )
        .await
    {
        Ok(result) => Json(BeginResponse {
            request_id: result.request_id,
            consent_challenge: URL_SAFE_NO_PAD.encode(result.consent_challenge),
            public_key,
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
            response: Some(URL_SAFE_NO_PAD.encode(response)),
        })
        .into_response(),
        Ok(RetrievedManagedChallenge::Failed) => Json(RetrieveResponse {
            state: "failed",
            response: None,
        })
        .into_response(),
        Ok(RetrievedManagedChallenge::Indeterminate) => Json(RetrieveResponse {
            state: "indeterminate",
            response: None,
        })
        .into_response(),
        Ok(RetrievedManagedChallenge::Pending) => Json(RetrieveResponse {
            state: "pending",
            response: None,
        })
        .into_response(),
        Err(error) => http_error(error),
    }
}
