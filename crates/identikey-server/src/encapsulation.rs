//! Export of the held user X25519. Unwrap stays in the library.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bc_components::Signature;
use dcbor::prelude::*;
use identikey_keys::{BeginEncapsulationRequest, EncapsulationError, HeldProof, Xid};
use serde::Deserialize;
use uuid::Uuid;
use webauthn_rs::prelude::PublicKeyCredential;
use zeroize::Zeroize;

use crate::ceremonies::{self, CeremonyError};
use crate::{AppState, oauth_error, signed_in_xid};

#[derive(Deserialize)]
pub struct BeginBody {
    purpose: String,
    #[serde(default)]
    wrap: Option<String>,
    #[serde(default)]
    friend: Option<String>,
}

#[derive(Deserialize)]
pub struct ExportBody {
    attempt: Uuid,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    credential: Option<PublicKeyCredential>,
}

#[derive(Deserialize)]
pub struct RewrapBody {
    attempt: Uuid,
    wrap: String,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    credential: Option<PublicKeyCredential>,
}

pub async fn begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BeginBody>,
) -> Response {
    let Some(xid) = signed_in_xid(&state, &headers) else {
        return no_store(oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "sign in to name the account",
        ));
    };
    if body.purpose != "export" && body.purpose != "unwrap" && body.purpose != "rewrap" {
        return no_store(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "purpose must be export, unwrap, or rewrap",
        ));
    }
    let wrap = match decode_optional(&body.wrap) {
        Ok(bytes) => bytes,
        Err(()) => {
            return no_store(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "wrap is not base64url",
            ));
        }
    };
    if (body.purpose == "unwrap" || body.purpose == "rewrap") && wrap.is_none() {
        return no_store(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "unwrap and rewrap require the wrap bytes",
        ));
    }
    if body.purpose == "export" && wrap.is_some() {
        return no_store(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "export does not take a wrap",
        ));
    }
    let friend = match body.friend.as_deref() {
        Some(text) => match text.parse::<Xid>() {
            Ok(xid) => Some(xid),
            Err(_) => {
                return no_store(oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "friend is not a base58btc xid",
                ));
            }
        },
        None => None,
    };
    if body.purpose == "rewrap" && friend.is_none() {
        return no_store(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "rewrap requires the friend's xid",
        ));
    }
    if body.purpose != "rewrap" && friend.is_some() {
        return no_store(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "only rewrap names a friend",
        ));
    }
    let (challenge, webauthn_state, public_key) = match state
        .ceremonies
        .begin_managed_assert(&state.store, xid)
        .await
    {
        Ok((public_key, state_bytes)) => {
            let challenge = match ceremonies::webauthn_challenge(&public_key) {
                Ok(challenge) => challenge,
                Err(err) => return no_store(ceremony_error(err)),
            };
            (challenge, Some(state_bytes), Some(public_key))
        }
        Err(CeremonyError::UnknownCredential) => (fresh_challenge(), None, None),
        Err(err) => return no_store(ceremony_error(err)),
    };
    let now = unix_now();
    match state
        .store
        .begin_encapsulation(BeginEncapsulationRequest {
            xid,
            purpose: &body.purpose,
            challenge: &challenge,
            wrap: wrap.as_deref(),
            webauthn_state: webauthn_state.as_deref(),
            now,
            friend,
        })
        .await
    {
        Ok(begun) => no_store(
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({
                    "attempt": begun.id,
                    "challenge": URL_SAFE_NO_PAD.encode(&begun.challenge),
                    "publicKey": public_key,
                    "friend_has_seal": begun.friend_has_seal,
                })
                .to_string(),
            )
                .into_response(),
        ),
        Err(err) => no_store(encapsulation_error(err)),
    }
}

pub async fn export(State(state): State<AppState>, Json(body): Json<ExportBody>) -> Response {
    let now = unix_now();
    let result = if let Some(credential) = body.credential.as_ref() {
        state
            .store
            .export_encapsulation(
                &state.managed_keys,
                body.attempt,
                HeldProof::A3 {
                    webauthn: state.ceremonies.verifier(),
                    credential,
                },
                now,
            )
            .await
    } else if let Some(signature) = body.signature.as_deref() {
        let signature = match decode_signature(signature) {
            Ok(signature) => signature,
            Err(reason) => {
                return no_store(oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    reason,
                ));
            }
        };
        state
            .store
            .export_encapsulation(
                &state.managed_keys,
                body.attempt,
                HeldProof::A4(&signature),
                now,
            )
            .await
    } else {
        return no_store(oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "export requires a passkey assertion or an elect signature",
        ));
    };
    match result {
        Ok(mut scalar) => {
            let body = URL_SAFE_NO_PAD.encode(scalar);
            scalar.zeroize();
            no_store(
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                    body,
                )
                    .into_response(),
            )
        }
        Err(err) => no_store(encapsulation_error(err)),
    }
}

pub async fn rewrap(State(state): State<AppState>, Json(body): Json<RewrapBody>) -> Response {
    let wrap = match URL_SAFE_NO_PAD.decode(body.wrap.as_bytes()) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        Ok(_) => {
            return no_store(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "rewrap requires the wrap bytes",
            ));
        }
        Err(_) => {
            return no_store(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "wrap is not base64url",
            ));
        }
    };
    let now = unix_now();
    let result = if let Some(credential) = body.credential.as_ref() {
        state
            .store
            .rewrap_encapsulation(
                &state.managed_keys,
                body.attempt,
                HeldProof::A3 {
                    webauthn: state.ceremonies.verifier(),
                    credential,
                },
                &wrap,
                now,
            )
            .await
    } else if let Some(signature) = body.signature.as_deref() {
        let signature = match decode_signature(signature) {
            Ok(signature) => signature,
            Err(reason) => {
                return no_store(oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    reason,
                ));
            }
        };
        state
            .store
            .rewrap_encapsulation(
                &state.managed_keys,
                body.attempt,
                HeldProof::A4(&signature),
                &wrap,
                now,
            )
            .await
    } else {
        return no_store(oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "rewrap requires a passkey assertion or an elect signature",
        ));
    };
    match result {
        Ok(wrapped) => no_store(
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                URL_SAFE_NO_PAD.encode(wrapped),
            )
                .into_response(),
        ),
        Err(err) => no_store(encapsulation_error(err)),
    }
}

pub(crate) fn is_encapsulation_path(path: &str) -> bool {
    path == "/account/encapsulation/begin"
        || path == "/account/encapsulation/export"
        || path == "/account/encapsulation/rewrap"
}

fn decode_optional(value: &Option<String>) -> Result<Option<Vec<u8>>, ()> {
    let Some(value) = value else {
        return Ok(None);
    };
    URL_SAFE_NO_PAD.decode(value).map(Some).map_err(|_| ())
}

fn decode_signature(value: &str) -> Result<Signature, &'static str> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "signature is not base64url")?;
    let cbor = CBOR::try_from_data(&bytes).map_err(|_| "signature is not cbor")?;
    Signature::try_from(cbor).map_err(|_| "signature is not an elect signature")
}

fn fresh_challenge() -> Vec<u8> {
    let mut challenge = [0u8; 32];
    challenge[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    challenge[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    challenge.to_vec()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn ceremony_error(err: CeremonyError) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_request", &err.to_string())
}

fn encapsulation_error(err: EncapsulationError) -> Response {
    let (status, code) = match err {
        EncapsulationError::NotFound => (StatusCode::NOT_FOUND, "invalid_request"),
        EncapsulationError::Expired
        | EncapsulationError::Revoked
        | EncapsulationError::InvalidProof => (StatusCode::UNAUTHORIZED, "access_denied"),
        EncapsulationError::BadPurpose | EncapsulationError::WrongWrap => {
            (StatusCode::BAD_REQUEST, "invalid_request")
        }
        _ => (StatusCode::BAD_REQUEST, "invalid_request"),
    };
    oauth_error(status, code, &err.to_string())
}
