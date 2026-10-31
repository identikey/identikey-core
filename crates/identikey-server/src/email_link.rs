//! Email-address verification. The bearer token proves the address binding;
//! it does not establish an account session or authorize access to keys.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use identikey_keys::StoreError;
use serde::Deserialize;

use crate::{AppState, oauth_error, signed_in_xid};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginBody {
    email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemQuery {
    token: String,
}

pub async fn begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BeginBody>,
) -> Response {
    let Some(xid) = signed_in_xid(&state, &headers) else {
        return private(oauth_error(
            StatusCode::UNAUTHORIZED,
            "access_denied",
            "sign in to set your email",
        ));
    };
    match state.store.begin_email_magic_link(xid, &body.email).await {
        Ok(token) => private(Json(serde_json::json!({
            "redeem_url": format!("{}/account/email/redeem?token={token}", state.provider.issuer().trim_end_matches('/')),
            "expires_in": 900
        })).into_response()),
        Err(error) => failure(error),
    }
}

pub async fn redeem(State(state): State<AppState>, Query(query): Query<RedeemQuery>) -> Response {
    match state.store.redeem_email_magic_link(&query.token).await {
        Ok(_) => private(Json(serde_json::json!({ "email_verified": true })).into_response()),
        Err(error) => failure(error),
    }
}

fn failure(error: StoreError) -> Response {
    let (status, description) = match error {
        StoreError::InvalidEmail => (StatusCode::BAD_REQUEST, "enter a valid email address"),
        StoreError::InvalidEmailLink => (
            StatusCode::BAD_REQUEST,
            "link is invalid, expired, or already used",
        ),
        StoreError::EmailInUse => (StatusCode::CONFLICT, "email address is already in use"),
        StoreError::NotFound => (StatusCode::FORBIDDEN, "account is unavailable"),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "email verification failed",
        ),
    };
    private(oauth_error(
        status,
        "email_verification_failed",
        description,
    ))
}

fn private(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}
