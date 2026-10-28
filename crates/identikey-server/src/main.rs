//! The IdentiKey Core server binary.
//!
//! Wires `identikey-oidc`, `identikey-keys` and `identikey-recovery` together
//! behind axum, and serves the SvelteKit build output.
//!
//! Serves `/health` (liveness only), the convenience XID resolver
//! (`GET /.well-known/xid/{xid}`), Related Origin Requests
//! (`GET /.well-known/webauthn`, `identikey-core-2js`), and the OIDC
//! code+PKCE surface (`add-oidc-endpoints`) including confidential
//! clients (`add-confidential-clients`). Login at `/authorize` is
//! passkey assertion (`add-passkey-ceremonies`); `/authorize/dev` is
//! flag-gated. Hosted signup is `GET`/`POST /signup` (`add-hosted-login-ui`).
//! WebAuthn RP ID / origin allowlist fails closed
//! at boot (`identikey-core-62j`).
//!
mod account;
mod ceremonies;
mod clients;
mod encapsulation;
mod local_register;
mod managed_challenge;
mod pages;
mod passkey_metadata;
mod webauthn;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Form, OriginalUri, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use bc_components::{PrivateKeyBase, XIDProvider};
#[cfg(test)]
use clients::client_from_spec;
use clients::{extra_clients, optional_client};
use identikey_keys::{
    CustodyRung, KeysStore, ManagedKeyring, OperationalEd25519, Xid, c2_native, c2_wrap_recipient,
    operational_ed25519_public,
};
use identikey_oidc::{
    AuthorizeError, AuthorizeQuery, OidcError, PairwiseSalt, Provider, SigningKey, TokenRequest,
    parse_http_basic,
};
#[cfg(test)]
use identikey_oidc::{SubjectType, TokenEndpointAuthMethod};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::signal;
use tower_http::services::{ServeDir, ServeFile};
use webauthn::{WebAuthnConfig, parse_webauthn_config};
use zeroize::Zeroize;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
struct AppState {
    store: KeysStore,
    provider: Arc<Provider>,
    webauthn: WebAuthnConfig,
    ceremonies: Arc<ceremonies::CeremonyHub>,
    accounts: Arc<account::AccountSessions>,
    managed_keys: Arc<ManagedKeyring>,
    /// Loopback registrar. Discovery advertises `/register` only when this is set.
    local_register: bool,
}

/// Liveness only. This must not grow into a readiness check that reports on the
/// database or key material — a health endpoint that leaks internal state is a
/// reconnaissance surface on an auth server.
async fn health() -> &'static str {
    "ok"
}

fn web_assets(web_dir: std::path::PathBuf) -> ServeDir<ServeFile> {
    let fallback = ServeFile::new(web_dir.join("200.html"));
    ServeDir::new(web_dir).fallback(fallback)
}

#[cfg(test)]
fn router(
    store: KeysStore,
    provider: Arc<Provider>,
    dev_login: bool,
    webauthn: WebAuthnConfig,
    accounts: Arc<account::AccountSessions>,
) -> Router {
    router_with_keyring(
        store,
        provider,
        dev_login,
        webauthn,
        accounts,
        Arc::new(ManagedKeyring::single("test", [0x6d; 32])),
        None,
    )
}

fn router_with_keyring(
    store: KeysStore,
    provider: Arc<Provider>,
    dev_login: bool,
    webauthn: WebAuthnConfig,
    accounts: Arc<account::AccountSessions>,
    managed_keys: Arc<ManagedKeyring>,
    local: Option<Arc<local_register::LocalRegistry>>,
) -> Router {
    let web_dir = std::env::var_os("IDENTIKEY_WEB_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("web/build"));
    let ceremonies = Arc::new(ceremonies::CeremonyHub::from_config(&webauthn));
    let mut routes = Router::new()
        .route("/health", get(health))
        .route("/.well-known/xid/{xid}", get(xid_document))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/.well-known/webauthn", get(well_known_webauthn))
        .route("/authorize", get(authorize))
        .route(
            "/authorize/passkey",
            get(passkey_login_page).post(passkey_login_finish),
        )
        .route("/signup", get(signup_page).post(signup))
        .route("/account", get(account_page))
        .route("/account/encapsulation/begin", post(encapsulation::begin))
        .route("/account/encapsulation/export", post(encapsulation::export))
        .route("/account/encapsulation/rewrap", post(encapsulation::rewrap))
        .route("/webauthn/register/begin", post(register_begin))
        .route("/webauthn/register/finish", post(register_finish))
        .route("/webauthn/assert/begin", post(assert_begin))
        .route("/webauthn/assert/finish", post(assert_finish))
        .route("/devices/ssh_git", post(add_ssh_git))
        .route("/devices/ssh_git/revoke", post(revoke_ssh_git))
        .route("/managed-challenge/begin", post(managed_challenge::begin))
        .route(
            "/managed-challenge/finish/a3",
            post(managed_challenge::finish_a3),
        )
        .route(
            "/managed-challenge/finish/a4",
            post(managed_challenge::finish_a4),
        )
        .route(
            "/managed-challenge/retrieve",
            post(managed_challenge::retrieve),
        )
        .route("/challenge", get(challenge).post(challenge))
        .route("/device_authorization", post(device_authorization))
        .route("/device", get(device_page))
        .route("/device/deny", post(device_deny))
        .route("/device/assert/begin", post(device_assert_begin))
        .route("/device/assert/finish", post(device_assert_finish))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo).post(userinfo))
        .route("/introspect", post(introspect))
        .route("/revoke", post(revoke));
    if dev_login {
        // The form lives only on this route, which is absent when the flag is off.
        routes = routes.route(
            "/authorize/dev",
            get(dev_login_form).post(dev_login_complete),
        );
    } else {
        // Keep the disabled development surface at 404 rather than allowing the
        // static SPA fallback to turn an unknown POST into a 405 response.
        routes = routes.route("/authorize/dev", any(|| async { StatusCode::NOT_FOUND }));
    }
    if local.is_none() {
        // Same treatment as `/authorize/dev`: an absent registrar must be 404,
        // not the static fallback turning POST into 405.
        routes = routes.route("/register", any(|| async { StatusCode::NOT_FOUND }));
    }
    let app = routes
        .layer(middleware::from_fn_with_state(provider.clone(), spa_cors))
        .with_state(AppState {
            store,
            provider: Arc::clone(&provider),
            webauthn,
            ceremonies,
            accounts,
            managed_keys,
            local_register: local.is_some(),
        });
    let app = if let Some(registry) = local {
        app.merge(local_register::router(registry, provider))
    } else {
        app
    };
    app.fallback_service(web_assets(web_dir))
}

/// CORS for public-client PKCE (CMS / other SPAs). Origins come from
/// registered redirect URIs; unknown origins get no ACAO header.
async fn spa_cors(State(provider): State<Arc<Provider>>, req: Request, next: Next) -> Response {
    if encapsulation::is_encapsulation_path(req.uri().path()) {
        if req.method() == Method::OPTIONS {
            let mut response = StatusCode::NO_CONTENT.into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            return response;
        }
        return next.run(req).await;
    }
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let allowed = origin
        .as_deref()
        .is_some_and(|origin| provider.allows_browser_origin(origin));
    if req.method() == Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        apply_spa_cors(&mut response, origin.as_deref(), allowed);
        return response;
    }
    let mut response = next.run(req).await;
    apply_spa_cors(&mut response, origin.as_deref(), allowed);
    response
}

fn apply_spa_cors(response: &mut Response, origin: Option<&str>, allowed: bool) {
    if !allowed {
        return;
    }
    let Some(origin) = origin else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(origin) {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("authorization, content-type, accept"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Origin"));
}

/// Related Origin Requests (`identikey-core-2js`). Served from the first
/// deploy even when the list is only the RP origin. Never lists profile
/// or user-content origins.
async fn well_known_webauthn(State(state): State<AppState>) -> Json<webauthn::RelatedOrigins> {
    Json(state.webauthn.related_origins())
}

fn body_etag(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn if_none_match_hits(headers: &HeaderMap, etag: &str) -> bool {
    let Some(raw) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let trimmed = raw.trim();
    if trimmed == "*" {
        return true;
    }
    trimmed.split(',').any(|part| {
        let token = part.trim().trim_start_matches("W/").trim_matches('"');
        token == etag
    })
}

async fn xid_document(
    State(state): State<AppState>,
    Path(xid): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(xid) = Xid::parse(&xid) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let published = match state.store.published_document(xid).await {
        Ok(row) => row,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let Some(published) = published else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let etag = body_etag(&published.bytes);
    if if_none_match_hits(&headers, &etag) {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    let Ok(etag_header) = HeaderValue::from_str(&format!("\"{etag}\"")) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/cbor"),
            ),
            (header::ETAG, etag_header),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("max-age=60, must-revalidate"),
            ),
        ],
        published.bytes,
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct AuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DevLoginParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    scope: Option<String>,
    xid: Option<String>,
}

fn authorize_query(params: &AuthorizeParams) -> AuthorizeQuery {
    AuthorizeQuery {
        response_type: params.response_type.clone(),
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
        state: params.state.clone(),
        nonce: params.nonce.clone(),
        scope: params.scope.clone(),
    }
}

fn dev_query(params: &DevLoginParams) -> AuthorizeQuery {
    AuthorizeQuery {
        response_type: params.response_type.clone(),
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
        state: params.state.clone(),
        nonce: params.nonce.clone(),
        scope: params.scope.clone(),
    }
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    response: Option<String>,
    device_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorizationForm {
    client_id: Option<String>,
    client_secret: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceQuery {
    user_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceCodeBody {
    user_code: String,
}

#[derive(Debug, Deserialize)]
struct TokenBody {
    token: Option<String>,
}

async fn discovery(State(state): State<AppState>) -> Response {
    let doc = state.provider.discovery();
    let doc = if state.local_register {
        doc.with_registration_endpoint()
    } else {
        doc
    };
    Json(doc).into_response()
}

fn ceremony_http(err: ceremonies::CeremonyError) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_request", &err.to_string())
}

/// XID of the first-party account whose session cookie this request carries.
fn signed_in_xid(state: &AppState, headers: &HeaderMap) -> Option<Xid> {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok());
    let token = account::parse_cookie(cookie)?;
    state.accounts.lookup(token).ok().flatten()
}

/// Mint a first-party account session for `xid` as a `Set-Cookie` value.
fn account_cookie(state: &AppState, xid: Xid) -> Option<HeaderValue> {
    let token = state.accounts.issue(xid).ok()?;
    let secure = state
        .webauthn
        .expected_origins
        .iter()
        .any(|origin| origin.starts_with("https://"));
    Some(account::set_cookie(&token, secure))
}

/// Adding a passkey is adding a way in, so it needs the account session
/// (from signup or a prior enrollment). A XID alone is public: it is the
/// public `sub` and the Mjolnir owner id. Refuse unknown and foreign XIDs
/// alike so the answer does not reveal which accounts exist.
async fn register_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ceremonies::RegisterBegin>,
) -> Response {
    let Ok(xid) = Xid::parse(&body.xid) else {
        return ceremony_http(ceremonies::CeremonyError::UnknownAccount);
    };
    if signed_in_xid(&state, &headers) != Some(xid) {
        return oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "sign in to this account before adding a passkey",
        );
    }
    match state.ceremonies.begin_register(&state.store, xid).await {
        Ok((session, public_key)) => Json(ceremonies::CeremonyOptions {
            session,
            public_key,
        })
        .into_response(),
        Err(err) => ceremony_http(err),
    }
}

async fn register_finish(
    State(state): State<AppState>,
    Json(body): Json<ceremonies::RegisterFinish>,
) -> Response {
    let Ok(xid) = Xid::parse(&body.xid) else {
        return ceremony_http(ceremonies::CeremonyError::UnknownAccount);
    };
    match state
        .ceremonies
        .finish_register(
            &state.store,
            &body.session,
            xid,
            body.credential,
            body.nickname.as_deref(),
        )
        .await
    {
        Ok(()) => {
            let Some(cookie) = account_cookie(&state, xid) else {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            };
            (
                StatusCode::OK,
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    ),
                    (account::cookie_header(), cookie),
                ],
                serde_json::json!({ "next": "/account" }).to_string(),
            )
                .into_response()
        }
        Err(err) => ceremony_http(err),
    }
}

async fn account_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok());
    let Some(token) = account::parse_cookie(cookie) else {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            pages::account_signed_out(),
        )
            .into_response();
    };
    let Ok(Some(xid)) = state.accounts.lookup(token) else {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            pages::account_signed_out(),
        )
            .into_response();
    };
    let custody = match state.store.get_custody(xid).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                pages::account_signed_out(),
            )
                .into_response();
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let passkeys = match state.store.list_passkey_presentations(xid).await {
        Ok(rows) => rows
            .into_iter()
            .map(|row| {
                let metadata = row.aaguid.as_ref().and_then(passkey_metadata::resolve);
                pages::AccountPasskey {
                    nickname: row.nickname,
                    provider_name: metadata.as_ref().map(|entry| entry.name.clone()),
                    icon: metadata.and_then(|entry| entry.icon),
                    backed_up: row.backed_up,
                    last_used: row.last_used_at.map(|value| value.date().to_string()),
                }
            })
            .collect::<Vec<_>>(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let rung = match custody.rung {
        CustodyRung::C0 => "Placeholder (C0)",
        CustodyRung::C1 => "Managed (C1)",
        CustodyRung::C2 => "Managed (C2)",
        CustodyRung::C3 => "Self-custody (C3)",
        CustodyRung::C4 => "Self-custody (C4)",
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        pages::account(&xid.to_string(), rung, &passkeys),
    )
        .into_response()
}

async fn assert_begin(
    State(state): State<AppState>,
    Json(body): Json<ceremonies::AssertBegin>,
) -> Response {
    let xid = match body.xid.as_deref() {
        Some(raw) => match Xid::parse(raw) {
            Ok(xid) => Some(xid),
            Err(_) => return ceremony_http(ceremonies::CeremonyError::UnknownAccount),
        },
        None => None,
    };
    match state.ceremonies.begin_assert(&state.store, xid, None).await {
        Ok((session, public_key)) => Json(ceremonies::CeremonyOptions {
            session,
            public_key,
        })
        .into_response(),
        Err(err) => ceremony_http(err),
    }
}

async fn assert_finish(
    State(state): State<AppState>,
    Json(body): Json<ceremonies::AssertFinish>,
) -> Response {
    match state
        .ceremonies
        .finish_assert(&state.store, &body.session, body.credential)
        .await
    {
        Ok(finished) => {
            if finished.device.is_some() {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "confirm this login on the device page",
                );
            }
            if let Some(pending) = finished.pending {
                return issue_authorize_code(&state, pending, finished.xid);
            }
            Json(serde_json::json!({ "xid": finished.xid.to_string() })).into_response()
        }
        Err(err) => ceremony_http(err),
    }
}

fn issue_authorize_code(
    state: &AppState,
    pending: identikey_oidc::PendingAuthorization,
    xid: Xid,
) -> Response {
    match state.provider.issue_code(&pending, xid) {
        Ok(code) => json_redirect(&pending.redirect_uri, &code, pending.state.as_deref()),
        Err(err) => token_error(err, false),
    }
}

async fn passkey_login_page(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    let query = authorize_query(&params);
    let pending = match state.provider.validate_authorize(&query) {
        Ok(pending) => pending,
        Err(AuthorizeError::Redirect {
            uri,
            error,
            description,
            state,
        }) => return redirect_with_error(&uri, error, &description, state.as_deref()),
        Err(AuthorizeError::Deny { error, description }) => {
            return oauth_error(StatusCode::BAD_REQUEST, error, &description);
        }
    };
    let xid = params_xid_from_query(&params);
    match state
        .ceremonies
        .begin_assert(&state.store, xid, Some(pending))
        .await
    {
        Ok((session, public_key)) => {
            let options = serde_json::json!({
                "session": session,
                "publicKey": public_key,
            });
            let body = pages::passkey_login(&options.to_string());
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                body,
            )
                .into_response()
        }
        Err(err) => ceremony_http(err),
    }
}

async fn passkey_login_finish(
    State(state): State<AppState>,
    Json(body): Json<ceremonies::AssertFinish>,
) -> Response {
    assert_finish(State(state), Json(body)).await
}

async fn add_ssh_git(
    State(state): State<AppState>,
    Json(body): Json<ceremonies::AddSshGit>,
) -> Response {
    if body.elect_signature.is_some() {
        return ceremony_http(ceremonies::CeremonyError::ElectCannotAddDevice);
    }
    let (Some(session), Some(credential)) = (body.session, body.credential) else {
        return ceremony_http(ceremonies::CeremonyError::ElectCannotAddDevice);
    };
    match state
        .ceremonies
        .add_ssh_git_device(
            &state.store,
            &session,
            credential,
            body.device_public_key.as_bytes(),
            body.nickname.as_deref(),
        )
        .await
    {
        Ok((xid, id)) => Json(serde_json::json!({
            "xid": xid.to_string(),
            "credential_id": id,
            "kind": "ssh_git",
        }))
        .into_response(),
        Err(err) => ceremony_http(err),
    }
}

async fn revoke_ssh_git(
    State(state): State<AppState>,
    Json(body): Json<ceremonies::RevokeSshGit>,
) -> Response {
    let Ok(xid) = Xid::parse(&body.xid) else {
        return ceremony_http(ceremonies::CeremonyError::UnknownAccount);
    };
    match state.store.revoke_ssh_git(xid, body.credential_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(identikey_keys::StoreError::NotFound) => {
            ceremony_http(ceremonies::CeremonyError::UnknownCredential)
        }
        Err(err) => ceremony_http(err.into()),
    }
}

fn params_xid_from_query(_params: &AuthorizeParams) -> Option<Xid> {
    None
}

fn html_page(body: String) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

async fn signup_page() -> Response {
    html_page(pages::signup())
}

async fn signup(State(state): State<AppState>) -> Response {
    let user = PrivateKeyBase::new();
    let operational = OperationalEd25519::generate();
    let doc = match c2_native(&user, operational.public_keys()) {
        Ok(doc) => doc,
        Err(err) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &err.to_string(),
            );
        }
    };
    let xid = Xid::from(doc.xid());
    let mut scalar = *user.x25519_private_key().data();
    drop(user);
    let recipient = match c2_wrap_recipient(&doc) {
        Ok(bytes) => bytes,
        Err(err) => {
            scalar.zeroize();
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &err.to_string(),
            );
        }
    };
    let recipient: [u8; 32] = match recipient.try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            scalar.zeroize();
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "wrap recipient is not 32 bytes",
            );
        }
    };
    let encapsulation_blob = match state
        .managed_keys
        .seal_encapsulation(xid, &recipient, &scalar)
    {
        Ok(blob) => {
            scalar.zeroize();
            blob
        }
        Err(err) => {
            scalar.zeroize();
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &err.to_string(),
            );
        }
    };
    let public = match operational_ed25519_public(&doc) {
        Ok(public) => public,
        Err(err) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &err.to_string(),
            );
        }
    };
    let blob = match state.managed_keys.seal(xid, &public, operational.seed()) {
        Ok(blob) => blob,
        Err(err) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &err.to_string(),
            );
        }
    };
    let xid = match state
        .store
        .create_managed_with_encapsulation(CustodyRung::C2, &doc, &blob, Some(&encapsulation_blob))
        .await
    {
        Ok(xid) => xid,
        Err(err) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &err.to_string(),
            );
        }
    };
    // The new account's session lets this browser retry enrollment through
    // register/begin; nobody else can.
    let Some(cookie) = account_cookie(&state, xid) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match state.ceremonies.begin_register(&state.store, xid).await {
        Ok((session, public_key)) => (
            [(account::cookie_header(), cookie)],
            Json(ceremonies::SignupOptions {
                xid: xid.to_string(),
                session,
                public_key,
            }),
        )
            .into_response(),
        Err(err) => ceremony_http(err),
    }
}

async fn challenge(State(state): State<AppState>) -> Response {
    match state.provider.issue_challenge() {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/cbor")],
            bytes,
        )
            .into_response(),
        Err(err) => token_error(err, false),
    }
}

async fn jwks(State(state): State<AppState>) -> Response {
    let body = state.provider.jwks_json();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeParams>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let query = authorize_query(&params);
    match state.provider.validate_authorize(&query) {
        Ok(_) => {
            let suffix = uri.query().unwrap_or("");
            let location = format!("/authorize/passkey?{suffix}");
            match HeaderValue::from_str(&location) {
                Ok(value) => (StatusCode::FOUND, [(header::LOCATION, value)]).into_response(),
                Err(_) => oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "could not redirect to the login form",
                ),
            }
        }
        Err(AuthorizeError::Redirect {
            uri,
            error,
            description,
            state,
        }) => redirect_with_error(&uri, error, &description, state.as_deref()),
        Err(AuthorizeError::Deny { error, description }) => {
            oauth_error(StatusCode::BAD_REQUEST, error, &description)
        }
    }
}

fn hidden(name: &str, value: Option<&str>) -> String {
    let Some(value) = value.filter(|s| !s.is_empty()) else {
        return String::new();
    };
    format!(
        "<input type=\"hidden\" name=\"{name}\" value=\"{}\" />\n",
        pages::html_escape(value)
    )
}

async fn dev_login_form(
    State(state): State<AppState>,
    Query(params): Query<DevLoginParams>,
) -> Response {
    if params.xid.as_deref().is_some_and(|s| !s.is_empty()) {
        return complete_dev_login(state, params).await;
    }
    let body = format!(
        "<!doctype html><html><body>\
         <form method=\"post\" action=\"/authorize/dev\">\
         {}{}{}{}{}{}{}{}\
         <label>XID <input name=\"xid\" required pattern=\"[0-9a-f]{{64}}\" /></label>\
         <button type=\"submit\">Continue</button>\
         </form></body></html>",
        hidden("response_type", params.response_type.as_deref()),
        hidden("client_id", params.client_id.as_deref()),
        hidden("redirect_uri", params.redirect_uri.as_deref()),
        hidden("code_challenge", params.code_challenge.as_deref()),
        hidden(
            "code_challenge_method",
            params.code_challenge_method.as_deref(),
        ),
        hidden("state", params.state.as_deref()),
        hidden("nonce", params.nonce.as_deref()),
        hidden("scope", params.scope.as_deref()),
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn dev_login_complete(
    State(state): State<AppState>,
    Form(params): Form<DevLoginParams>,
) -> Response {
    complete_dev_login(state, params).await
}

async fn complete_dev_login(state: AppState, params: DevLoginParams) -> Response {
    let query = dev_query(&params);
    let pending = match state.provider.validate_authorize(&query) {
        Ok(pending) => pending,
        Err(AuthorizeError::Redirect {
            uri,
            error,
            description,
            state,
        }) => return redirect_with_error(&uri, error, &description, state.as_deref()),
        Err(AuthorizeError::Deny { error, description }) => {
            return oauth_error(StatusCode::BAD_REQUEST, error, &description);
        }
    };
    let Some(raw) = params.xid.as_deref().filter(|s| !s.is_empty()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "xid is required",
        );
    };
    let Ok(xid) = Xid::parse(raw) else {
        return redirect_with_error(
            &pending.redirect_uri,
            "access_denied",
            "unknown xid",
            pending.state.as_deref(),
        );
    };
    match state.store.get_account(xid).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return redirect_with_error(
                &pending.redirect_uri,
                "access_denied",
                "unknown xid",
                pending.state.as_deref(),
            );
        }
        Err(_) => {
            return oauth_error(StatusCode::BAD_REQUEST, "server_error", "store unavailable");
        }
    }
    let code = match state.provider.issue_code(&pending, xid) {
        Ok(code) => code,
        Err(err) => return token_error(err, false),
    };
    redirect_with_code(&pending.redirect_uri, &code, pending.state.as_deref())
}

/// Fetch-based WebAuthn cannot follow a 302 to the RP: `redirect:manual`
/// is opaque and hides `Location`. Return a JSON body the page can assign.
fn json_redirect(uri: &str, code: &str, state: Option<&str>) -> Response {
    let Ok(mut parsed) = url::Url::parse(uri) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is not a URI",
        );
    };
    {
        let mut pairs = parsed.query_pairs_mut();
        pairs.append_pair("code", code);
        if let Some(state) = state {
            pairs.append_pair("state", state);
        }
    }
    let location = parsed.to_string();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({ "redirect": location }).to_string(),
    )
        .into_response()
}

fn redirect_with_code(uri: &str, code: &str, state: Option<&str>) -> Response {
    let Ok(mut parsed) = url::Url::parse(uri) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is not a URI",
        );
    };
    {
        let mut pairs = parsed.query_pairs_mut();
        pairs.append_pair("code", code);
        if let Some(state) = state {
            pairs.append_pair("state", state);
        }
    }
    let location = parsed.to_string();
    match HeaderValue::from_str(&location) {
        Ok(value) => (StatusCode::FOUND, [(header::LOCATION, value)]).into_response(),
        Err(_) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri produced an invalid Location",
        ),
    }
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let basic = match headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        Some(raw) => match parse_http_basic(raw) {
            Ok(parsed) => parsed,
            Err(err) => return token_error(err, true),
        },
        None => None,
    };
    let used_basic = basic.is_some();
    let (basic_client_id, basic_client_secret) = match basic {
        Some((id, secret)) => (Some(id), Some(secret)),
        None => (None, None),
    };
    let req = TokenRequest {
        grant_type: form.grant_type,
        code: form.code,
        redirect_uri: form.redirect_uri,
        client_id: form.client_id,
        client_secret: form.client_secret,
        basic_client_id,
        basic_client_secret,
        code_verifier: form.code_verifier,
        refresh_token: form.refresh_token,
        response: form.response,
        device_code: form.device_code,
    };
    match state.provider.token(&req).await {
        Ok(issued) => Json(issued).into_response(),
        Err(err) => token_error(err, used_basic),
    }
}

async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(access) = bearer_token(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "missing bearer token",
        )
            .into_response();
    };
    match state.provider.userinfo(access) {
        Ok(info) => Json(info).into_response(),
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "invalid token",
        )
            .into_response(),
    }
}

async fn introspect(State(state): State<AppState>, Form(body): Form<TokenBody>) -> Response {
    let token = body.token.unwrap_or_default();
    Json(state.provider.introspect(&token).await).into_response()
}

async fn revoke(State(state): State<AppState>, Form(body): Form<TokenBody>) -> Response {
    let token = body.token.unwrap_or_default();
    match state.provider.revoke(&token).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(err) => token_error(err, false),
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
}

fn attempt_source(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("direct")
        .to_owned()
}

async fn device_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeviceAuthorizationForm>,
) -> Response {
    let basic = match headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    {
        Some(raw) => match parse_http_basic(raw) {
            Ok(parsed) => parsed,
            Err(err) => return token_error(err, true),
        },
        None => None,
    };
    let used_basic = basic.is_some();
    let (basic_client_id, basic_client_secret) = match basic {
        Some((id, secret)) => (Some(id), Some(secret)),
        None => (None, None),
    };
    let req = TokenRequest {
        client_id: form.client_id,
        client_secret: form.client_secret,
        basic_client_id,
        basic_client_secret,
        ..TokenRequest::default()
    };
    match state.provider.start_device(&req, form.scope.as_deref()) {
        Ok(body) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(body),
        )
            .into_response(),
        Err(err) => token_error(err, used_basic),
    }
}

/// The account cookie is not read. A signed-in browser does not approve a device code.
async fn device_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DeviceQuery>,
) -> Response {
    let Some(user_code) = query.user_code.filter(|code| !code.trim().is_empty()) else {
        return html_page(pages::device_confirm(None, false));
    };
    let prompt = match state
        .provider
        .device_prompt(&user_code, &attempt_source(&headers))
    {
        Ok(prompt) => prompt,
        Err(_) => return html_page(pages::device_confirm(None, true)),
    };
    let Some(client) = state.provider.registered_client(&prompt.client_id) else {
        return html_page(pages::device_confirm(None, true));
    };
    html_page(pages::device_confirm(
        Some(&pages::DeviceConfirm {
            user_code,
            display_name: client.display_name,
        }),
        false,
    ))
}

async fn device_assert_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeviceCodeBody>,
) -> Response {
    if let Err(err) = state
        .provider
        .device_prompt(&body.user_code, &attempt_source(&headers))
    {
        return token_error(err, false);
    }
    match state.ceremonies.begin_device_assert(&body.user_code).await {
        Ok((session, public_key, challenge)) => {
            if let Err(err) = state
                .provider
                .bind_device_assertion(&body.user_code, &challenge)
            {
                return token_error(err, false);
            }
            Json(ceremonies::CeremonyOptions {
                session,
                public_key,
            })
            .into_response()
        }
        Err(err) => ceremony_http(err),
    }
}

async fn device_assert_finish(
    State(state): State<AppState>,
    Json(body): Json<ceremonies::AssertFinish>,
) -> Response {
    match state
        .ceremonies
        .finish_assert(&state.store, &body.session, body.credential)
        .await
    {
        Ok(finished) => {
            let Some(device) = finished.device else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "this ceremony is not a device approval",
                );
            };
            if !body.confirmed {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "confirmation is required",
                );
            }
            match state
                .provider
                .approve_device(&device.user_code, finished.xid, &device.challenge)
            {
                Ok(()) => Json(serde_json::json!({ "approved": true })).into_response(),
                Err(err) => token_error(err, false),
            }
        }
        Err(err) => ceremony_http(err),
    }
}

async fn device_deny(State(state): State<AppState>, Json(body): Json<DeviceCodeBody>) -> Response {
    match state.provider.deny_device(&body.user_code) {
        Ok(()) => Json(serde_json::json!({ "denied": true })).into_response(),
        Err(err) => token_error(err, false),
    }
}

fn token_error(err: OidcError, used_basic: bool) -> Response {
    let status = if err.error == "invalid_client" {
        StatusCode::UNAUTHORIZED
    } else if err.error == "server_error" {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };
    if err.error == "invalid_client" && used_basic {
        return (
            status,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"identikey\""),
            )],
            Json(serde_json::json!({
                "error": err.error,
                "error_description": err.description,
            })),
        )
            .into_response();
    }
    oauth_error(status, err.error, &err.description)
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

fn redirect_with_error(uri: &str, error: &str, description: &str, state: Option<&str>) -> Response {
    let Ok(mut parsed) = url::Url::parse(uri) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is not a URI",
        );
    };
    {
        let mut pairs = parsed.query_pairs_mut();
        pairs.append_pair("error", error);
        pairs.append_pair("error_description", description);
        if let Some(state) = state {
            pairs.append_pair("state", state);
        }
    }
    let location = parsed.to_string();
    match HeaderValue::from_str(&location) {
        Ok(value) => (StatusCode::FOUND, [(header::LOCATION, value)]).into_response(),
        Err(_) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri produced an invalid Location",
        ),
    }
}

/// The bind address used when `IDENTIKEY_BIND` is unset.
///
/// Loopback is the right default: a misconfigured auth server should be
/// unreachable rather than exposed. Binding publicly is an explicit act.
const DEFAULT_BIND: &str = "127.0.0.1:8080";

/// Parse a bind address, kept separate from the environment so it is testable
/// without mutating process-global state.
fn parse_bind(raw: &str) -> Result<SocketAddr, BoxError> {
    raw.parse::<SocketAddr>()
        .map_err(|e| format!("IDENTIKEY_BIND is not a valid socket address ({raw}): {e}").into())
}

fn bind_addr() -> Result<SocketAddr, BoxError> {
    let raw = std::env::var("IDENTIKEY_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_owned());
    parse_bind(&raw)
}

/// Fail closed: an auth server that is up without a store is a lie.
fn database_url(raw: Option<String>) -> Result<String, BoxError> {
    match raw {
        Some(url) if !url.is_empty() => Ok(url),
        _ => Err("DATABASE_URL is required".into()),
    }
}

fn managed_keyring(raw: Option<String>, kid: Option<String>) -> Result<ManagedKeyring, BoxError> {
    let raw = raw.ok_or("IDENTIKEY_MANAGED_WRAP_KEY is required")?;
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("IDENTIKEY_MANAGED_WRAP_KEY must be exactly 64 hexadecimal characters".into());
    }
    let mut key = [0_u8; 32];
    for (index, pair) in raw.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| "invalid managed wrap key")?;
        let slot = key
            .get_mut(index)
            .ok_or("invalid managed wrap key length")?;
        *slot = u8::from_str_radix(text, 16).map_err(|_| "invalid managed wrap key")?;
    }
    let kid = kid
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "v1".into());
    Ok(ManagedKeyring::single(kid, key))
}

async fn shutdown_signal() {
    if let Err(e) = signal::ctrl_c().await {
        tracing::error!(error = %e, "failed to install ctrl-c handler; shutting down");
    }
    tracing::info!("shutdown signal received");
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    if std::env::args().nth(1).as_deref() == Some("check-clients") {
        if !clients::check_clients()? {
            std::process::exit(1);
        }
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Fail closed before opening a store or binding a port.
    let webauthn = parse_webauthn_config(
        std::env::var("WEBAUTHN_RP_ID").ok().as_deref(),
        std::env::var("WEBAUTHN_EXPECTED_ORIGIN").ok().as_deref(),
    )?;
    tracing::info!("webauthn origin allowlist ready");
    let managed_keys = Arc::new(managed_keyring(
        std::env::var("IDENTIKEY_MANAGED_WRAP_KEY").ok(),
        std::env::var("IDENTIKEY_MANAGED_WRAP_KID").ok(),
    )?);
    tracing::info!("managed wrapping key ready");

    let url = database_url(std::env::var("DATABASE_URL").ok())?;
    let store = KeysStore::connect(&url).await?;
    store.migrate().await?;
    let indeterminate = store
        .mark_claimed_managed_challenges_indeterminate()
        .await?;
    if indeterminate > 0 {
        tracing::warn!(
            indeterminate,
            "terminalized managed signing claims left by restart"
        );
    }
    tracing::info!("database migrated");

    let data_dir = std::env::var("IDENTIKEY_DATA_DIR").unwrap_or_else(|_| ".".into());
    let data_path = std::path::Path::new(&data_dir);
    // Load only. Never log the values — Debug redacts, and we do not print hex.
    let salt = PairwiseSalt::load(
        std::env::var("IDENTIKEY_PAIRWISE_SALT").ok().as_deref(),
        data_path,
    )?;
    tracing::info!("pairwise salt ready");

    let signing = SigningKey::load(
        std::env::var("IDENTIKEY_SIGNING_KEY").ok().as_deref(),
        data_path,
    )?;
    tracing::info!("signing key ready");

    let issuer =
        std::env::var("IDENTIKEY_ISSUER").unwrap_or_else(|_| format!("http://{DEFAULT_BIND}"));
    let provider =
        Arc::new(Provider::new(issuer, signing, salt).with_refresh_pool(store.pool().clone()));
    let mut pinned = HashSet::new();
    if let Some(client) = optional_client()? {
        tracing::info!(
            client_id = %client.id,
            auth = client.token_endpoint_auth_method.as_str(),
            "registered OIDC client"
        );
        pinned.insert(client.id.clone());
        provider.register(client);
    }
    for client in extra_clients()? {
        tracing::info!(
            client_id = %client.id,
            auth = client.token_endpoint_auth_method.as_str(),
            "registered OIDC client"
        );
        pinned.insert(client.id.clone());
        provider.register(client);
    }

    let local_register =
        local_register::flag_from_env(std::env::var("IDENTIKEY_LOCAL_REGISTER").ok().as_deref())?;
    let addr = bind_addr()?;
    let local = if local_register {
        local_register::require_loopback_bind(addr)?;
        let registry = Arc::new(local_register::LocalRegistry::open(
            data_path.join("local-clients.json"),
            pinned,
        )?);
        let loaded = registry.load_into(&provider)?;
        tracing::info!(clients = loaded, "loaded local OIDC clients");
        Some(registry)
    } else {
        None
    };

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "identikey-server listening");

    let dev_login = std::env::var("IDENTIKEY_DEV_LOGIN").ok().as_deref() == Some("1");
    axum::serve(
        listener,
        router_with_keyring(
            store,
            provider,
            dev_login,
            webauthn,
            Arc::new(account::AccountSessions::default()),
            managed_keys,
            local,
        ),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;
    use identikey_oidc::{Client, s256_challenge};

    fn test_provider() -> Arc<Provider> {
        let salt = PairwiseSalt::from_hex(&"ab".repeat(32)).unwrap();
        let provider = Provider::generate("http://127.0.0.1:8080", salt).unwrap();
        provider
            .register(Client::new("smoke", "127.0.0.1").with_redirect("http://127.0.0.1:9999/cb"));
        Arc::new(provider)
    }

    fn test_webauthn() -> WebAuthnConfig {
        parse_webauthn_config(Some("auth.identikey.me"), Some("https://auth.identikey.me")).unwrap()
    }

    fn test_router(store: KeysStore) -> Router {
        test_router_with_accounts(store, Arc::new(account::AccountSessions::default()))
    }

    fn test_router_with_accounts(
        store: KeysStore,
        accounts: Arc<account::AccountSessions>,
    ) -> Router {
        router(store, test_provider(), false, test_webauthn(), accounts)
    }

    fn test_router_dev(store: KeysStore, provider: Arc<Provider>) -> Router {
        router(
            store,
            provider,
            true,
            test_webauthn(),
            Arc::new(account::AccountSessions::default()),
        )
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn signup_seals_the_user_x25519(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let app = test_router(KeysStore::from_pool(pool.clone()));
        let created = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/signup")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(
            &body::to_bytes(created.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let xid = Xid::parse(json["xid"].as_str().unwrap()).unwrap();
        let present: bool = sqlx::query_scalar(
            "SELECT encapsulation_key_blob IS NOT NULL FROM custody_records WHERE xid = $1",
        )
        .bind(xid.as_bytes().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(present);
        let managed: Vec<u8> =
            sqlx::query_scalar("SELECT managed_key_blob FROM custody_records WHERE xid = $1")
                .bind(xid.as_bytes().as_slice())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(&managed[..4], b"IKMK");
        let sealed: Vec<u8> =
            sqlx::query_scalar("SELECT encapsulation_key_blob FROM custody_records WHERE xid = $1")
                .bind(xid.as_bytes().as_slice())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(&sealed[..4], b"IKEK");
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn encapsulation_routes_reject_spa_cors_and_a_cookie(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let app = test_router(KeysStore::from_pool(pool));
        for uri in [
            "/account/encapsulation/begin",
            "/account/encapsulation/export",
            "/account/encapsulation/rewrap",
        ] {
            let preflight = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("OPTIONS")
                        .uri(uri)
                        .header(header::ORIGIN, "http://127.0.0.1:9999")
                        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                preflight
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .is_none(),
                "{uri} preflight leaked ACAO"
            );
        }
        let created = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/signup")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookie = created
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .unwrap()
            .to_owned();
        let begun = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/account/encapsulation/begin")
                    .header(header::ORIGIN, "http://127.0.0.1:9999")
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"purpose":"export"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(begun.status(), StatusCode::OK);
        assert!(
            begun
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("no-store")
        );
        assert!(
            begun
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        let begin_json: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(begun.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        let attempt = begin_json["attempt"].as_str().unwrap();
        let cookie_rewrap = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/account/encapsulation/rewrap")
                    .header(header::ORIGIN, "http://127.0.0.1:9999")
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"attempt":"{attempt}","wrap":"AAAA"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cookie_rewrap.status(), StatusCode::UNAUTHORIZED);
        assert!(
            cookie_rewrap
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        let exported = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/account/encapsulation/export")
                    .header(header::ORIGIN, "http://127.0.0.1:9999")
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"attempt":"{attempt}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(exported.status(), StatusCode::UNAUTHORIZED);
        assert!(
            exported
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_eq!(
            exported.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn http_export_returns_the_scalar_without_html(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::Request;
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use bc_components::Signer;
        use dcbor::prelude::CBOR;
        use identikey_keys::{BeginEncapsulationRequest, encapsulation_transcript};
        use tower::ServiceExt;

        let user = PrivateKeyBase::new();
        let operational = OperationalEd25519::generate();
        let doc = c2_native(&user, operational.public_keys()).unwrap();
        let xid = Xid::from(doc.xid());
        let scalar = *user.x25519_private_key().data();
        let recipient: [u8; 32] = c2_wrap_recipient(&doc).unwrap().try_into().unwrap();
        let keys = ManagedKeyring::single("test", [0x6d; 32]);
        let blob = keys.seal_encapsulation(xid, &recipient, &scalar).unwrap();
        let public = operational_ed25519_public(&doc).unwrap();
        let managed = keys.seal(xid, &public, operational.seed()).unwrap();
        let store = KeysStore::from_pool(pool.clone());
        store
            .create_managed_with_encapsulation(CustodyRung::C2, &doc, &managed, Some(&blob))
            .await
            .unwrap();
        let begun = store
            .begin_encapsulation(BeginEncapsulationRequest {
                xid,
                purpose: "export",
                challenge: &[0x33; 32],
                wrap: None,
                webauthn_state: None,
                now: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                friend: None,
            })
            .await
            .unwrap();
        let transcript = encapsulation_transcript(
            "export",
            xid.as_bytes(),
            begun.id.as_bytes(),
            &begun.challenge,
            begun.iat,
            begun.exp,
            None,
            None,
        );
        let signature = user.sign(&transcript).unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(CBOR::from(signature).to_cbor_data());
        let app = test_router(KeysStore::from_pool(pool));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/account/encapsulation/export")
                    .header(header::ORIGIN, "http://127.0.0.1:9999")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"attempt":"{}","signature":"{encoded}"}}"#,
                        begun.id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), URL_SAFE_NO_PAD.encode(scalar).as_bytes());
        assert!(!body.windows(5).any(|window| window == b"<html"));
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn http_rewrap_returns_the_wrap_without_html(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::Request;
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use bc_components::Signer;
        use dcbor::prelude::*;
        use identikey_keys::{BeginEncapsulationRequest, encapsulation_transcript, wrap_data_key};
        use tower::ServiceExt;

        let owner = PrivateKeyBase::new();
        let owner_operational = OperationalEd25519::generate();
        let owner_doc = c2_native(&owner, owner_operational.public_keys()).unwrap();
        let owner_xid = Xid::from(owner_doc.xid());
        let owner_scalar = *owner.x25519_private_key().data();
        let owner_recipient: [u8; 32] = c2_wrap_recipient(&owner_doc).unwrap().try_into().unwrap();
        let friend = PrivateKeyBase::new();
        let friend_operational = OperationalEd25519::generate();
        let friend_doc = c2_native(&friend, friend_operational.public_keys()).unwrap();
        let friend_xid = Xid::from(friend_doc.xid());
        let friend_recipient: [u8; 32] =
            c2_wrap_recipient(&friend_doc).unwrap().try_into().unwrap();
        let keys = ManagedKeyring::single("test", [0x6d; 32]);
        let store = KeysStore::from_pool(pool.clone());
        for (user, doc, xid, recipient, operational) in [
            (
                &owner,
                &owner_doc,
                owner_xid,
                owner_recipient,
                &owner_operational,
            ),
            (
                &friend,
                &friend_doc,
                friend_xid,
                friend_recipient,
                &friend_operational,
            ),
        ] {
            let scalar = *user.x25519_private_key().data();
            let blob = keys.seal_encapsulation(xid, &recipient, &scalar).unwrap();
            let public = operational_ed25519_public(doc).unwrap();
            let managed = keys.seal(xid, &public, operational.seed()).unwrap();
            store
                .create_managed_with_encapsulation(CustodyRung::C2, doc, &managed, Some(&blob))
                .await
                .unwrap();
        }
        let ptk = [0xab; 32];
        let wrapped = wrap_data_key(&owner_recipient, &ptk).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let begun = store
            .begin_encapsulation(BeginEncapsulationRequest {
                xid: owner_xid,
                purpose: "rewrap",
                challenge: &[0x33; 32],
                wrap: Some(&wrapped),
                webauthn_state: None,
                now,
                friend: Some(friend_xid),
            })
            .await
            .unwrap();
        assert_eq!(begun.friend_has_seal, Some(true));
        let wrap_digest: [u8; 32] = Sha256::digest(&wrapped).into();
        let transcript = encapsulation_transcript(
            "rewrap",
            owner_xid.as_bytes(),
            begun.id.as_bytes(),
            &begun.challenge,
            begun.iat,
            begun.exp,
            Some(&wrap_digest),
            Some(&friend_recipient),
        );
        let signature = owner.sign(&transcript).unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(CBOR::from(signature).to_cbor_data());
        let wrap_b64 = URL_SAFE_NO_PAD.encode(&wrapped);
        let app = test_router(KeysStore::from_pool(pool));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/account/encapsulation/rewrap")
                    .header(header::ORIGIN, "http://127.0.0.1:9999")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"attempt":"{}","wrap":"{wrap_b64}","signature":"{encoded}"}}"#,
                        begun.id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body.windows(5).any(|window| window == b"<html"));
        let decoded = URL_SAFE_NO_PAD.decode(body.as_ref()).unwrap();
        assert_ne!(decoded.as_slice(), ptk.as_slice());
        assert_ne!(decoded.as_slice(), owner_scalar.as_slice());
        let cbor = CBOR::try_from_data(&decoded).unwrap();
        let CBORCase::Map(map) = cbor.into_case() else {
            panic!("rewrap body is not a dCBOR map");
        };
        let alg: String = map.extract("alg").unwrap();
        assert_eq!(alg, "x25519-xchacha20poly1305");
        let recipient: ByteString = map.extract("recipient").unwrap();
        assert_eq!(recipient.as_ref(), friend_recipient.as_slice());
        let again = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/account/encapsulation/rewrap")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"attempt":"{}","wrap":"{wrap_b64}","signature":"{encoded}"}}"#,
                        begun.id
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(again.status(), StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn spa_preflight_allows_registered_loopback_origin(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = test_router(KeysStore::from_pool(pool));
        let allowed = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/token")
                    .header(header::ORIGIN, "http://127.0.0.1:9999")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            allowed
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("http://127.0.0.1:9999")
        );

        let denied = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/token")
                    .header(header::ORIGIN, "https://evil.example")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            denied
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }

    #[test]
    fn default_bind_is_loopback() {
        // Safety net for DEFAULT_BIND: if it ever becomes 0.0.0.0, a
        // misconfigured deployment is exposed rather than unreachable.
        let addr = parse_bind(DEFAULT_BIND).unwrap();
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn malformed_bind_is_rejected() {
        assert!(
            parse_bind("not-an-address").is_err(),
            "a malformed bind address must fail at boot, not silently fall back"
        );
    }

    #[tokio::test]
    async fn web_assets_serve_files_and_spa_fallback() {
        use axum::body::Body;
        use axum::http::Request;
        use std::fs;
        use tower::ServiceExt;

        let web_dir = std::env::temp_dir().join(format!("identikey-web-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&web_dir).unwrap();
        fs::write(
            web_dir.join("200.html"),
            "<!doctype html><title>IdentiKey</title>",
        )
        .unwrap();
        fs::write(web_dir.join("app.css"), "body{color:#123}").unwrap();

        let asset = web_assets(web_dir.clone())
            .oneshot(
                Request::builder()
                    .uri("/app.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(asset.status(), StatusCode::OK);
        assert_eq!(
            asset.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/css"
        );

        let fallback = web_assets(web_dir.clone())
            .oneshot(
                Request::builder()
                    .uri("/account/security")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fallback.status(), StatusCode::OK);
        assert_eq!(
            fallback.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html"
        );

        fs::remove_dir_all(web_dir).unwrap();
    }

    #[test]
    fn missing_database_url_fails_closed() {
        let err = database_url(None).unwrap_err().to_string();
        assert!(
            err.contains("DATABASE_URL"),
            "boot error must name DATABASE_URL, got {err}"
        );
        assert!(database_url(Some(String::new())).is_err());
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn well_known_webauthn_lists_configured_https_origin_only(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let response = test_router(KeysStore::from_pool(pool))
            .oneshot(
                Request::builder()
                    .uri("/.well-known/webauthn")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            doc,
            serde_json::json!({"origins": ["https://auth.identikey.me"]})
        );
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn well_known_serves_stored_document(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use bc_components::PrivateKeyBase;
        use identikey_keys::{CustodyRung, c2_native};
        use tower::ServiceExt;

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &[0x51, 0x47])
            .await
            .unwrap();
        let expected = store.document_bytes(xid).await.unwrap().unwrap();

        let response = test_router(store.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/.well-known/xid/{xid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "max-age=60, must-revalidate"
        );
        let etag = response
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), expected.as_slice());

        let not_modified = test_router(store.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/.well-known/xid/{xid}"))
                    .header(header::IF_NONE_MATCH, etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);

        let missing = test_router(store.clone())
            .oneshot(
                Request::builder()
                    .uri("/.well-known/xid/dead")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let hex_path = test_router(store)
            .oneshot(
                Request::builder()
                    .uri(format!("/.well-known/xid/{}", xid.to_hex()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(hex_path.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn well_known_etag_changes_after_write(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use bc_components::{PrivateKeyBase, PublicKeysProvider};
        use bc_xid::{Key, Privilege};
        use identikey_keys::{CustodyRung, c2_native};
        use tower::ServiceExt;

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let extra = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &[0x51, 0x47])
            .await
            .unwrap();

        let first = test_router(store.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/.well-known/xid/{xid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first_etag = first
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        let mut updated = store.get_custody(xid).await.unwrap().unwrap().document;
        let mut key = Key::new(extra.public_keys());
        key.add_permission(Privilege::Auth);
        updated.add_key(key).unwrap();
        store.apply_document_update(&user, &updated).await.unwrap();

        let second = test_router(store)
            .oneshot(
                Request::builder()
                    .uri(format!("/.well-known/xid/{xid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let second_etag = second
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap();
        assert_ne!(first_etag, second_etag);
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn discovery_names_code_and_s256(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let response = test_router(KeysStore::from_pool(pool))
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let as_text = body.as_ref();
        let text = std::str::from_utf8(as_text).unwrap();
        assert!(doc["authorization_endpoint"].as_str().is_some());
        assert!(doc["token_endpoint"].as_str().is_some());
        assert!(doc["jwks_uri"].as_str().is_some());
        assert_eq!(doc["response_types_supported"], serde_json::json!(["code"]));
        assert_eq!(
            doc["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
        assert!(!text.contains("password"));
        assert!(doc.get("registration_endpoint").is_none());
        assert!(
            !doc["response_types_supported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "token")
        );
        assert_eq!(
            doc["token_endpoint_auth_methods_supported"],
            serde_json::json!(["none", "client_secret_basic", "client_secret_post"])
        );
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn local_register_is_not_mounted_by_default(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let response = test_router(KeysStore::from_pool(pool))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"client_id":"mesh","redirect_uris":["http://127.0.0.1:9/cb"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn authorize_without_pkce_is_refused(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let response = test_router(KeysStore::from_pool(pool))
            .oneshot(
                Request::builder()
                    .uri("/authorize?response_type=code&client_id=smoke&redirect_uri=http://127.0.0.1:9999/cb")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("error=invalid_request"));
        assert!(!location.contains("code="));
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn token_rejects_code_replay(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use identikey_keys::Xid;
        use tower::ServiceExt;

        let store = KeysStore::from_pool(pool);
        let provider = test_provider();
        let pending = provider
            .validate_authorize(&AuthorizeQuery {
                response_type: Some("code".into()),
                client_id: Some("smoke".into()),
                redirect_uri: Some("http://127.0.0.1:9999/cb".into()),
                code_challenge: Some(s256_challenge(VERIFIER)),
                code_challenge_method: Some("S256".into()),
                state: None,
                nonce: None,
                scope: Some("openid".into()),
            })
            .unwrap();
        let code = provider
            .issue_code(&pending, Xid::from_bytes([0x22; 32]))
            .unwrap();
        let app = router(
            store,
            provider,
            false,
            test_webauthn(),
            Arc::new(account::AccountSessions::default()),
        );
        let form = format!(
            "grant_type=authorization_code&code={code}&redirect_uri=http://127.0.0.1:9999/cb&client_id=smoke&code_verifier={VERIFIER}"
        );

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first_body = body::to_bytes(first.into_body(), usize::MAX).await.unwrap();
        let issued: serde_json::Value = serde_json::from_slice(&first_body).unwrap();
        assert!(issued["access_token"].as_str().unwrap().len() > 8);
        assert!(issued["id_token"].as_str().unwrap().contains('.'));

        let second = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::BAD_REQUEST);
        let second_body = body::to_bytes(second.into_body(), usize::MAX)
            .await
            .unwrap();
        let err: serde_json::Value = serde_json::from_slice(&second_body).unwrap();
        assert_eq!(err["error"], "invalid_grant");
    }

    fn authorize_qs(challenge: &str) -> String {
        format!(
            "response_type=code&client_id=smoke&redirect_uri=http://127.0.0.1:9999/cb&code_challenge={challenge}&code_challenge_method=S256"
        )
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn dev_login_issues_code_for_stored_xid(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use bc_components::PrivateKeyBase;
        use identikey_keys::{CustodyRung, c2_native};
        use tower::ServiceExt;

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &[0x51, 0x47])
            .await
            .unwrap();
        let provider = test_provider();
        let app = test_router_dev(store, provider);
        let challenge = s256_challenge(VERIFIER);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/authorize/dev")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "{}&xid={xid}",
                        authorize_qs(&challenge)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            location.contains("code="),
            "expected a code on the redirect, got {location}"
        );
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn dev_login_path_absent_without_flag(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let response = test_router(KeysStore::from_pool(pool))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/authorize/dev")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "{}&xid={}",
                        authorize_qs(&s256_challenge(VERIFIER)),
                        "11".repeat(32)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn unknown_xid_is_refused_and_creates_nothing(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use identikey_keys::Xid;
        use tower::ServiceExt;

        let store = KeysStore::from_pool(pool);
        let missing = Xid::from_bytes([0x33; 32]);
        let provider = test_provider();
        let app = test_router_dev(store.clone(), provider);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/authorize/dev")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "{}&xid={missing}",
                        authorize_qs(&s256_challenge(VERIFIER))
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("error=access_denied"));
        assert!(!location.contains("code="));
        assert!(store.get_account(missing).await.unwrap().is_none());
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn health_does_not_mention_dev_login(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let response = test_router_dev(KeysStore::from_pool(pool), test_provider())
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert_eq!(text, "ok");
        assert!(!text.to_ascii_lowercase().contains("dev"));
        assert!(!text.contains("IDENTIKEY"));
    }

    #[test]
    fn confidential_spec_hashes_and_public_rejects_secret() {
        let confidential = client_from_spec(
            "basic-1".into(),
            vec!["http://127.0.0.1:9999/cb".into()],
            Some("s3cret".into()),
            Some("client_secret_basic".into()),
            None,
            Some("127.0.0.1".into()),
        )
        .unwrap();
        assert_eq!(
            confidential.token_endpoint_auth_method,
            TokenEndpointAuthMethod::ClientSecretBasic
        );
        let leaked = format!("{confidential:?}");
        assert!(!leaked.contains("s3cret"), "spec leaked secret: {leaked}");

        let two_basic_one_post = [
            ("basic-1", "client_secret_basic"),
            ("basic-2", "client_secret_basic"),
            ("post-1", "client_secret_post"),
        ];
        for (id, auth) in two_basic_one_post {
            let client = client_from_spec(
                id.into(),
                vec!["http://127.0.0.1:9999/cb".into()],
                Some(format!("{id}-secret")),
                Some(auth.into()),
                None,
                Some("127.0.0.1".into()),
            )
            .unwrap();
            assert_eq!(client.token_endpoint_auth_method.as_str(), auth);
        }

        assert!(
            client_from_spec(
                "smoke".into(),
                vec!["http://127.0.0.1:9999/cb".into()],
                Some("nope".into()),
                Some("none".into()),
                None,
                Some("127.0.0.1".into()),
            )
            .is_err()
        );
        assert!(
            client_from_spec(
                "basic-1".into(),
                vec!["http://127.0.0.1:9999/cb".into()],
                None,
                Some("client_secret_basic".into()),
                None,
                Some("127.0.0.1".into()),
            )
            .is_err()
        );

        let mjolnir = client_from_spec(
            "mjolnir-term".into(),
            vec!["https://api.vm.worldtree.network/auth/callback".into()],
            None,
            Some("none".into()),
            Some("public".into()),
            None,
        )
        .unwrap();
        assert_eq!(mjolnir.subject_type, SubjectType::Public);
        assert_eq!(
            mjolnir.token_endpoint_auth_method,
            TokenEndpointAuthMethod::None
        );
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn token_basic_wrong_secret_is_unauthorized(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use identikey_keys::Xid;
        use tower::ServiceExt;

        let store = KeysStore::from_pool(pool);
        let salt = PairwiseSalt::from_hex(&"ab".repeat(32)).unwrap();
        let provider = Provider::generate("http://127.0.0.1:8080", salt).unwrap();
        provider.register(
            Client::new("basic-1", "127.0.0.1")
                .with_redirect("http://127.0.0.1:9999/cb")
                .with_secret(TokenEndpointAuthMethod::ClientSecretBasic, "basic-secret"),
        );
        let pending = provider
            .validate_authorize(&AuthorizeQuery {
                response_type: Some("code".into()),
                client_id: Some("basic-1".into()),
                redirect_uri: Some("http://127.0.0.1:9999/cb".into()),
                code_challenge: Some(s256_challenge(VERIFIER)),
                code_challenge_method: Some("S256".into()),
                state: None,
                nonce: None,
                scope: Some("openid".into()),
            })
            .unwrap();
        let code = provider
            .issue_code(&pending, Xid::from_bytes([0x22; 32]))
            .unwrap();
        let app = router(
            store,
            Arc::new(provider),
            false,
            test_webauthn(),
            Arc::new(account::AccountSessions::default()),
        );
        let form = format!(
            "grant_type=authorization_code&code={code}&redirect_uri=http://127.0.0.1:9999/cb&code_verifier={VERIFIER}"
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::AUTHORIZATION, "Basic YmFzaWMtMTp3cm9uZw==")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_some());
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let err: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(err["error"], "invalid_client");
        let desc = err["error_description"].as_str().unwrap_or("");
        assert!(!desc.contains("wrong"), "must not echo the secret: {desc}");
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn challenge_is_cbor(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let response = test_router(KeysStore::from_pool(pool))
            .oneshot(
                Request::builder()
                    .uri("/challenge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/cbor"
        );
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            identikey_auth::Challenge::from_bytes(&body).is_ok(),
            "challenge body must be an identikey-auth Challenge"
        );
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn token_urn_grant_mints_and_refuses_replay(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use identikey_auth::{Challenge, Signer, SoftwareSigner};
        use identikey_keys::Xid;
        use identikey_oidc::CHALLENGE_RESPONSE_GRANT;
        use tower::ServiceExt;

        let store = KeysStore::from_pool(pool);
        let salt = PairwiseSalt::from_hex(&"ab".repeat(32)).unwrap();
        let provider = Provider::generate("http://127.0.0.1:8080", salt).unwrap();
        provider.register(
            Client::new("smoke", "127.0.0.1")
                .with_redirect("http://127.0.0.1:9999/cb")
                .with_grant(CHALLENGE_RESPONSE_GRANT),
        );
        let signer = SoftwareSigner::generate_ed25519();
        let xid = Xid::from_bytes([0x11; 32]);
        provider.register_subject(&signer.classical_public_key(), xid);
        let chal = Challenge::from_bytes(&provider.issue_challenge().unwrap()).unwrap();
        let encoded = {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            URL_SAFE_NO_PAD.encode(signer.respond(&chal).unwrap().to_bytes())
        };
        let app = router(
            store,
            Arc::new(provider),
            false,
            test_webauthn(),
            Arc::new(account::AccountSessions::default()),
        );
        let form =
            format!("grant_type={CHALLENGE_RESPONSE_GRANT}&client_id=smoke&response={encoded}");
        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let body = body::to_bytes(first.into_body(), usize::MAX).await.unwrap();
        let issued: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(issued["access_token"].as_str().unwrap().len() > 8);
        assert!(issued["id_token"].as_str().unwrap().contains('.'));

        let replay = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
        let replay_body = body::to_bytes(replay.into_body(), usize::MAX)
            .await
            .unwrap();
        let err: serde_json::Value = serde_json::from_slice(&replay_body).unwrap();
        assert_eq!(err["error"], "invalid_grant");
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn authorize_with_pkce_redirects_to_passkey(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let challenge = s256_challenge(VERIFIER);
        let response = test_router(KeysStore::from_pool(pool))
            .oneshot(
                Request::builder()
                    .uri(format!("/authorize?{}", authorize_qs(&challenge)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            location.starts_with("/authorize/passkey?"),
            "expected passkey login redirect, got {location}"
        );
        assert!(location.contains("code_challenge="));
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn passkey_login_page_is_html_product_surface(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let challenge = s256_challenge(VERIFIER);
        let response = test_router(KeysStore::from_pool(pool))
            .oneshot(
                Request::builder()
                    .uri(format!("/authorize/passkey?{}", authorize_qs(&challenge)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            content_type.starts_with("text/html"),
            "expected text/html, got {content_type}"
        );
        let body = String::from_utf8(
            body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("navigator.credentials.get"));
        assert!(!body.contains("name=\"username\""));
        assert!(body.contains("Continue with passkey"));
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn managed_challenge_signup_then_register_stores_ed25519(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use identikey_keys::{CustodyRung, Xid, is_c2, operational_ed25519_public};
        use tower::ServiceExt;

        let store = KeysStore::from_pool(pool);
        let accounts = Arc::new(account::AccountSessions::default());
        let app = test_router_with_accounts(store.clone(), accounts.clone());

        let get = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/signup")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get.status(), StatusCode::OK);
        assert!(
            get.headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        let get_body = String::from_utf8(
            body::to_bytes(get.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(get_body.contains("navigator.credentials.create"));

        let created = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/signup")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let created_json: serde_json::Value = serde_json::from_slice(
            &body::to_bytes(created.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let xid = Xid::parse(created_json["xid"].as_str().unwrap()).unwrap();
        let session = created_json["session"].as_str().unwrap().to_owned();
        assert!(created_json["publicKey"].is_object());
        assert!(store.get_account(xid).await.unwrap().is_some());
        let custody = store.get_custody(xid).await.unwrap().unwrap();
        assert_eq!(custody.rung, CustodyRung::C2);
        assert!(is_c2(&custody.document));
        assert!(operational_ed25519_public(&custody.document).is_ok());
        assert_eq!(store.has_managed_key(xid).await.unwrap(), Some(true));
        assert!(store.list_passkeys(xid).await.unwrap().is_empty());
        let _session = session;

        store
            .insert_passkey(xid, &[0xAA; 16], &[0xBB; 8], 0)
            .await
            .unwrap();
        let token = accounts.issue(xid).unwrap();
        assert!(
            account::set_cookie(&token, true)
                .to_str()
                .unwrap()
                .contains("HttpOnly")
        );

        let profile = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/account")
                    .header(header::COOKIE, format!("identikey_account={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(profile.status(), StatusCode::OK);
        let profile_html = String::from_utf8(
            body::to_bytes(profile.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(profile_html.contains(&xid.to_string()));
        assert!(!profile_html.contains(&xid.to_hex()));
        assert!(profile_html.contains("Managed (C2)"));
        assert!(profile_html.contains("<span>Passkey</span>"));
        assert!(profile_html.contains("Not backed up · Never used"));

        let signed_out = app
            .oneshot(
                Request::builder()
                    .uri("/account")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(signed_out.status(), StatusCode::UNAUTHORIZED);
        let signed_out_html = String::from_utf8(
            body::to_bytes(signed_out.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!signed_out_html.contains(&xid.to_string()));
        assert!(!signed_out_html.contains(&xid.to_hex()));
        assert!(signed_out_html.contains("/signup"));
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn register_begin_unknown_xid_creates_nothing(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use identikey_keys::Xid;
        use tower::ServiceExt;

        let missing = Xid::from_bytes([0xAB; 32]);
        let store = KeysStore::from_pool(pool);
        let app = test_router(store.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webauthn/register/begin")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"xid":"{missing}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(store.get_account(missing).await.unwrap().is_none());
        let _ = body::to_bytes(response.into_body(), usize::MAX).await;
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn register_options_match_rp_id_and_stable_user_id(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use bc_components::PrivateKeyBase;
        use identikey_keys::{CustodyRung, c2_native};
        use tower::ServiceExt;

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &[0x51, 0x47])
            .await
            .unwrap();
        let accounts = Arc::new(account::AccountSessions::default());
        let cookie = format!("identikey_account={}", accounts.issue(xid).unwrap());
        let app = test_router_with_accounts(store, accounts);
        let body = format!(r#"{{"xid":"{xid}"}}"#);
        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webauthn/register/begin")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first_json: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(first.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(first_json["publicKey"]["rp"]["id"], "auth.identikey.me");
        assert_eq!(first_json["publicKey"]["rp"]["name"], "IdentiKey");
        assert_hybrid_hint_options(&first_json["publicKey"]);
        assert_eq!(
            first_json["publicKey"]["authenticatorSelection"]["residentKey"],
            "required"
        );
        assert_eq!(
            first_json["publicKey"]["authenticatorSelection"]["requireResidentKey"],
            true
        );
        assert_eq!(
            first_json["publicKey"]["authenticatorSelection"]["userVerification"],
            "required"
        );
        let user_id = first_json["publicKey"]["user"]["id"].clone();
        assert!(!user_id.is_null());

        let second = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webauthn/register/begin")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let second_json: serde_json::Value = serde_json::from_slice(
            &body::to_bytes(second.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(second_json["publicKey"]["user"]["id"], user_id);
        assert_ne!(first_json["session"], second_json["session"]);
    }

    fn assert_hybrid_hint_options(options: &serde_json::Value) {
        assert_eq!(
            options["hints"],
            serde_json::json!(["client-device", "hybrid", "security-key"])
        );
        assert!(options.get("authenticatorAttachment").is_none());
        assert!(
            options
                .get("authenticatorSelection")
                .and_then(|selection| selection.get("authenticatorAttachment"))
                .is_none()
        );
    }

    async fn register_hybrid_hint_test_passkey(
        store: &KeysStore,
        hub: &ceremonies::CeremonyHub,
    ) -> identikey_keys::Xid {
        use bc_components::PrivateKeyBase;
        use identikey_keys::{CustodyRung, c2_native};
        use webauthn_authenticator_rs::prelude::WebauthnAuthenticator;
        use webauthn_authenticator_rs::softpasskey::SoftPasskey;
        use webauthn_rs::prelude::CreationChallengeResponse;

        let doc = c2_native(&PrivateKeyBase::new(), &PrivateKeyBase::new()).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &[0x51, 0x47])
            .await
            .unwrap();
        let (session, mut options) = hub.begin_register(store, xid).await.unwrap();
        // SoftPasskey needs the same client-side residency relaxation as the
        // registration/assertion integration test; server options stay required.
        options["authenticatorSelection"]["residentKey"] = "discouraged".into();
        options["authenticatorSelection"]["requireResidentKey"] = false.into();
        let credential = WebauthnAuthenticator::new(SoftPasskey::new(true))
            .do_registration(
                url::Url::parse("https://auth.identikey.me").unwrap(),
                CreationChallengeResponse {
                    public_key: serde_json::from_value(options).unwrap(),
                },
            )
            .unwrap();
        hub.finish_register(store, &session, xid, credential, None)
            .await
            .unwrap();
        xid
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn discoverable_assertion_hybrid_hint(pool: sqlx::PgPool) {
        let store = KeysStore::from_pool(pool);
        let hub = ceremonies::CeremonyHub::from_config(&test_webauthn());
        let (_, options) = hub.begin_assert(&store, None, None).await.unwrap();
        assert_hybrid_hint_options(&options);
        assert!(options["allowCredentials"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn device_discoverable_assertion_hybrid_hint() {
        let hub = ceremonies::CeremonyHub::from_config(&test_webauthn());
        let (_, options, _) = hub.begin_device_assert("ABCD-EFGH").await.unwrap();
        assert_hybrid_hint_options(&options);
        assert!(options["allowCredentials"].as_array().unwrap().is_empty());
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn allow_list_assertion_hybrid_hint(pool: sqlx::PgPool) {
        let store = KeysStore::from_pool(pool);
        let hub = ceremonies::CeremonyHub::from_config(&test_webauthn());
        let xid = register_hybrid_hint_test_passkey(&store, &hub).await;
        let (_, options) = hub.begin_assert(&store, Some(xid), None).await.unwrap();
        assert_hybrid_hint_options(&options);
        assert_eq!(options["allowCredentials"].as_array().unwrap().len(), 1);
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn managed_allow_list_assertion_hybrid_hint(pool: sqlx::PgPool) {
        let store = KeysStore::from_pool(pool);
        let hub = ceremonies::CeremonyHub::from_config(&test_webauthn());
        let xid = register_hybrid_hint_test_passkey(&store, &hub).await;
        let (options, _) = hub.begin_managed_assert(&store, xid).await.unwrap();
        assert_hybrid_hint_options(&options);
        assert_eq!(options["allowCredentials"].as_array().unwrap().len(), 1);
    }

    /// Account takeover regression: a public XID must not be enough to add a
    /// passkey. Without a session, or with another account's session, begin
    /// is refused and issues no ceremony.
    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn register_begin_requires_that_accounts_session(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use bc_components::PrivateKeyBase;
        use identikey_keys::{CustodyRung, c2_native};
        use tower::ServiceExt;

        let store = KeysStore::from_pool(pool);
        let mut xids = Vec::new();
        for _ in 0..2 {
            let doc = c2_native(&PrivateKeyBase::new(), &PrivateKeyBase::new()).unwrap();
            xids.push(
                store
                    .create_managed(CustodyRung::C2, &doc, &[0x51, 0x47])
                    .await
                    .unwrap(),
            );
        }
        let (victim, attacker) = (xids[0], xids[1]);
        let accounts = Arc::new(account::AccountSessions::default());
        let attacker_cookie = format!("identikey_account={}", accounts.issue(attacker).unwrap());
        let victim_cookie = format!("identikey_account={}", accounts.issue(victim).unwrap());
        let app = test_router_with_accounts(store, accounts);
        let begin = |cookie: Option<String>| {
            let mut request = Request::builder()
                .method("POST")
                .uri("/webauthn/register/begin")
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(cookie) = cookie {
                request = request.header(header::COOKIE, cookie);
            }
            request
                .body(Body::from(format!(r#"{{"xid":"{victim}"}}"#)))
                .unwrap()
        };

        for cookie in [
            None,
            Some(attacker_cookie),
            Some("identikey_account=not-a-session".to_owned()),
        ] {
            let response = app.clone().oneshot(begin(cookie)).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        let response = app.oneshot(begin(Some(victim_cookie))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Signup hands its browser the new account's session, so a cancelled
    /// prompt can be retried through register/begin without a second account.
    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn signup_session_can_retry_enrollment(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = test_router(KeysStore::from_pool(pool));
        let created = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/signup")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let cookie = created
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .unwrap()
            .to_owned();
        let json: serde_json::Value = serde_json::from_slice(
            &body::to_bytes(created.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let xid = json["xid"].as_str().unwrap();
        let retry = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webauthn/register/begin")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, cookie)
                    .body(Body::from(format!(r#"{{"xid":"{xid}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn register_finish_garbage_does_not_store(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use bc_components::PrivateKeyBase;
        use identikey_keys::{CustodyRung, c2_native};
        use tower::ServiceExt;

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &[0x51, 0x47])
            .await
            .unwrap();
        let accounts = Arc::new(account::AccountSessions::default());
        let cookie = format!("identikey_account={}", accounts.issue(xid).unwrap());
        let app = test_router_with_accounts(store.clone(), accounts);
        let begin = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webauthn/register/begin")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from(format!(r#"{{"xid":"{xid}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        let begin_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(begin.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let session = begin_json["session"].as_str().unwrap();
        let finish = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webauthn/register/finish")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"session":"{session}","xid":"{xid}","credential":{{"id":"x","rawId":"AA","type":"public-key","response":{{"clientDataJSON":"e30","attestationObject":"AA"}}}}}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(finish.status(), StatusCode::BAD_REQUEST);
        assert!(store.list_passkeys(xid).await.unwrap().is_empty());
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn assert_unknown_credential_creates_no_account(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use identikey_keys::Xid;
        use tower::ServiceExt;

        let missing = Xid::from_bytes([0xCD; 32]);
        let store = KeysStore::from_pool(pool);
        let app = test_router(store.clone());
        let begin = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webauthn/assert/begin")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(begin.status(), StatusCode::OK);
        let begin_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(begin.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let session = begin_json["session"].as_str().unwrap();
        let finish = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webauthn/assert/finish")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"session":"{session}","credential":{{"id":"nope","rawId":"AA","type":"public-key","response":{{"clientDataJSON":"e30","authenticatorData":"AA","signature":"AA"}}}}}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(finish.status(), StatusCode::BAD_REQUEST);
        assert!(store.get_account(missing).await.unwrap().is_none());
        let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(accounts, 0);
        let credentials: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM credentials")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(credentials, 0);
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn passkey_register_and_assert_issues_authorize_code(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use bc_components::PrivateKeyBase;
        use identikey_keys::{CustodyRung, c2_native};
        use identikey_oidc::AuthorizeQuery;
        use tower::ServiceExt;
        use url::Url;
        use webauthn_authenticator_rs::prelude::WebauthnAuthenticator;
        use webauthn_authenticator_rs::softpasskey::SoftPasskey;
        use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &[0x51, 0x47])
            .await
            .unwrap();
        let origin = Url::parse("https://auth.identikey.me").unwrap();
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let accounts = Arc::new(account::AccountSessions::default());
        let cookie = format!("identikey_account={}", accounts.issue(xid).unwrap());
        let app = test_router_with_accounts(store.clone(), accounts);

        let begin = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webauthn/register/begin")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from(format!(r#"{{"xid":"{xid}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(begin.status(), StatusCode::OK);
        let begin_json: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(begin.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        let session = begin_json["session"].as_str().unwrap().to_owned();
        // SoftPasskey cannot store resident keys, so it refuses our
        // residentKey=required options. Relax that on the client side only:
        // the server cannot observe residency, and it still verifies this
        // registration and the assertion below exactly as in production.
        let mut public_key = begin_json["publicKey"].clone();
        public_key["authenticatorSelection"]["residentKey"] = "discouraged".into();
        public_key["authenticatorSelection"]["requireResidentKey"] = false.into();
        let ccr = CreationChallengeResponse {
            public_key: serde_json::from_value(public_key).unwrap(),
        };
        let cred = authenticator.do_registration(origin.clone(), ccr).unwrap();
        let finish = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webauthn/register/finish")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "session": session,
                            "xid": xid.to_string(),
                            "credential": cred,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(finish.status(), StatusCode::OK);
        assert_eq!(store.list_passkeys(xid).await.unwrap().len(), 1);

        let provider = test_provider();
        let pending = provider
            .validate_authorize(&AuthorizeQuery {
                response_type: Some("code".into()),
                client_id: Some("smoke".into()),
                redirect_uri: Some("http://127.0.0.1:9999/cb".into()),
                code_challenge: Some(s256_challenge(VERIFIER)),
                code_challenge_method: Some("S256".into()),
                state: None,
                nonce: None,
                scope: Some("openid".into()),
            })
            .unwrap();
        let hub = ceremonies::CeremonyHub::from_config(&test_webauthn());
        let (session, options) = hub
            .begin_assert(&store, Some(xid), Some(pending))
            .await
            .unwrap();
        let rcr = RequestChallengeResponse {
            public_key: serde_json::from_value(options).unwrap(),
            mediation: None,
        };
        let assertion = authenticator.do_authentication(origin, rcr).unwrap();
        let finished = hub
            .finish_assert(&store, &session, assertion)
            .await
            .unwrap();
        assert_eq!(finished.xid, xid);
        assert!(finished.device.is_none());
        let pending = finished.pending.unwrap();
        let code = provider.issue_code(&pending, finished.xid).unwrap();
        assert!(!code.is_empty());
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn ssh_git_insert_refuses_elect_only(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let store = KeysStore::from_pool(pool);
        let app = test_router(store);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/devices/ssh_git")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "elect_signature": "not-an-assertion",
                            "device_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake",
                            "xid": "aa".repeat(32),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let desc = body["error_description"].as_str().unwrap_or("");
        assert!(
            desc.contains("Elect") || desc.contains("A3"),
            "unexpected description: {desc}"
        );
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn ssh_git_unknown_session_is_not_an_insert(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let store = KeysStore::from_pool(pool);
        let app = test_router(store);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/devices/ssh_git")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"session":"nope","credential":{"id":"nope","rawId":"AA","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AA","signature":"AA"}},"device_public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake"}"#.to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let _ = body::to_bytes(response.into_body(), usize::MAX).await;
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn ssh_git_http_revoke_after_a3_insert(pool: sqlx::PgPool) {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use bc_components::PrivateKeyBase;
        use identikey_keys::{
            ADD_DEVICE_ACTION, AccessLevel, ConsentAppend, ConsentResult, CustodyRung, ProofKind,
            SshGitInsert, c2_native,
        };
        use tower::ServiceExt;

        let store = KeysStore::from_pool(pool);
        let user = PrivateKeyBase::new();
        let ours = PrivateKeyBase::new();
        let doc = c2_native(&user, &ours).unwrap();
        let xid = store
            .create_managed(CustodyRung::C2, &doc, &[0x51, 0x47])
            .await
            .unwrap();
        let passkey = store
            .insert_passkey(xid, &[0xAAu8], &[0xBBu8], 0)
            .await
            .unwrap();
        let id = store
            .insert_ssh_git(SshGitInsert {
                xid,
                device_public_key: b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake",
                nickname: Some("vm-1"),
                consent: ConsentAppend {
                    xid,
                    action: ADD_DEVICE_ACTION,
                    audience: Some("mjolnir-hosted-being"),
                    purpose: Some("ssh git-signing device"),
                    access_level: AccessLevel::A3,
                    credential_id: Some(passkey),
                    proof_kind: ProofKind::WebauthnAssertion,
                    proof_bytes: b"assertion",
                    result: ConsentResult::Signed,
                },
            })
            .await
            .unwrap();
        let app = test_router(store.clone());
        let revoke = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/devices/ssh_git/revoke")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "xid": xid.to_string(),
                            "credential_id": id,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoke.status(), StatusCode::NO_CONTENT);
        assert!(
            store
                .list_devices(xid)
                .await
                .unwrap()
                .iter()
                .all(|d| d.kind != "ssh_git")
        );
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn device_grant_is_opt_in_and_the_page_does_not_use_the_cookie(pool: sqlx::PgPool) {
        use axum::body::{self, Body};
        use axum::http::{Request, StatusCode};
        use identikey_keys::Xid;
        use identikey_oidc::{GRANT_DEVICE_CODE, GRANT_REFRESH_TOKEN};
        use tower::ServiceExt;

        let provider = test_provider();
        provider.register(
            Client::new("cli", "cli.example")
                .with_subject_type(SubjectType::Public)
                .with_display_name("Mjolnir CLI")
                .with_grants([GRANT_DEVICE_CODE, GRANT_REFRESH_TOKEN]),
        );
        let app = router(
            KeysStore::from_pool(pool),
            provider.clone(),
            false,
            test_webauthn(),
            Arc::new(account::AccountSessions::default()),
        );
        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/device_authorization")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("client_id=smoke&scope=openid"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
        let denied_body = body::to_bytes(denied.into_body(), usize::MAX)
            .await
            .unwrap();
        let denied_json: serde_json::Value = serde_json::from_slice(&denied_body).unwrap();
        assert_eq!(denied_json["error"], "unauthorized_client");

        let started = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/device_authorization")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("client_id=cli&scope=openid"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::OK);
        let started_body = body::to_bytes(started.into_body(), usize::MAX)
            .await
            .unwrap();
        let started_json: serde_json::Value = serde_json::from_slice(&started_body).unwrap();
        let user_code = started_json["user_code"].as_str().unwrap().to_owned();
        let device_code = started_json["device_code"].as_str().unwrap().to_owned();
        assert!(
            started_json["verification_uri_complete"]
                .as_str()
                .unwrap()
                .contains(&user_code)
        );

        let page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/device?user_code={user_code}"))
                    .header(header::COOKIE, "identikey_account=not-a-session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        let html = String::from_utf8(
            body::to_bytes(page.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains("Sign in to Mjolnir CLI"));
        assert!(html.contains(&user_code));
        assert!(html.contains(">Approve</button>"));
        assert!(!html.contains("checkbox"));

        let pending = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "grant_type={GRANT_DEVICE_CODE}&client_id=cli&device_code={device_code}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pending.status(), StatusCode::BAD_REQUEST);
        let pending_body = body::to_bytes(pending.into_body(), usize::MAX)
            .await
            .unwrap();
        let pending_json: serde_json::Value = serde_json::from_slice(&pending_body).unwrap();
        assert_eq!(pending_json["error"], "authorization_pending");

        let authorize = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/authorize?response_type=code&client_id=cli&redirect_uri=https://evil.example/cb&code_challenge=abc&code_challenge_method=S256")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorize.status(), StatusCode::BAD_REQUEST);
        let authorize_body = body::to_bytes(authorize.into_body(), usize::MAX)
            .await
            .unwrap();
        let authorize_json: serde_json::Value = serde_json::from_slice(&authorize_body).unwrap();
        assert_eq!(authorize_json["error"], "unauthorized_client");

        let redeem = provider
            .start_device(
                &TokenRequest {
                    client_id: Some("cli".into()),
                    ..TokenRequest::default()
                },
                None,
            )
            .unwrap();
        provider
            .bind_device_assertion(&redeem.user_code, b"challenge")
            .unwrap();
        provider
            .approve_device(&redeem.user_code, Xid::from_bytes([9; 32]), b"challenge")
            .unwrap();
        let minted = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "grant_type={GRANT_DEVICE_CODE}&client_id=cli&device_code={}",
                        redeem.device_code
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(minted.status(), StatusCode::OK);
        let minted_body = body::to_bytes(minted.into_body(), usize::MAX)
            .await
            .unwrap();
        let minted_json: serde_json::Value = serde_json::from_slice(&minted_body).unwrap();
        assert_eq!(minted_json["expires_in"], 3600);
        assert!(minted_json["id_token"].as_str().unwrap().contains('.'));
    }

    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
}
