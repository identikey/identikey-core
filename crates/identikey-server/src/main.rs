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
//! `add-dev-authorize`. WebAuthn RP ID / origin allowlist fails closed
//! at boot (`identikey-core-62j`).
//!
//! Not yet wired, each blocking on its own issue:
//!
//! - The URN grant (`identikey-core-ccf.5`).
//! - Static asset serving for `web/`.

mod webauthn;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Form, OriginalUri, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use identikey_keys::{KeysStore, Xid};
use identikey_oidc::{
    AuthorizeError, AuthorizeQuery, Client, OidcError, PairwiseSalt, Provider, SigningKey,
    TokenEndpointAuthMethod, TokenRequest, parse_http_basic,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::signal;
use webauthn::{WebAuthnConfig, parse_webauthn_config};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
struct AppState {
    store: KeysStore,
    provider: Arc<Provider>,
    dev_login: bool,
    webauthn: WebAuthnConfig,
}

/// Liveness only. This must not grow into a readiness check that reports on the
/// database or key material — a health endpoint that leaks internal state is a
/// reconnaissance surface on an auth server.
async fn health() -> &'static str {
    "ok"
}

fn router(
    store: KeysStore,
    provider: Arc<Provider>,
    dev_login: bool,
    webauthn: WebAuthnConfig,
) -> Router {
    let mut routes = Router::new()
        .route("/health", get(health))
        .route("/.well-known/xid/{xid}", get(xid_document))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/.well-known/webauthn", get(well_known_webauthn))
        .route("/authorize", get(authorize))
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
    }
    routes.with_state(AppState {
        store,
        provider,
        dev_login,
        webauthn,
    })
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
    Path(hex): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(xid) = Xid::from_hex(&hex) else {
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
}

#[derive(Debug, Deserialize)]
struct TokenBody {
    token: Option<String>,
}

async fn discovery(State(state): State<AppState>) -> Response {
    Json(state.provider.discovery()).into_response()
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
        Ok(_) if state.dev_login => {
            let suffix = uri.query().unwrap_or("");
            let location = format!("/authorize/dev?{suffix}");
            match HeaderValue::from_str(&location) {
                Ok(value) => (StatusCode::FOUND, [(header::LOCATION, value)]).into_response(),
                Err(_) => oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "could not redirect to the login form",
                ),
            }
        }
        Ok(_) => (StatusCode::UNAUTHORIZED, "authentication required").into_response(),
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

fn html_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

fn hidden(name: &str, value: Option<&str>) -> String {
    let Some(value) = value.filter(|s| !s.is_empty()) else {
        return String::new();
    };
    format!(
        "<input type=\"hidden\" name=\"{name}\" value=\"{}\" />\n",
        html_escape(value)
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
    let Some(hex) = params.xid.as_deref().filter(|s| !s.is_empty()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "xid is required",
        );
    };
    let Ok(xid) = Xid::from_hex(hex) else {
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
    };
    match state.provider.token(&req) {
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
    Json(state.provider.introspect(&token)).into_response()
}

async fn revoke(State(state): State<AppState>, Form(body): Form<TokenBody>) -> Response {
    let token = body.token.unwrap_or_default();
    let _ = state.provider.revoke(&token);
    StatusCode::OK.into_response()
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
}

fn token_error(err: OidcError, used_basic: bool) -> Response {
    let status = if err.error == "invalid_client" {
        StatusCode::UNAUTHORIZED
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

#[derive(Debug, Deserialize)]
struct ClientJson {
    id: String,
    redirect: String,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    auth: Option<String>,
}

fn sector_from_redirect(redirect: &str) -> String {
    url::Url::parse(redirect)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| "default".into())
}

fn client_from_spec(
    id: String,
    redirect: String,
    secret: Option<String>,
    auth: Option<String>,
) -> Result<Client, BoxError> {
    if id.is_empty() || redirect.is_empty() {
        return Err("OIDC client id and redirect are required".into());
    }
    let method = match (auth.as_deref(), secret.as_deref()) {
        (Some(raw), _) => TokenEndpointAuthMethod::parse(raw).map_err(|e| e.to_string())?,
        (None, Some(s)) if !s.is_empty() => TokenEndpointAuthMethod::ClientSecretBasic,
        (None, _) => TokenEndpointAuthMethod::None,
    };
    let sector = sector_from_redirect(&redirect);
    let client = Client::new(id, sector).with_redirect(redirect);
    match (method, secret.as_deref().filter(|s| !s.is_empty())) {
        (TokenEndpointAuthMethod::None, Some(_)) => {
            Err("public client (token_endpoint_auth_method=none) must not have a secret".into())
        }
        (TokenEndpointAuthMethod::None, None) => Ok(client),
        (confidential, Some(secret)) => Ok(client.with_secret(confidential, secret)),
        (confidential, None) => Err(format!(
            "confidential client {} requires a secret",
            confidential.as_str()
        )
        .into()),
    }
}

fn optional_client() -> Result<Option<Client>, BoxError> {
    let id = match std::env::var("IDENTIKEY_CLIENT_ID") {
        Ok(id) if !id.is_empty() => id,
        _ => return Ok(None),
    };
    let redirect = std::env::var("IDENTIKEY_CLIENT_REDIRECT").unwrap_or_default();
    let secret = std::env::var("IDENTIKEY_CLIENT_SECRET").ok();
    let auth = std::env::var("IDENTIKEY_CLIENT_AUTH_METHOD").ok();
    Ok(Some(client_from_spec(id, redirect, secret, auth)?))
}

fn extra_clients() -> Result<Vec<Client>, BoxError> {
    let raw = match std::env::var("IDENTIKEY_CLIENTS") {
        Ok(raw) if !raw.is_empty() => raw,
        _ => return Ok(Vec::new()),
    };
    let specs: Vec<ClientJson> = serde_json::from_str(&raw)
        .map_err(|e| format!("IDENTIKEY_CLIENTS is not valid JSON: {e}"))?;
    specs
        .into_iter()
        .map(|spec| client_from_spec(spec.id, spec.redirect, spec.secret, spec.auth))
        .collect()
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

async fn shutdown_signal() {
    if let Err(e) = signal::ctrl_c().await {
        tracing::error!(error = %e, "failed to install ctrl-c handler; shutting down");
    }
    tracing::info!("shutdown signal received");
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
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

    let url = database_url(std::env::var("DATABASE_URL").ok())?;
    let store = KeysStore::connect(&url).await?;
    store.migrate().await?;
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
    let provider = Provider::new(issuer, signing, salt);
    if let Some(client) = optional_client()? {
        tracing::info!(
            client_id = %client.id,
            auth = client.token_endpoint_auth_method.as_str(),
            "registered OIDC client"
        );
        provider.register(client);
    }
    for client in extra_clients()? {
        tracing::info!(
            client_id = %client.id,
            auth = client.token_endpoint_auth_method.as_str(),
            "registered OIDC client"
        );
        provider.register(client);
    }

    let addr = bind_addr()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "identikey-server listening");

    let dev_login = std::env::var("IDENTIKEY_DEV_LOGIN").ok().as_deref() == Some("1");
    axum::serve(
        listener,
        router(store, Arc::new(provider), dev_login, webauthn),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;
    use identikey_oidc::s256_challenge;

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
        router(store, test_provider(), false, test_webauthn())
    }

    fn test_router_dev(store: KeysStore, provider: Arc<Provider>) -> Router {
        router(store, provider, true, test_webauthn())
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

        let missing = test_router(store)
            .oneshot(
                Request::builder()
                    .uri("/.well-known/xid/dead")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
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
        let app = router(store, provider, false, test_webauthn());
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
            "http://127.0.0.1:9999/cb".into(),
            Some("s3cret".into()),
            Some("client_secret_basic".into()),
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
                "http://127.0.0.1:9999/cb".into(),
                Some(format!("{id}-secret")),
                Some(auth.into()),
            )
            .unwrap();
            assert_eq!(client.token_endpoint_auth_method.as_str(), auth);
        }

        assert!(
            client_from_spec(
                "smoke".into(),
                "http://127.0.0.1:9999/cb".into(),
                Some("nope".into()),
                Some("none".into()),
            )
            .is_err()
        );
        assert!(
            client_from_spec(
                "basic-1".into(),
                "http://127.0.0.1:9999/cb".into(),
                None,
                Some("client_secret_basic".into()),
            )
            .is_err()
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
        let app = router(store, Arc::new(provider), false, test_webauthn());
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

    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
}
