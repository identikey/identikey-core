//! The IdentiKey Core server binary.
//!
//! Wires `identikey-oidc`, `identikey-keys` and `identikey-recovery` together
//! behind axum, and serves the SvelteKit build output.
//!
//! Serves `/health` (liveness only), the convenience XID resolver
//! (`GET /.well-known/xid/{xid}`), and the OIDC code+PKCE surface
//! (`add-oidc-endpoints`). Login at `/authorize` is `add-dev-authorize`.
//!
//! Not yet wired, each blocking on its own issue:
//!
//! - Configuration, including the strict WebAuthn origin allowlist that must
//!   fail closed at boot (`identikey-core-62j`). Failing at startup is much
//!   cheaper than discovering a permissive origin in production.
//! - WebAuthn RP ID / origin allowlist (`identikey-core-62j`).
//! - `/.well-known/webauthn`, required on the *first* deploy of
//!   `auth.identikey.me` (`identikey-core-2js`).
//! - The URN grant (`identikey-core-ccf.5`).
//! - Static asset serving for `web/`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use identikey_keys::{KeysStore, Xid};
use identikey_oidc::{
    AuthorizeError, AuthorizeQuery, Client, OidcError, PairwiseSalt, Provider, SigningKey,
    TokenRequest,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::signal;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
struct AppState {
    store: KeysStore,
    provider: Arc<Provider>,
}

/// Liveness only. This must not grow into a readiness check that reports on the
/// database or key material — a health endpoint that leaks internal state is a
/// reconnaissance surface on an auth server.
async fn health() -> &'static str {
    "ok"
}

fn router(store: KeysStore, provider: Arc<Provider>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/.well-known/xid/{xid}", get(xid_document))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo).post(userinfo))
        .route("/introspect", post(introspect))
        .route("/revoke", post(revoke))
        .with_state(AppState { store, provider })
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
struct TokenForm {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
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
) -> Response {
    let query = AuthorizeQuery {
        response_type: params.response_type,
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
        state: params.state,
        nonce: params.nonce,
        scope: params.scope,
    };
    match state.provider.validate_authorize(&query) {
        Ok(_) => {
            // Login finish is add-dev-authorize. Valid request, no code.
            (StatusCode::UNAUTHORIZED, "authentication required").into_response()
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

async fn token(State(state): State<AppState>, Form(form): Form<TokenForm>) -> Response {
    let req = TokenRequest {
        grant_type: form.grant_type,
        code: form.code,
        redirect_uri: form.redirect_uri,
        client_id: form.client_id,
        code_verifier: form.code_verifier,
    };
    match state.provider.token(&req) {
        Ok(issued) => Json(issued).into_response(),
        Err(err) => token_error(err),
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

fn token_error(err: OidcError) -> Response {
    let status = if err.error == "invalid_client" {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::BAD_REQUEST
    };
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

fn optional_client() -> Option<Client> {
    let id = std::env::var("IDENTIKEY_CLIENT_ID").ok()?;
    let redirect = std::env::var("IDENTIKEY_CLIENT_REDIRECT").ok()?;
    if id.is_empty() || redirect.is_empty() {
        return None;
    }
    let sector = url::Url::parse(&redirect)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| "default".into());
    Some(Client::new(id, sector).with_redirect(redirect))
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
    if let Some(client) = optional_client() {
        tracing::info!(client_id = %client.id, "registered OIDC client");
        provider.register(client);
    }

    let addr = bind_addr()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "identikey-server listening");

    axum::serve(listener, router(store, Arc::new(provider)))
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

    fn test_router(store: KeysStore) -> Router {
        router(store, test_provider())
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
        let app = router(store, provider);
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

    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
}
