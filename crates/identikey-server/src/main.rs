//! The IdentiKey Core server binary.
//!
//! Wires `identikey-oidc`, `identikey-keys` and `identikey-recovery` together
//! behind axum, and serves the SvelteKit build output.
//!
//! Serves `/health` (liveness only) and the convenience XID resolver
//! (`GET /.well-known/xid/{xid}`). Other surfaces are still unwired:
//!
//! Not yet wired, each blocking on its own issue:
//!
//! - Configuration, including the strict WebAuthn origin allowlist that must
//!   fail closed at boot (`identikey-core-62j`). Failing at startup is much
//!   cheaper than discovering a permissive origin in production.
//! - WebAuthn RP ID / origin allowlist (`identikey-core-62j`).
//! - `/.well-known/webauthn`, required on the *first* deploy of
//!   `auth.identikey.me` (`identikey-core-2js`).
//! - The OIDC endpoints (`identikey-core-ccf.4`) and the URN grant
//!   (`identikey-core-ccf.5`).
//! - Static asset serving for `web/`.

use std::net::SocketAddr;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};
use identikey_keys::{KeysStore, Xid};
use identikey_oidc::PairwiseSalt;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::signal;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Liveness only. This must not grow into a readiness check that reports on the
/// database or key material — a health endpoint that leaks internal state is a
/// reconnaissance surface on an auth server.
async fn health() -> &'static str {
    "ok"
}

fn router(store: KeysStore) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/.well-known/xid/{xid}", get(xid_document))
        .with_state(store)
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
    State(store): State<KeysStore>,
    Path(hex): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(xid) = Xid::from_hex(&hex) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let published = match store.published_document(xid).await {
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
    // Load only. Never log the value — Debug redacts, and we do not print hex.
    let _salt = PairwiseSalt::load(
        std::env::var("IDENTIKEY_PAIRWISE_SALT").ok().as_deref(),
        std::path::Path::new(&data_dir),
    )?;
    tracing::info!("pairwise salt ready");

    let addr = bind_addr()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "identikey-server listening");

    axum::serve(listener, router(store))
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;

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

        let response = router(store.clone())
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

        let not_modified = router(store.clone())
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

        let missing = router(store)
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

        let first = router(store.clone())
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

        let second = router(store)
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
}
