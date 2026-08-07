//! The IdentiKey Core server binary.
//!
//! Wires `identikey-oidc`, `identikey-keys` and `identikey-recovery` together
//! behind axum, and serves the SvelteKit build output.
//!
//! Right now it serves `/health` and nothing else. That is deliberate: the
//! scaffold proves the dependency graph compiles and links before any behaviour
//! is written, rather than shipping stubs that look like features.
//!
//! Not yet wired, each blocking on its own issue:
//!
//! - Configuration, including the strict WebAuthn origin allowlist that must
//!   fail closed at boot (`identikey-core-62j`). Failing at startup is much
//!   cheaper than discovering a permissive origin in production.
//! - The Postgres pool (`identikey-core-zan.1`).
//! - `/.well-known/webauthn`, required on the *first* deploy of
//!   `auth.identikey.me` (`identikey-core-2js`).
//! - The OIDC endpoints (`identikey-core-ccf.4`) and the URN grant
//!   (`identikey-core-ccf.5`).
//! - Static asset serving for `web/`.

use std::net::SocketAddr;

use axum::{Router, routing::get};
use tokio::net::TcpListener;
use tokio::signal;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Liveness only. This must not grow into a readiness check that reports on the
/// database or key material — a health endpoint that leaks internal state is a
/// reconnaissance surface on an auth server.
async fn health() -> &'static str {
    "ok"
}

fn router() -> Router {
    Router::new().route("/health", get(health))
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

    let addr = bind_addr()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "identikey-server listening");

    axum::serve(listener, router())
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
}
