//! Relying-party client for an identikey-core OpenID Provider (or any
//! OIDC issuer that signs ID tokens with EdDSA and publishes JWKS).
//!
//! This crate is **not** the OP. It never mints tokens, never holds a
//! user key, and does not depend on `identikey-oidc`. A homeserver
//! (Conduit) validates a JWT here, then mints its *own* agency token.
//! The OP JWT is identity, not a grant.
//!
//! What it gives an RP:
//! 1. Discover `{issuer}/.well-known/openid-configuration` → `jwks_uri`
//! 2. Cache the JWKS
//! 3. Verify EdDSA signature, `iss`, `aud`, `exp`
//! 4. Return opaque `sub` (identikey-core: a XID or pairwise subject)

use std::time::{SystemTime, UNIX_EPOCH};

use josekit::jwk::{Jwk, JwkSet};
use josekit::jws::EdDSA;
use josekit::jwt::{self, JwtPayload};
use serde::Deserialize;
use tokio::sync::RwLock;

/// Verified identity from an OP JWT. Not a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcIdentity {
    pub issuer: String,
    pub subject: String,
}

#[derive(Debug, thiserror::Error)]
pub enum OidcClientError {
    #[error("oidc discovery failed: {0}")]
    Discovery(String),
    #[error("jwks fetch failed: {0}")]
    Jwks(String),
    #[error("token is not a JWT: {0}")]
    Malformed(String),
    #[error("token signature did not verify")]
    BadSignature,
    #[error("token issuer mismatch")]
    BadIssuer,
    #[error("token audience mismatch")]
    BadAudience,
    #[error("token is expired")]
    Expired,
    #[error("token has no subject")]
    NoSubject,
    #[error("no signing key for this token")]
    NoKey,
}

type Result<T> = std::result::Result<T, OidcClientError>;

#[derive(Debug, Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

/// RP client. Construct via [`OidcClient::discover`] (live OP) or
/// [`OidcClient::from_jwks`] (tests / pinned keys).
pub struct OidcClient {
    issuer: String,
    audience: String,
    jwks_uri: String,
    jwks: RwLock<JwkSet>,
    http: reqwest::Client,
}

impl OidcClient {
    /// Fetch discovery + JWKS from `issuer`. `audience` is this RP
    /// (Conduit: the Matrix server name).
    pub async fn discover(
        issuer: &str,
        audience: &str,
        http: reqwest::Client,
    ) -> Result<Self> {
        let issuer = issuer.trim_end_matches('/').to_owned();
        let url = format!("{issuer}/.well-known/openid-configuration");
        let disco: Discovery = http
            .get(&url)
            .send()
            .await
            .map_err(|e| OidcClientError::Discovery(e.to_string()))?
            .error_for_status()
            .map_err(|e| OidcClientError::Discovery(e.to_string()))?
            .json()
            .await
            .map_err(|e| OidcClientError::Discovery(e.to_string()))?;
        if disco.issuer.trim_end_matches('/') != issuer {
            return Err(OidcClientError::Discovery(format!(
                "discovery issuer {} != {issuer}",
                disco.issuer
            )));
        }
        let jwks = fetch_jwks(&http, &disco.jwks_uri).await?;
        Ok(Self {
            issuer,
            audience: audience.to_owned(),
            jwks_uri: disco.jwks_uri,
            jwks: RwLock::new(jwks),
            http,
        })
    }

    /// Test / offline constructor: no HTTP, keys supplied.
    pub fn from_jwks(issuer: &str, audience: &str, jwks: JwkSet) -> Self {
        Self {
            issuer: issuer.trim_end_matches('/').to_owned(),
            audience: audience.to_owned(),
            jwks_uri: String::new(),
            jwks: RwLock::new(jwks),
            http: reqwest::Client::new(),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Verify an ID/access token and return `iss` + `sub`.
    pub async fn validate(&self, token: &str, now_unix: u64) -> Result<OidcIdentity> {
        let header = jwt::decode_header(token)
            .map_err(|e| OidcClientError::Malformed(e.to_string()))?;
        let kid = header.claim("kid").and_then(|v| v.as_str()).map(str::to_owned);

        let jwk = self.lookup_jwk(kid.as_deref()).await?;
        let verifier = EdDSA
            .verifier_from_jwk(&jwk)
            .map_err(|_| OidcClientError::BadSignature)?;
        let (payload, _header) = jwt::decode_with_verifier(token, &verifier)
            .map_err(|_| OidcClientError::BadSignature)?;

        self.check_claims(&payload, now_unix)?;
        let subject = payload
            .subject()
            .ok_or(OidcClientError::NoSubject)?
            .to_owned();
        Ok(OidcIdentity {
            issuer: self.issuer.clone(),
            subject,
        })
    }

    async fn lookup_jwk(&self, kid: Option<&str>) -> Result<Jwk> {
        if let Some(jwk) = find_jwk(&*self.jwks.read().await, kid) {
            return Ok(jwk);
        }
        if !self.jwks_uri.is_empty() {
            let fresh = fetch_jwks(&self.http, &self.jwks_uri).await?;
            let found = find_jwk(&fresh, kid);
            *self.jwks.write().await = fresh;
            if let Some(jwk) = found {
                return Ok(jwk);
            }
        }
        Err(OidcClientError::NoKey)
    }

    fn check_claims(&self, payload: &JwtPayload, now_unix: u64) -> Result<()> {
        let iss = payload.issuer().unwrap_or("");
        if iss.trim_end_matches('/') != self.issuer {
            return Err(OidcClientError::BadIssuer);
        }
        let aud_ok = payload.audience().map(|list| {
            list.iter()
                .any(|a| a == &self.audience)
        }).unwrap_or(false);
        if !aud_ok {
            return Err(OidcClientError::BadAudience);
        }
        if let Some(exp) = payload.expires_at() {
            let exp_unix = exp.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            if now_unix >= exp_unix {
                return Err(OidcClientError::Expired);
            }
        }
        Ok(())
    }
}

fn find_jwk(set: &JwkSet, kid: Option<&str>) -> Option<Jwk> {
    let keys: Vec<Jwk> = set.keys().iter().cloned().cloned().collect();
    if let Some(kid) = kid {
        return keys.into_iter().find(|k| k.key_id() == Some(kid));
    }
    keys.into_iter().next()
}

async fn fetch_jwks(http: &reqwest::Client, uri: &str) -> Result<JwkSet> {
    let bytes = http
        .get(uri)
        .send()
        .await
        .map_err(|e| OidcClientError::Jwks(e.to_string()))?
        .error_for_status()
        .map_err(|e| OidcClientError::Jwks(e.to_string()))?
        .bytes()
        .await
        .map_err(|e| OidcClientError::Jwks(e.to_string()))?;
    JwkSet::from_bytes(&bytes).map_err(|e| OidcClientError::Jwks(e.to_string()))
}

/// Unix seconds. Hosts that already have a clock should pass it in.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use josekit::jwk::alg::ed::EdCurve;
    use josekit::jws::{EdDSA, JwsHeader};
    use josekit::jwt::JwtPayload;
    use std::time::{Duration, SystemTime};

    fn keypair() -> impl josekit::jwk::KeyPair {
        let mut pair = EdDSA.generate_key_pair(EdCurve::Ed25519).unwrap();
        pair.set_key_id(Some("test-kid".to_string()));
        pair.set_algorithm(Some("EdDSA"));
        pair
    }

    fn mint(pair: &impl josekit::jwk::KeyPair, iss: &str, aud: &str, sub: &str, exp_secs: i64) -> String {
        let mut header = JwsHeader::new();
        header.set_algorithm("EdDSA");
        header.set_key_id("test-kid");
        let mut payload = JwtPayload::new();
        payload.set_issuer(iss);
        payload.set_subject(sub);
        payload.set_audience(vec![aud]);
        let exp = SystemTime::now() + Duration::from_secs(exp_secs.max(0) as u64);
        if exp_secs >= 0 {
            payload.set_expires_at(&exp);
        } else {
            payload.set_expires_at(&(SystemTime::now() - Duration::from_secs(60)));
        }
        let jwk = pair.to_jwk_key_pair();
        let signer = EdDSA.signer_from_jwk(&jwk).unwrap();
        jwt::encode_with_signer(&payload, &header, &signer).unwrap()
    }

    fn client_for(pair: &impl josekit::jwk::KeyPair) -> OidcClient {
        let mut set = JwkSet::new();
        set.push_key(pair.to_jwk_public_key());
        OidcClient::from_jwks("https://idp.example", "conduit.example", set)
    }

    #[tokio::test]
    async fn valid_token_yields_sub() {
        let pair = keypair();
        let client = client_for(&pair);
        let token = mint(&pair, "https://idp.example", "conduit.example", "xid-alice", 300);
        let id = client.validate(&token, now_unix()).await.unwrap();
        assert_eq!(id.subject, "xid-alice");
        assert_eq!(id.issuer, "https://idp.example");
    }

    #[tokio::test]
    async fn wrong_audience_fails() {
        let pair = keypair();
        let client = client_for(&pair);
        let token = mint(&pair, "https://idp.example", "other-rp", "xid-alice", 300);
        let err = client.validate(&token, now_unix()).await.unwrap_err();
        assert!(matches!(err, OidcClientError::BadAudience));
    }

    #[tokio::test]
    async fn expired_fails() {
        let pair = keypair();
        let client = client_for(&pair);
        let token = mint(&pair, "https://idp.example", "conduit.example", "xid-alice", -1);
        let err = client.validate(&token, now_unix()).await.unwrap_err();
        assert!(matches!(err, OidcClientError::Expired));
    }

    #[tokio::test]
    async fn wrong_issuer_fails() {
        let pair = keypair();
        let client = client_for(&pair);
        let token = mint(&pair, "https://evil.example", "conduit.example", "xid-alice", 300);
        let err = client.validate(&token, now_unix()).await.unwrap_err();
        assert!(matches!(err, OidcClientError::BadIssuer));
    }
}
