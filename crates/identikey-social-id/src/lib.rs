//! Verify Apple and Google identity tokens. A verified identity is not an
//! authorization grant. Keep a verifier alive to reuse its per-provider caches.
//!
//! The caller supplies the expected audience and current Unix time explicitly.
//! Only RS256 is accepted; issuer matching is exact and expiry allows five
//! seconds of clock skew. No discovery or token-controlled key URLs are used.

use std::{future::Future, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{
    JsonWebKey,
    core::{CoreJsonWebKey, CoreJsonWebKeySet, CoreJwsSigningAlgorithm},
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

const CLOCK_SKEW_SECONDS: i64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Apple,
    Google,
}

impl Provider {
    pub fn jwks_url(self) -> &'static str {
        match self {
            Self::Apple => "https://appleid.apple.com/auth/keys",
            Self::Google => "https://www.googleapis.com/oauth2/v3/certs",
        }
    }

    fn accepts_issuer(self, issuer: &str) -> bool {
        match self {
            Self::Apple => issuer == "https://appleid.apple.com",
            Self::Google => matches!(
                issuer,
                "https://accounts.google.com" | "accounts.google.com"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppleIdentity {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_private_email: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoogleIdentity {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocialIdentity {
    Apple(AppleIdentity),
    Google(GoogleIdentity),
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("malformed identity token: {0}")]
    Malformed(String),
    #[error("only RS256 identity tokens are supported")]
    UnsupportedAlgorithm,
    #[error("token has no nonempty kid")]
    MissingKeyId,
    #[error("no unique signing key for token kid")]
    NoKey,
    #[error("JWKS fetch failed: {0}")]
    Jwks(String),
    #[error("invalid token signature or incompatible signing key")]
    BadSignature,
    #[error("token issuer mismatch")]
    BadIssuer,
    #[error("a nonempty matching audience is required")]
    BadAudience,
    #[error("token expired")]
    Expired,
    #[error("token is not yet valid")]
    NotYetValid,
    #[error("token subject is empty")]
    NoSubject,
}

type Result<T> = std::result::Result<T, VerifyError>;

/// Trusted JWKS transport. Implementations must fetch only the chosen provider's
/// keys; this hook also permits deterministic, entirely offline tests.
pub trait JwksSource: Send + Sync {
    fn fetch(&self, provider: Provider) -> impl Future<Output = Result<CoreJsonWebKeySet>> + Send;
}

pub struct HttpJwksSource {
    client: reqwest::Client,
}

impl HttpJwksSource {
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| VerifyError::Jwks(e.to_string()))?;
        Ok(Self { client })
    }
}

impl JwksSource for HttpJwksSource {
    async fn fetch(&self, provider: Provider) -> Result<CoreJsonWebKeySet> {
        self.client
            .get(provider.jwks_url())
            .send()
            .await
            .map_err(|e| VerifyError::Jwks(e.to_string()))?
            .error_for_status()
            .map_err(|e| VerifyError::Jwks(e.to_string()))?
            .json()
            .await
            .map_err(|e| VerifyError::Jwks(e.to_string()))
    }
}

/// Separate Apple and Google caches. A cache miss refreshes only that provider
/// once per verification; a known kid never triggers a fetch, even if its
/// signature is invalid. Concurrent requests recheck after acquiring the lock.
pub struct SocialIdVerifier<S = HttpJwksSource> {
    source: S,
    apple: RwLock<CoreJsonWebKeySet>,
    google: RwLock<CoreJsonWebKeySet>,
}

impl SocialIdVerifier<HttpJwksSource> {
    pub fn new() -> Result<Self> {
        Ok(Self::with_source(HttpJwksSource::new()?))
    }
}

impl<S: JwksSource> SocialIdVerifier<S> {
    pub fn with_source(source: S) -> Self {
        Self::with_cached_jwks(
            source,
            CoreJsonWebKeySet::default(),
            CoreJsonWebKeySet::default(),
        )
    }

    /// Seed each cache with trusted JWKS. Unknown kids still use `source` once.
    pub fn with_cached_jwks(
        source: S,
        apple: CoreJsonWebKeySet,
        google: CoreJsonWebKeySet,
    ) -> Self {
        Self {
            source,
            apple: RwLock::new(apple),
            google: RwLock::new(google),
        }
    }

    pub async fn verify(
        &self,
        provider: Provider,
        token: &str,
        audience: &str,
        now_unix: i64,
    ) -> Result<SocialIdentity> {
        if audience.is_empty() {
            return Err(VerifyError::BadAudience);
        }
        let (signed, signature) = token
            .rsplit_once('.')
            .ok_or_else(|| malformed("missing signature"))?;
        let (header, payload) = signed
            .split_once('.')
            .ok_or_else(|| malformed("missing payload"))?;
        let header: Header =
            serde_json::from_slice(&decode(header)?).map_err(|e| malformed(e.to_string()))?;
        if header.alg != "RS256" {
            return Err(VerifyError::UnsupportedAlgorithm);
        }
        // No extensions (including unencoded JWS payloads) are implemented.
        if !header.crit.is_empty() || header.b64 == Some(false) {
            return Err(malformed(
                "unsupported critical header or unencoded payload",
            ));
        }
        let kid = header
            .kid
            .filter(|kid| !kid.is_empty())
            .ok_or(VerifyError::MissingKeyId)?;
        let signature = decode(signature)?;
        let key = self.key(provider, &kid).await?;
        key.verify_signature(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            signed.as_bytes(),
            &signature,
        )
        .map_err(|_| VerifyError::BadSignature)?;

        // Parse claims only after authenticating the exact compact JWS bytes.
        // Explicit strings also support Google's issuer without a URL scheme.
        let claims: Claims =
            serde_json::from_slice(&decode(payload)?).map_err(|e| malformed(e.to_string()))?;
        if !provider.accepts_issuer(&claims.iss) {
            return Err(VerifyError::BadIssuer);
        }
        if !claims.aud.contains(audience) {
            return Err(VerifyError::BadAudience);
        }
        if now_unix.saturating_sub(CLOCK_SKEW_SECONDS) >= claims.exp {
            return Err(VerifyError::Expired);
        }
        if claims
            .nbf
            .is_some_and(|nbf| nbf > now_unix.saturating_add(CLOCK_SKEW_SECONDS))
        {
            return Err(VerifyError::NotYetValid);
        }
        if claims.sub.is_empty() {
            return Err(VerifyError::NoSubject);
        }
        Ok(match provider {
            Provider::Apple => SocialIdentity::Apple(AppleIdentity {
                sub: claims.sub,
                email: claims.email,
                email_verified: claims.email_verified.map(BooleanClaim::value),
                is_private_email: claims.is_private_email.map(BooleanClaim::value),
            }),
            Provider::Google => SocialIdentity::Google(GoogleIdentity {
                sub: claims.sub,
                email: claims.email,
                email_verified: claims.email_verified.map(BooleanClaim::value),
                name: claims.name,
                picture: claims.picture,
            }),
        })
    }

    async fn key(&self, provider: Provider, kid: &str) -> Result<CoreJsonWebKey> {
        let cache = match provider {
            Provider::Apple => &self.apple,
            Provider::Google => &self.google,
        };
        {
            let keys = cache.read().await;
            if has_kid(&keys, kid) {
                return unique_key(&keys, kid);
            }
        }
        let mut keys = cache.write().await;
        if !has_kid(&keys, kid) {
            *keys = self.source.fetch(provider).await?;
        }
        unique_key(&keys, kid)
    }
}

fn has_kid(keys: &CoreJsonWebKeySet, kid: &str) -> bool {
    keys.keys()
        .iter()
        .any(|key| key.key_id().is_some_and(|id| id.as_str() == kid))
}

fn unique_key(keys: &CoreJsonWebKeySet, kid: &str) -> Result<CoreJsonWebKey> {
    let mut matches = keys
        .keys()
        .iter()
        .filter(|key| key.key_id().is_some_and(|id| id.as_str() == kid));
    let key = matches.next().ok_or(VerifyError::NoKey)?;
    if matches.next().is_some() {
        return Err(VerifyError::NoKey);
    }
    Ok(key.clone())
}

fn malformed(message: impl Into<String>) -> VerifyError {
    VerifyError::Malformed(message.into())
}
fn decode(encoded: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| malformed(e.to_string()))
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
    #[serde(default)]
    crit: Vec<String>,
    b64: Option<bool>,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: Audience,
    exp: i64,
    sub: String,
    nbf: Option<i64>,
    email: Option<String>,
    email_verified: Option<BooleanClaim>,
    is_private_email: Option<BooleanClaim>,
    name: Option<String>,
    picture: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(aud) => aud == expected,
            Self::Many(aud) => aud.iter().any(|aud| aud == expected),
        }
    }
}

// Apple has emitted both JSON booleans and the strings "true"/"false".
// A closed enum rejects arbitrary strings instead of treating them as truthy.
#[derive(Deserialize)]
#[serde(untagged)]
enum BooleanClaim {
    Boolean(bool),
    String(BooleanString),
}
#[derive(Deserialize)]
enum BooleanString {
    #[serde(rename = "true")]
    True,
    #[serde(rename = "false")]
    False,
}
impl BooleanClaim {
    fn value(self) -> bool {
        match self {
            Self::Boolean(value) => value,
            Self::String(BooleanString::True) => true,
            Self::String(BooleanString::False) => false,
        }
    }
}
