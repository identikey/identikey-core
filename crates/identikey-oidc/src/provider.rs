//! In-memory authorization-code provider.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use identikey_keys::Xid;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::discovery::DiscoveryDocument;
use crate::error::{AuthorizeError, OidcError};
use crate::salt::PairwiseSalt;
use crate::signing::SigningKey;
use crate::subject::{Client, TokenEndpointAuthMethod, hash_client_secret, subject};

const CODE_TTL: Duration = Duration::from_secs(600);
const ACCESS_TTL: Duration = Duration::from_secs(3600);
const ACCESS_TTL_SECS: u64 = 3600;

/// Validated `/authorize` request. Completing login (`issue_code`) is
/// `add-dev-authorize`; this change only validates and can mint a code
/// when a caller already knows the XID (tests, later the flag-gated login).
#[derive(Debug, Clone)]
pub struct PendingAuthorization {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub scope: String,
}

#[derive(Debug, Clone)]
pub struct AuthorizeQuery {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub scope: Option<String>,
}

#[derive(Clone, Default)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub basic_client_id: Option<String>,
    pub basic_client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

impl std::fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRequest")
            .field("grant_type", &self.grant_type)
            .field("code", &self.code)
            .field("redirect_uri", &self.redirect_uri)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("basic_client_id", &self.basic_client_id)
            .field(
                "basic_client_secret",
                &self.basic_client_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("code_verifier", &self.code_verifier)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub id_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserInfo {
    pub sub: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Introspection {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<&'static str>,
}

struct AuthCode {
    client_id: String,
    redirect_uri: String,
    challenge: Option<String>,
    xid: Xid,
    nonce: Option<String>,
    used: bool,
    expires_at: Instant,
    issued_access: Option<String>,
}

struct AccessGrant {
    sub: String,
    client_id: String,
    expires_at: Instant,
}

struct RefreshGrant {
    client_id: String,
    xid: Xid,
    sub: String,
}

pub struct Provider {
    issuer: String,
    signing: SigningKey,
    salt: PairwiseSalt,
    clients: Mutex<HashMap<String, Client>>,
    codes: Mutex<HashMap<String, AuthCode>>,
    access: Mutex<HashMap<String, AccessGrant>>,
    /// SHA-256 of the refresh token → grant. The raw token is never stored.
    refresh: Mutex<HashMap<[u8; 32], RefreshGrant>>,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field("issuer", &self.issuer)
            .field("signing", &self.signing)
            .field("salt", &self.salt)
            .finish_non_exhaustive()
    }
}

impl Provider {
    #[must_use]
    pub fn new(issuer: impl Into<String>, signing: SigningKey, salt: PairwiseSalt) -> Self {
        Self {
            issuer: issuer.into().trim_end_matches('/').to_owned(),
            signing,
            salt,
            clients: Mutex::new(HashMap::new()),
            codes: Mutex::new(HashMap::new()),
            access: Mutex::new(HashMap::new()),
            refresh: Mutex::new(HashMap::new()),
        }
    }

    pub fn generate(issuer: impl Into<String>, salt: PairwiseSalt) -> Result<Self, OidcError> {
        let signing = SigningKey::generate().map_err(|e| OidcError::server_error(e.to_string()))?;
        Ok(Self::new(issuer, signing, salt))
    }

    pub fn register(&self, client: Client) {
        if let Ok(mut clients) = self.clients.lock() {
            clients.insert(client.id.clone(), client);
        }
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    #[must_use]
    pub fn discovery(&self) -> DiscoveryDocument {
        DiscoveryDocument::for_issuer(&self.issuer)
    }

    #[must_use]
    pub fn jwks_json(&self) -> String {
        self.signing.public_jwks().to_string()
    }

    pub fn validate_authorize(
        &self,
        query: &AuthorizeQuery,
    ) -> Result<PendingAuthorization, AuthorizeError> {
        let client_id = query
            .client_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AuthorizeError::deny("invalid_request", "client_id is required"))?;
        let client = self
            .client(client_id)
            .ok_or_else(|| AuthorizeError::deny("invalid_client", "unknown client_id"))?;

        let redirect = query.redirect_uri.as_deref().unwrap_or("");
        if redirect.is_empty() || !redirect_allowed(&client, redirect) {
            return Err(AuthorizeError::deny(
                "invalid_request",
                "redirect_uri must exactly match a registered URI",
            ));
        }

        let state = query.state.clone();
        let fail = |error: &'static str, description: &str| {
            AuthorizeError::redirect(redirect, error, description, state.clone())
        };

        match query.response_type.as_deref() {
            Some("code") => {}
            Some(other) if other == "token" || other == "id_token" || other.contains("token") => {
                return Err(fail(
                    "unsupported_response_type",
                    "only response_type=code is supported",
                ));
            }
            _ => {
                return Err(fail("invalid_request", "response_type=code is required"));
            }
        }

        let challenge = query
            .code_challenge
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| fail("invalid_request", "code_challenge is required"))?;
        match query.code_challenge_method.as_deref() {
            None | Some("S256") => {}
            Some(other) => {
                return Err(fail(
                    "invalid_request",
                    &format!("code_challenge_method {other} is refused; only S256"),
                ));
            }
        }

        Ok(PendingAuthorization {
            client_id: client_id.to_owned(),
            redirect_uri: redirect.to_owned(),
            code_challenge: challenge.to_owned(),
            state,
            nonce: query.nonce.clone(),
            scope: query.scope.clone().unwrap_or_else(|| "openid".to_owned()),
        })
    }

    /// Test helper: a code with no stored challenge, so a verifier is a
    /// PKCE downgrade (RFC 9700 §2.1.1).
    #[cfg(test)]
    pub fn issue_code_without_challenge(
        &self,
        pending: &PendingAuthorization,
        xid: Xid,
    ) -> Result<String, OidcError> {
        let code = random_token()?;
        let mut codes = lock(&self.codes)?;
        codes.insert(
            code.clone(),
            AuthCode {
                client_id: pending.client_id.clone(),
                redirect_uri: pending.redirect_uri.clone(),
                challenge: None,
                xid,
                nonce: pending.nonce.clone(),
                used: false,
                expires_at: Instant::now() + CODE_TTL,
                issued_access: None,
            },
        );
        Ok(code)
    }

    /// Mint a one-time authorization code for a completed login.
    ///
    /// HTTP `/authorize` does not call this until `add-dev-authorize`.
    pub fn issue_code(
        &self,
        pending: &PendingAuthorization,
        xid: Xid,
    ) -> Result<String, OidcError> {
        let code = random_token()?;
        let mut codes = lock(&self.codes)?;
        codes.insert(
            code.clone(),
            AuthCode {
                client_id: pending.client_id.clone(),
                redirect_uri: pending.redirect_uri.clone(),
                challenge: Some(pending.code_challenge.clone()),
                xid,
                nonce: pending.nonce.clone(),
                used: false,
                expires_at: Instant::now() + CODE_TTL,
                issued_access: None,
            },
        );
        Ok(code)
    }

    pub fn token(&self, req: &TokenRequest) -> Result<TokenResponse, OidcError> {
        match req.grant_type.as_deref() {
            Some("authorization_code") => self.exchange_code(req),
            Some("password") => Err(OidcError::unsupported_grant_type(
                "resource owner password is refused",
            )),
            Some("refresh_token") => self.exchange_refresh(req),
            _ => Err(OidcError::invalid_request("grant_type is required")),
        }
    }

    /// Authenticate the client named by the token request (body and/or Basic).
    fn authenticate(&self, req: &TokenRequest, client_id: &str) -> Result<Client, OidcError> {
        let client = self
            .client(client_id)
            .ok_or_else(|| OidcError::invalid_client("unknown client_id"))?;
        let presented = presented_auth(req)?;
        match (client.token_endpoint_auth_method, presented) {
            (TokenEndpointAuthMethod::None, PresentedAuth::None) => Ok(client),
            (TokenEndpointAuthMethod::None, _) => Err(OidcError::invalid_client(
                "public client must not send a client secret",
            )),
            (TokenEndpointAuthMethod::ClientSecretBasic, PresentedAuth::Basic { id, secret }) => {
                if id != client.id {
                    return Err(OidcError::invalid_client(
                        "client_id does not match Authorization",
                    ));
                }
                verify_secret(&client, &secret)?;
                Ok(client)
            }
            (TokenEndpointAuthMethod::ClientSecretPost, PresentedAuth::Post { id, secret }) => {
                if id != client.id {
                    return Err(OidcError::invalid_client("client_id mismatch"));
                }
                verify_secret(&client, &secret)?;
                Ok(client)
            }
            (TokenEndpointAuthMethod::ClientSecretBasic, _) => {
                Err(OidcError::invalid_client("client_secret_basic is required"))
            }
            (TokenEndpointAuthMethod::ClientSecretPost, _) => {
                Err(OidcError::invalid_client("client_secret_post is required"))
            }
        }
    }

    pub fn userinfo(&self, access_token: &str) -> Result<UserInfo, OidcError> {
        let grant = self
            .lookup_access(access_token)?
            .ok_or_else(|| OidcError::invalid_grant("unknown or expired access token"))?;
        Ok(UserInfo { sub: grant.sub })
    }

    #[must_use]
    pub fn introspect(&self, token: &str) -> Introspection {
        if let Ok(Some(grant)) = self.lookup_access(token) {
            return Introspection {
                active: true,
                sub: Some(grant.sub),
                client_id: Some(grant.client_id),
                token_type: Some("Bearer"),
            };
        }
        match self.lookup_refresh(token) {
            Ok(Some(grant)) => Introspection {
                active: true,
                sub: Some(grant.sub),
                client_id: Some(grant.client_id),
                token_type: Some("Bearer"),
            },
            _ => Introspection {
                active: false,
                sub: None,
                client_id: None,
                token_type: None,
            },
        }
    }

    pub fn revoke(&self, token: &str) -> Result<(), OidcError> {
        let mut access = lock(&self.access)?;
        if access.remove(token).is_some() {
            return Ok(());
        }
        drop(access);
        let mut refresh = lock(&self.refresh)?;
        refresh.remove(&hash_token(token));
        Ok(())
    }

    fn exchange_code(&self, req: &TokenRequest) -> Result<TokenResponse, OidcError> {
        let client_id = request_client_id(req)?;
        let client = self.authenticate(req, client_id)?;
        let code = req
            .code
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OidcError::invalid_request("code is required"))?;
        let client_id = client.id.as_str();
        let redirect = req.redirect_uri.as_deref().unwrap_or("");

        let mut codes = lock(&self.codes)?;
        let entry = codes
            .get_mut(code)
            .ok_or_else(|| OidcError::invalid_grant("unknown authorization code"))?;
        if entry.used {
            if let Some(token) = entry.issued_access.clone() {
                drop(codes);
                let mut access = lock(&self.access)?;
                access.remove(&token);
            }
            return Err(OidcError::invalid_grant(
                "authorization code has already been used",
            ));
        }
        if Instant::now() >= entry.expires_at {
            return Err(OidcError::invalid_grant("authorization code expired"));
        }
        if entry.client_id != client_id {
            return Err(OidcError::invalid_grant(
                "code was issued to another client",
            ));
        }
        if entry.redirect_uri != redirect {
            return Err(OidcError::invalid_grant("redirect_uri does not match"));
        }

        match (&entry.challenge, req.code_verifier.as_deref()) {
            (None, Some(_)) => {
                return Err(OidcError::invalid_grant(
                    "code_verifier rejected; no challenge was stored",
                ));
            }
            (Some(_), None) => {
                return Err(OidcError::invalid_request("code_verifier is required"));
            }
            (Some(challenge), Some(verifier)) => {
                if !pkce_s256_matches(verifier, challenge) {
                    return Err(OidcError::invalid_grant("code_verifier does not match"));
                }
            }
            (None, None) => {
                return Err(OidcError::invalid_request("PKCE is required"));
            }
        }

        let xid = entry.xid;
        let nonce = entry.nonce.clone();
        entry.used = true;
        drop(codes);

        let issued = self.mint_tokens(client_id, xid, nonce.as_deref())?;
        {
            let mut codes = lock(&self.codes)?;
            if let Some(entry) = codes.get_mut(code) {
                entry.issued_access = Some(issued.access_token.clone());
            }
        }
        Ok(issued)
    }

    fn exchange_refresh(&self, req: &TokenRequest) -> Result<TokenResponse, OidcError> {
        let presented = req
            .refresh_token
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OidcError::invalid_request("refresh_token is required"))?;
        let presented_id = optional_request_client_id(req)?;
        let hashed = hash_token(presented);
        let grant = {
            let refresh = lock(&self.refresh)?;
            refresh
                .get(&hashed)
                .map(|g| RefreshGrant {
                    client_id: g.client_id.clone(),
                    xid: g.xid,
                    sub: g.sub.clone(),
                })
                .ok_or_else(|| OidcError::invalid_grant("unknown or revoked refresh token"))?
        };
        if let Some(client_id) = presented_id {
            if client_id != grant.client_id {
                return Err(OidcError::invalid_grant(
                    "refresh token belongs to another client",
                ));
            }
        }
        self.authenticate(req, &grant.client_id)?;
        {
            let mut refresh = lock(&self.refresh)?;
            if refresh.remove(&hashed).is_none() {
                return Err(OidcError::invalid_grant("unknown or revoked refresh token"));
            }
        }
        self.mint_tokens(&grant.client_id, grant.xid, None)
    }

    fn mint_tokens(
        &self,
        client_id: &str,
        xid: Xid,
        nonce: Option<&str>,
    ) -> Result<TokenResponse, OidcError> {
        let client = self
            .client(client_id)
            .ok_or_else(|| OidcError::invalid_client("unknown client_id"))?;
        let sub = subject(&self.salt, xid, &client)
            .map_err(|e| OidcError::server_error(e.to_string()))?;
        let id_token = self
            .signing
            .sign_id_token(&self.issuer, client_id, &sub, nonce, ACCESS_TTL_SECS)
            .map_err(|e| OidcError::server_error(e.to_string()))?;
        let access_token = random_token()?;
        let refresh_token = random_token()?;
        {
            let mut access = lock(&self.access)?;
            access.insert(
                access_token.clone(),
                AccessGrant {
                    sub: sub.clone(),
                    client_id: client_id.to_owned(),
                    expires_at: Instant::now() + ACCESS_TTL,
                },
            );
        }
        {
            let mut refresh = lock(&self.refresh)?;
            refresh.insert(
                hash_token(&refresh_token),
                RefreshGrant {
                    client_id: client_id.to_owned(),
                    xid,
                    sub,
                },
            );
        }
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: ACCESS_TTL_SECS,
            id_token,
            refresh_token: Some(refresh_token),
        })
    }

    fn client(&self, id: &str) -> Option<Client> {
        self.clients.lock().ok()?.get(id).cloned()
    }

    #[cfg(test)]
    fn refresh_is_hashed(&self, raw: &str) -> bool {
        let Ok(map) = self.refresh.lock() else {
            return false;
        };
        map.contains_key(&hash_token(raw))
            && map.keys().all(|stored| stored.as_slice() != raw.as_bytes())
    }

    fn lookup_refresh(&self, token: &str) -> Result<Option<RefreshGrant>, OidcError> {
        let refresh = lock(&self.refresh)?;
        Ok(refresh.get(&hash_token(token)).map(|g| RefreshGrant {
            client_id: g.client_id.clone(),
            xid: g.xid,
            sub: g.sub.clone(),
        }))
    }

    fn lookup_access(&self, token: &str) -> Result<Option<AccessGrant>, OidcError> {
        let access = lock(&self.access)?;
        Ok(access.get(token).and_then(|g| {
            if Instant::now() >= g.expires_at {
                None
            } else {
                Some(AccessGrant {
                    sub: g.sub.clone(),
                    client_id: g.client_id.clone(),
                    expires_at: g.expires_at,
                })
            }
        }))
    }
}

enum PresentedAuth {
    None,
    Basic { id: String, secret: String },
    Post { id: String, secret: String },
}

fn presented_auth(req: &TokenRequest) -> Result<PresentedAuth, OidcError> {
    let has_basic = req
        .basic_client_id
        .as_deref()
        .is_some_and(|s| !s.is_empty())
        || req
            .basic_client_secret
            .as_deref()
            .is_some_and(|s| !s.is_empty());
    let has_post = req.client_secret.as_deref().is_some_and(|s| !s.is_empty());
    if has_basic && has_post {
        return Err(OidcError::invalid_client(
            "multiple client authentication methods",
        ));
    }
    if has_basic {
        let id = req
            .basic_client_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OidcError::invalid_client("malformed client authentication"))?;
        let secret = req
            .basic_client_secret
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OidcError::invalid_client("malformed client authentication"))?;
        return Ok(PresentedAuth::Basic {
            id: id.to_owned(),
            secret: secret.to_owned(),
        });
    }
    if has_post {
        let id = req
            .client_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OidcError::invalid_client("client_id is required"))?;
        let secret = req
            .client_secret
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OidcError::invalid_client("malformed client authentication"))?;
        return Ok(PresentedAuth::Post {
            id: id.to_owned(),
            secret: secret.to_owned(),
        });
    }
    Ok(PresentedAuth::None)
}

fn optional_request_client_id(req: &TokenRequest) -> Result<Option<&str>, OidcError> {
    match (
        req.basic_client_id.as_deref().filter(|s| !s.is_empty()),
        req.client_id.as_deref().filter(|s| !s.is_empty()),
    ) {
        (Some(basic), Some(body)) if basic != body => Err(OidcError::invalid_client(
            "client_id does not match Authorization",
        )),
        (Some(basic), _) => Ok(Some(basic)),
        (None, Some(body)) => Ok(Some(body)),
        (None, None) => Ok(None),
    }
}

fn request_client_id(req: &TokenRequest) -> Result<&str, OidcError> {
    optional_request_client_id(req)?
        .ok_or_else(|| OidcError::invalid_client("client_id is required"))
}

fn verify_secret(client: &Client, presented: &str) -> Result<(), OidcError> {
    let Some(stored) = client.secret_hash() else {
        return Err(OidcError::invalid_client("client authentication failed"));
    };
    let computed = hash_client_secret(presented);
    if ct_eq(&computed, &stored) {
        Ok(())
    } else {
        Err(OidcError::invalid_client("client authentication failed"))
    }
}

/// RFC 6749 §2.3.1 HTTP Basic. `None` if the header is absent or not Basic.
pub fn parse_http_basic(header: &str) -> Result<Option<(String, String)>, OidcError> {
    let trimmed = header.trim();
    let Some((scheme, param)) = trimmed.split_once(' ') else {
        return Ok(None);
    };
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Ok(None);
    }
    let param = param.trim();
    if param.is_empty() {
        return Err(OidcError::invalid_client("malformed client authentication"));
    }
    let decoded = STANDARD
        .decode(param)
        .map_err(|_| OidcError::invalid_client("malformed client authentication"))?;
    let decoded = String::from_utf8(decoded)
        .map_err(|_| OidcError::invalid_client("malformed client authentication"))?;
    let Some((id, secret)) = decoded.split_once(':') else {
        return Err(OidcError::invalid_client("malformed client authentication"));
    };
    Ok(Some((www_form_decode(id)?, www_form_decode(secret)?)))
}

fn www_form_decode(input: &str) -> Result<String, OidcError> {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes.get(i).copied() {
            Some(b'+') => {
                out.push(b' ');
                i += 1;
            }
            Some(b'%') => {
                let h1 = bytes.get(i + 1).copied().and_then(from_hex_digit);
                let h2 = bytes.get(i + 2).copied().and_then(from_hex_digit);
                match (h1, h2) {
                    (Some(a), Some(b)) => {
                        out.push((a << 4) | b);
                        i += 3;
                    }
                    _ => {
                        return Err(OidcError::invalid_client("malformed client authentication"));
                    }
                }
            }
            Some(b) => {
                out.push(b);
                i += 1;
            }
            None => break,
        }
    }
    String::from_utf8(out).map_err(|_| OidcError::invalid_client("malformed client authentication"))
}

fn from_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, OidcError> {
    mutex
        .lock()
        .map_err(|_| OidcError::server_error("lock poisoned"))
}

fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn random_token() -> Result<String, OidcError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| OidcError::server_error(format!("entropy: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn pkce_s256_matches(verifier: &str, challenge: &str) -> bool {
    if !(43..=128).contains(&verifier.len()) {
        return false;
    }
    if !verifier
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'))
    {
        return false;
    }
    let digest = Sha256::digest(verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(digest);
    ct_eq(computed.as_bytes(), challenge.as_bytes())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Exact string match, plus RFC 8252 §7.3 loopback port flexibility.
fn redirect_allowed(client: &Client, requested: &str) -> bool {
    if !is_safe_redirect(requested) {
        return false;
    }
    client
        .redirect_uris
        .iter()
        .any(|registered| registered == requested || loopback_port_flexible(registered, requested))
}

fn is_safe_redirect(uri: &str) -> bool {
    if uri.starts_with("https://") {
        return true;
    }
    is_loopback_http(uri)
}

fn is_loopback_http(uri: &str) -> bool {
    uri.starts_with("http://127.0.0.1:")
        || uri.starts_with("http://127.0.0.1/")
        || uri.starts_with("http://localhost:")
        || uri.starts_with("http://localhost/")
        || uri.starts_with("http://[::1]:")
        || uri.starts_with("http://[::1]/")
}

fn loopback_port_flexible(registered: &str, requested: &str) -> bool {
    fn split_loopback(uri: &str) -> Option<(&str, &str)> {
        for prefix in ["http://127.0.0.1", "http://localhost", "http://[::1]"] {
            if let Some(rest) = uri.strip_prefix(prefix) {
                if rest.starts_with(':') {
                    let after_port = rest.find(['/', '?', '#']).map_or(rest.len(), |i| i);
                    let path = rest.get(after_port..).unwrap_or("");
                    return Some((prefix, path));
                }
                if rest.starts_with('/') || rest.starts_with('?') || rest.is_empty() {
                    return Some((prefix, rest));
                }
            }
        }
        None
    }
    match (split_loopback(registered), split_loopback(requested)) {
        (Some((a_host, a_path)), Some((b_host, b_path))) => a_host == b_host && a_path == b_path,
        _ => false,
    }
}

/// Build the S256 challenge for a verifier. Tests and later login use this.
#[must_use]
pub fn s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;

    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

    fn provider() -> Provider {
        let salt = PairwiseSalt::from_hex(&"ab".repeat(32)).unwrap();
        let p = Provider::generate("http://127.0.0.1:8080", salt).unwrap();
        p.register(Client::new("smoke", "127.0.0.1").with_redirect("http://127.0.0.1:9999/cb"));
        p
    }

    fn xid() -> Xid {
        Xid::from_bytes([0x11; 32])
    }

    fn good_query() -> AuthorizeQuery {
        AuthorizeQuery {
            response_type: Some("code".into()),
            client_id: Some("smoke".into()),
            redirect_uri: Some("http://127.0.0.1:9999/cb".into()),
            code_challenge: Some(s256_challenge(VERIFIER)),
            code_challenge_method: Some("S256".into()),
            state: Some("xyz".into()),
            nonce: None,
            scope: Some("openid".into()),
        }
    }

    #[test]
    fn missing_pkce_is_refused() {
        let p = provider();
        let mut q = good_query();
        q.code_challenge = None;
        let err = p.validate_authorize(&q).unwrap_err();
        match err {
            AuthorizeError::Redirect { error, .. } => assert_eq!(error, "invalid_request"),
            other => panic!("expected redirect error, got {other:?}"),
        }
    }

    #[test]
    fn implicit_is_refused() {
        let p = provider();
        let mut q = good_query();
        q.response_type = Some("token".into());
        let err = p.validate_authorize(&q).unwrap_err();
        match err {
            AuthorizeError::Redirect { error, .. } => {
                assert_eq!(error, "unsupported_response_type");
            }
            other => panic!("expected redirect error, got {other:?}"),
        }
    }

    #[test]
    fn code_is_one_time() {
        let p = provider();
        let pending = p.validate_authorize(&good_query()).unwrap();
        let code = p.issue_code(&pending, xid()).unwrap();
        let req = TokenRequest {
            grant_type: Some("authorization_code".into()),
            code: Some(code),
            redirect_uri: Some(pending.redirect_uri.clone()),
            client_id: Some("smoke".into()),
            client_secret: None,
            basic_client_id: None,
            basic_client_secret: None,
            code_verifier: Some(VERIFIER.into()),
            refresh_token: None,
        };
        let first = p.token(&req).unwrap();
        assert!(!first.access_token.is_empty());
        assert_eq!(first.id_token.split('.').count(), 3);
        let second = p.token(&req).unwrap_err();
        assert_eq!(second.error, "invalid_grant");
        assert!(p.userinfo(&first.access_token).is_err());
    }

    #[test]
    fn pkce_downgrade_refused() {
        let p = provider();
        let pending = p.validate_authorize(&good_query()).unwrap();
        let missing_verifier = p.issue_code(&pending, xid()).unwrap();
        let err = p
            .token(&TokenRequest {
                grant_type: Some("authorization_code".into()),
                code: Some(missing_verifier),
                redirect_uri: Some(pending.redirect_uri.clone()),
                client_id: Some("smoke".into()),
                client_secret: None,
                basic_client_id: None,
                basic_client_secret: None,
                code_verifier: None,
                refresh_token: None,
            })
            .unwrap_err();
        assert_eq!(err.error, "invalid_request");

        let no_challenge = p.issue_code_without_challenge(&pending, xid()).unwrap();
        let err = p
            .token(&TokenRequest {
                grant_type: Some("authorization_code".into()),
                code: Some(no_challenge),
                redirect_uri: Some(pending.redirect_uri),
                client_id: Some("smoke".into()),
                client_secret: None,
                basic_client_id: None,
                basic_client_secret: None,
                code_verifier: Some(VERIFIER.into()),
                refresh_token: None,
            })
            .unwrap_err();
        assert_eq!(err.error, "invalid_grant");
    }

    #[test]
    fn discovery_shape() {
        let p = provider();
        let json = serde_json::to_string(&p.discovery()).unwrap();
        assert!(json.contains("authorization_endpoint"));
        assert!(json.contains("/token"));
        assert!(json.contains("jwks_uri"));
        assert!(json.contains("\"code\""));
        assert!(json.contains("S256"));
        assert!(!json.contains("password"));
        assert_eq!(
            p.discovery().token_endpoint_auth_methods_supported,
            vec!["none", "client_secret_basic", "client_secret_post"]
        );
    }

    #[test]
    fn refresh_rotates_and_stores_only_hash() {
        let p = provider();
        let pending = p.validate_authorize(&good_query()).unwrap();
        let code = p.issue_code(&pending, xid()).unwrap();
        let first = p
            .token(&TokenRequest {
                grant_type: Some("authorization_code".into()),
                code: Some(code),
                redirect_uri: Some(pending.redirect_uri),
                client_id: Some("smoke".into()),
                client_secret: None,
                basic_client_id: None,
                basic_client_secret: None,
                code_verifier: Some(VERIFIER.into()),
                refresh_token: None,
            })
            .unwrap();
        let t1 = first.refresh_token.clone().unwrap();
        assert!(p.refresh_is_hashed(&t1));

        let second = p
            .token(&TokenRequest {
                grant_type: Some("refresh_token".into()),
                code: None,
                redirect_uri: None,
                client_id: Some("smoke".into()),
                client_secret: None,
                basic_client_id: None,
                basic_client_secret: None,
                code_verifier: None,
                refresh_token: Some(t1.clone()),
            })
            .unwrap();
        let t2 = second.refresh_token.clone().unwrap();
        assert_ne!(t1, t2);
        assert!(p.refresh_is_hashed(&t2));

        let replay = p
            .token(&TokenRequest {
                grant_type: Some("refresh_token".into()),
                code: None,
                redirect_uri: None,
                client_id: Some("smoke".into()),
                client_secret: None,
                basic_client_id: None,
                basic_client_secret: None,
                code_verifier: None,
                refresh_token: Some(t1),
            })
            .unwrap_err();
        assert_eq!(replay.error, "invalid_grant");
    }

    #[test]
    fn revoked_refresh_is_inactive() {
        let p = provider();
        let pending = p.validate_authorize(&good_query()).unwrap();
        let code = p.issue_code(&pending, xid()).unwrap();
        let issued = p
            .token(&TokenRequest {
                grant_type: Some("authorization_code".into()),
                code: Some(code),
                redirect_uri: Some(pending.redirect_uri),
                client_id: Some("smoke".into()),
                client_secret: None,
                basic_client_id: None,
                basic_client_secret: None,
                code_verifier: Some(VERIFIER.into()),
                refresh_token: None,
            })
            .unwrap();
        let refresh = issued.refresh_token.unwrap();
        assert!(p.introspect(&refresh).active);
        p.revoke(&refresh).unwrap();
        assert!(!p.introspect(&refresh).active);
        let err = p
            .token(&TokenRequest {
                grant_type: Some("refresh_token".into()),
                code: None,
                redirect_uri: None,
                client_id: Some("smoke".into()),
                client_secret: None,
                basic_client_id: None,
                basic_client_secret: None,
                code_verifier: None,
                refresh_token: Some(refresh),
            })
            .unwrap_err();
        assert_eq!(err.error, "invalid_grant");
    }

    fn confidential_provider() -> Provider {
        let p = provider();
        p.register(
            Client::new("basic-1", "127.0.0.1")
                .with_redirect("http://127.0.0.1:9999/cb")
                .with_secret(TokenEndpointAuthMethod::ClientSecretBasic, "basic-secret"),
        );
        p.register(
            Client::new("basic-2", "127.0.0.1")
                .with_redirect("http://127.0.0.1:9999/cb")
                .with_secret(TokenEndpointAuthMethod::ClientSecretBasic, "basic-secret-2"),
        );
        p.register(
            Client::new("post-1", "127.0.0.1")
                .with_redirect("http://127.0.0.1:9999/cb")
                .with_secret(TokenEndpointAuthMethod::ClientSecretPost, "post-secret"),
        );
        p
    }

    fn pending_for(p: &Provider, client_id: &str) -> PendingAuthorization {
        p.validate_authorize(&AuthorizeQuery {
            response_type: Some("code".into()),
            client_id: Some(client_id.into()),
            redirect_uri: Some("http://127.0.0.1:9999/cb".into()),
            code_challenge: Some(s256_challenge(VERIFIER)),
            code_challenge_method: Some("S256".into()),
            state: None,
            nonce: None,
            scope: Some("openid".into()),
        })
        .unwrap()
    }

    #[test]
    fn two_basic_and_one_post_register() {
        let p = confidential_provider();
        assert!(p.client("basic-1").is_some());
        assert!(p.client("basic-2").is_some());
        assert!(p.client("post-1").is_some());
        assert_eq!(
            p.client("basic-1").unwrap().token_endpoint_auth_method,
            TokenEndpointAuthMethod::ClientSecretBasic
        );
        assert_eq!(
            p.client("post-1").unwrap().token_endpoint_auth_method,
            TokenEndpointAuthMethod::ClientSecretPost
        );
    }

    #[test]
    fn wrong_secret_is_refused() {
        let p = confidential_provider();
        let pending = pending_for(&p, "basic-1");
        let code = p.issue_code(&pending, xid()).unwrap();
        let err = p
            .token(&TokenRequest {
                grant_type: Some("authorization_code".into()),
                code: Some(code.clone()),
                redirect_uri: Some(pending.redirect_uri.clone()),
                client_id: Some("basic-1".into()),
                client_secret: None,
                basic_client_id: Some("basic-1".into()),
                basic_client_secret: Some("wrong".into()),
                code_verifier: Some(VERIFIER.into()),
                refresh_token: None,
            })
            .unwrap_err();
        assert_eq!(err.error, "invalid_client");
        // Code was not consumed: the right secret still works.
        let issued = p
            .token(&TokenRequest {
                grant_type: Some("authorization_code".into()),
                code: Some(code),
                redirect_uri: Some(pending.redirect_uri),
                client_id: Some("basic-1".into()),
                client_secret: None,
                basic_client_id: Some("basic-1".into()),
                basic_client_secret: Some("basic-secret".into()),
                code_verifier: Some(VERIFIER.into()),
                refresh_token: None,
            })
            .unwrap();
        assert!(!issued.access_token.is_empty());
    }

    #[test]
    fn public_client_still_uses_pkce_only() {
        let p = confidential_provider();
        let pending = pending_for(&p, "smoke");
        let code = p.issue_code(&pending, xid()).unwrap();
        let issued = p
            .token(&TokenRequest {
                grant_type: Some("authorization_code".into()),
                code: Some(code),
                redirect_uri: Some(pending.redirect_uri),
                client_id: Some("smoke".into()),
                client_secret: None,
                basic_client_id: None,
                basic_client_secret: None,
                code_verifier: Some(VERIFIER.into()),
                refresh_token: None,
            })
            .unwrap();
        assert!(!issued.access_token.is_empty());
    }

    #[test]
    fn public_client_sending_secret_is_refused() {
        let p = confidential_provider();
        let pending = pending_for(&p, "smoke");
        let code = p.issue_code(&pending, xid()).unwrap();
        let err = p
            .token(&TokenRequest {
                grant_type: Some("authorization_code".into()),
                code: Some(code),
                redirect_uri: Some(pending.redirect_uri),
                client_id: Some("smoke".into()),
                client_secret: Some("not-a-secret".into()),
                basic_client_id: None,
                basic_client_secret: None,
                code_verifier: Some(VERIFIER.into()),
                refresh_token: None,
            })
            .unwrap_err();
        assert_eq!(err.error, "invalid_client");
    }

    #[test]
    fn confidential_still_requires_pkce() {
        let p = confidential_provider();
        let pending = pending_for(&p, "post-1");
        let code = p.issue_code(&pending, xid()).unwrap();
        let err = p
            .token(&TokenRequest {
                grant_type: Some("authorization_code".into()),
                code: Some(code),
                redirect_uri: Some(pending.redirect_uri),
                client_id: Some("post-1".into()),
                client_secret: Some("post-secret".into()),
                basic_client_id: None,
                basic_client_secret: None,
                code_verifier: None,
                refresh_token: None,
            })
            .unwrap_err();
        assert_eq!(err.error, "invalid_request");
    }

    #[test]
    fn client_secret_post_succeeds() {
        let p = confidential_provider();
        let pending = pending_for(&p, "post-1");
        let code = p.issue_code(&pending, xid()).unwrap();
        let issued = p
            .token(&TokenRequest {
                grant_type: Some("authorization_code".into()),
                code: Some(code),
                redirect_uri: Some(pending.redirect_uri),
                client_id: Some("post-1".into()),
                client_secret: Some("post-secret".into()),
                basic_client_id: None,
                basic_client_secret: None,
                code_verifier: Some(VERIFIER.into()),
                refresh_token: None,
            })
            .unwrap();
        assert!(!issued.access_token.is_empty());
    }

    #[test]
    fn parse_basic_decodes_form_urlencoded() {
        let raw = format!("Basic {}", STANDARD.encode("client%3Aid:sec%3Aret"));
        let (id, secret) = parse_http_basic(&raw).unwrap().unwrap();
        assert_eq!(id, "client:id");
        assert_eq!(secret, "sec:ret");
    }
}
