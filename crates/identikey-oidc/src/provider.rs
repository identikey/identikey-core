//! Authorization-code provider with durable, rotating refresh sessions.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use identikey_auth::{
    AuthError, ChallengeIssuer, ClassicalPublicKey, InMemoryNonceStore, VerifyPolicy,
    verify_response,
};
use identikey_keys::Xid;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::device::{self, DeviceSessions, Poll};
use crate::discovery::DiscoveryDocument;
use crate::error::{AuthorizeError, OidcError};
use crate::salt::PairwiseSalt;
use crate::signing::SigningKey;
use crate::subject::{
    Client, GRANT_AUTHORIZATION_CODE, GRANT_DEVICE_CODE, GRANT_REFRESH_TOKEN,
    TokenEndpointAuthMethod, hash_client_secret, subject,
};

const CODE_TTL: Duration = Duration::from_secs(600);
const ACCESS_TTL: Duration = Duration::from_secs(3600);
const ACCESS_TTL_SECS: u64 = 3600;
const CHALLENGE_TTL_SECS: u64 = 120;
const CHALLENGE_SKEW_SECS: u64 = 30;

/// RFC 6749 grant_type for an identikey-auth Response.
pub const CHALLENGE_RESPONSE_GRANT: &str = crate::subject::GRANT_CHALLENGE_RESPONSE;

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
    /// Unpadded base64url of identikey-auth Response bytes (URN grant).
    pub response: Option<String>,
    /// RFC 8628 device code. Held by the poller. It is the redemption secret.
    pub device_code: Option<String>,
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
            .field("response", &self.response.as_ref().map(|_| "[redacted]"))
            .field(
                "device_code",
                &self.device_code.as_ref().map(|_| "[redacted]"),
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

/// RFC 8628 device-authorization response. Raw codes are returned once.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// Public registration fields the confirm page may show.
#[derive(Debug, Clone)]
pub struct RegisteredClient {
    pub id: String,
    pub display_name: String,
    pub subject_type: crate::subject::SubjectType,
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

#[derive(Clone)]
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
    refresh_pool: Option<sqlx::PgPool>,
    devices: Mutex<DeviceSessions>,
    challenges: ChallengeIssuer,
    nonces: Mutex<InMemoryNonceStore>,
    /// identikey-auth public key (alg + bytes) → XID. Never a user private key.
    subjects: Mutex<HashMap<Vec<u8>, Xid>>,
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
        let issuer = issuer.into().trim_end_matches('/').to_owned();
        Self {
            challenges: ChallengeIssuer::new(issuer.clone(), CHALLENGE_TTL_SECS),
            issuer,
            signing,
            salt,
            clients: Mutex::new(HashMap::new()),
            codes: Mutex::new(HashMap::new()),
            access: Mutex::new(HashMap::new()),
            refresh: Mutex::new(HashMap::new()),
            refresh_pool: None,
            devices: Mutex::new(DeviceSessions::new()),
            nonces: Mutex::new(InMemoryNonceStore::new()),
            subjects: Mutex::new(HashMap::new()),
        }
    }

    /// Production refresh sessions share the account database, so replacing a
    /// service VM does not sign every relying party out. Only token hashes persist.
    #[must_use]
    pub fn with_refresh_pool(mut self, pool: sqlx::PgPool) -> Self {
        self.refresh_pool = Some(pool);
        self
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

    /// Bind an identikey-auth public key to a stored XID. The OP still
    /// never holds the matching private key.
    pub fn register_subject(&self, public_key: &ClassicalPublicKey, xid: Xid) {
        if let Ok(mut subjects) = self.subjects.lock() {
            subjects.insert(subject_key(public_key), xid);
        }
    }

    /// Issue a verifier-owned Challenge (`aud` = this issuer). Bytes are
    /// canonical dCBOR per identikey-auth-challenge-v1.
    pub fn issue_challenge(&self) -> Result<Vec<u8>, OidcError> {
        let now = unix_now()?;
        let mut nonces = lock(&self.nonces)?;
        let challenge = self.challenges.issue(&mut *nonces, now);
        Ok(challenge.to_bytes())
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
        if !client.allows_grant(GRANT_AUTHORIZATION_CODE) {
            return Err(AuthorizeError::deny(
                "unauthorized_client",
                "client is not allowed the authorization_code grant",
            ));
        }

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

    pub async fn token(&self, req: &TokenRequest) -> Result<TokenResponse, OidcError> {
        match req.grant_type.as_deref() {
            Some("authorization_code") => self.exchange_code(req).await,
            Some("password") => Err(OidcError::unsupported_grant_type(
                "resource owner password is refused",
            )),
            Some("refresh_token") => self.exchange_refresh(req).await,
            Some(CHALLENGE_RESPONSE_GRANT) => self.exchange_urn(req).await,
            Some(GRANT_DEVICE_CODE) => self.exchange_device(req).await,
            Some("") | None => Err(OidcError::invalid_request("grant_type is required")),
            Some(other) => Err(OidcError::unsupported_grant_type(format!(
                "grant_type {other} is refused"
            ))),
        }
    }

    /// Start an RFC 8628 device authorization. The raw codes leave this process once.
    pub fn start_device(
        &self,
        req: &TokenRequest,
        scope: Option<&str>,
    ) -> Result<DeviceAuthorizationResponse, OidcError> {
        if let Some(scope) = scope.map(str::trim).filter(|value| !value.is_empty()) {
            if scope.split_whitespace().any(|part| part != "openid") {
                return Err(OidcError::new(
                    "invalid_scope",
                    "only scope=openid is supported",
                ));
            }
        }
        let client_id = request_client_id(req)?;
        let client = self.authenticate(req, client_id)?;
        ensure_grant(&client, GRANT_DEVICE_CODE)?;
        let now = unix_now()?;
        let (device_code, user_code) = {
            let mut devices = lock(&self.devices)?;
            let mut issued = None;
            for _ in 0..8 {
                let device_code = device::new_device_code()?;
                let user_code = device::new_user_code()?;
                if devices.contains_user(&user_code) || devices.contains_device(&device_code) {
                    continue;
                }
                devices.insert(&client.id, &device_code, &user_code, now);
                issued = Some((device_code, user_code));
                break;
            }
            issued.ok_or_else(|| OidcError::server_error("could not allocate a device code"))?
        };
        let shown = hyphenate_user_code(&user_code);
        let verification_uri = format!("{}/device", self.issuer);
        Ok(DeviceAuthorizationResponse {
            device_code,
            user_code: shown.clone(),
            verification_uri: verification_uri.clone(),
            verification_uri_complete: format!("{verification_uri}?user_code={shown}"),
            expires_in: device::DEVICE_TTL_SECS,
            interval: device::DEVICE_INTERVAL_SECS,
        })
    }

    pub fn device_prompt(
        &self,
        user_code: &str,
        source: &str,
    ) -> Result<device::DevicePrompt, OidcError> {
        let mut devices = lock(&self.devices)?;
        devices.prompt(user_code, source, unix_now()?, Instant::now())
    }

    pub fn bind_device_assertion(
        &self,
        user_code: &str,
        challenge: &[u8],
    ) -> Result<(), OidcError> {
        let mut devices = lock(&self.devices)?;
        devices.bind(user_code, challenge, unix_now()?)
    }

    pub fn approve_device(
        &self,
        user_code: &str,
        xid: Xid,
        challenge: &[u8],
    ) -> Result<(), OidcError> {
        let mut devices = lock(&self.devices)?;
        devices.approve(user_code, xid, challenge, unix_now()?)
    }

    pub fn deny_device(&self, user_code: &str) -> Result<(), OidcError> {
        let mut devices = lock(&self.devices)?;
        devices.deny(user_code, unix_now()?)
    }

    #[must_use]
    pub fn registered_client(&self, id: &str) -> Option<RegisteredClient> {
        self.client(id).map(|client| RegisteredClient {
            id: client.id,
            display_name: client.display_name,
            subject_type: client.subject_type,
        })
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
    pub async fn introspect(&self, token: &str) -> Introspection {
        if let Ok(Some(grant)) = self.lookup_access(token) {
            return Introspection {
                active: true,
                sub: Some(grant.sub),
                client_id: Some(grant.client_id),
                token_type: Some("Bearer"),
            };
        }
        match self.lookup_refresh(token).await {
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

    pub async fn revoke(&self, token: &str) -> Result<(), OidcError> {
        {
            let mut access = lock(&self.access)?;
            if access.remove(token).is_some() {
                return Ok(());
            }
        }
        let hash = hash_token(token);
        if let Some(pool) = &self.refresh_pool {
            sqlx::query("DELETE FROM oidc_refresh_sessions WHERE issuer = $1 AND token_hash = $2")
                .bind(&self.issuer)
                .bind(hash.as_slice())
                .execute(pool)
                .await
                .map_err(refresh_store_error)?;
        } else {
            lock(&self.refresh)?.remove(&hash);
        }
        Ok(())
    }

    async fn exchange_device(&self, req: &TokenRequest) -> Result<TokenResponse, OidcError> {
        let client_id = request_client_id(req)?;
        let client = self.authenticate(req, client_id)?;
        ensure_grant(&client, GRANT_DEVICE_CODE)?;
        let device_code = req
            .device_code
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| OidcError::invalid_request("device_code is required"))?;
        let polled = {
            let mut devices = lock(&self.devices)?;
            devices.poll(device_code, &client.id, unix_now()?, Instant::now())?
        };
        match polled {
            Poll::Pending => Err(OidcError::new(
                "authorization_pending",
                "authorization pending",
            )),
            Poll::SlowDown => Err(OidcError::new("slow_down", "polling too frequently")),
            Poll::Ready { client_id, xid } => self.mint_tokens(&client_id, xid, None, None).await,
        }
    }

    async fn exchange_urn(&self, req: &TokenRequest) -> Result<TokenResponse, OidcError> {
        let client_id = request_client_id(req)?;
        let client = self.authenticate(req, client_id)?;
        ensure_grant(&client, CHALLENGE_RESPONSE_GRANT)?;
        // The Response audience is this issuer. A wallet client, not this
        // slice, must also bind that Response to the redeeming client_id.
        // The nonce stops replay. It does not stop cross-client redemption.
        let encoded = req
            .response
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OidcError::invalid_request("response is required"))?;
        let bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| {
            OidcError::invalid_grant("response is not a valid identikey-auth Response")
        })?;
        let parsed = identikey_auth::Response::from_bytes(&bytes).map_err(|_| {
            OidcError::invalid_grant("response is not a valid identikey-auth Response")
        })?;
        let now = unix_now()?;
        let verified = {
            let mut nonces = lock(&self.nonces)?;
            verify_response(
                &parsed,
                &self.issuer,
                now,
                CHALLENGE_SKEW_SECS,
                VerifyPolicy::PqOptional,
                &mut *nonces,
            )
            .map_err(auth_to_oidc)?
        };
        let xid = self
            .subject_for(&verified.public_key)
            .ok_or_else(|| OidcError::invalid_grant("unknown subject"))?;
        self.mint_tokens(&client.id, xid, None, None).await
    }

    fn subject_for(&self, public_key: &ClassicalPublicKey) -> Option<Xid> {
        self.subjects
            .lock()
            .ok()?
            .get(&subject_key(public_key))
            .copied()
    }

    async fn exchange_code(&self, req: &TokenRequest) -> Result<TokenResponse, OidcError> {
        let client_id = request_client_id(req)?;
        let client = self.authenticate(req, client_id)?;
        ensure_grant(&client, GRANT_AUTHORIZATION_CODE)?;
        let code = req
            .code
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OidcError::invalid_request("code is required"))?;
        let client_id = client.id.as_str();
        let redirect = req.redirect_uri.as_deref().unwrap_or("");

        let (xid, nonce) = {
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
            (xid, nonce)
        };

        let issued = self
            .mint_tokens(client_id, xid, nonce.as_deref(), None)
            .await?;
        {
            let mut codes = lock(&self.codes)?;
            if let Some(entry) = codes.get_mut(code) {
                entry.issued_access = Some(issued.access_token.clone());
            }
        }
        Ok(issued)
    }

    async fn exchange_refresh(&self, req: &TokenRequest) -> Result<TokenResponse, OidcError> {
        let presented = req
            .refresh_token
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OidcError::invalid_request("refresh_token is required"))?;
        let presented_id = optional_request_client_id(req)?;
        let hashed = hash_token(presented);
        let grant = self
            .lookup_refresh(presented)
            .await?
            .ok_or_else(|| OidcError::invalid_grant("unknown or revoked refresh token"))?;
        if let Some(client_id) = presented_id {
            if client_id != grant.client_id {
                return Err(OidcError::invalid_grant(
                    "refresh token belongs to another client",
                ));
            }
        }
        let client = self.authenticate(req, &grant.client_id)?;
        ensure_grant(&client, GRANT_REFRESH_TOKEN)?;
        self.mint_tokens(&grant.client_id, grant.xid, None, Some(hashed))
            .await
    }

    async fn mint_tokens(
        &self,
        client_id: &str,
        xid: Xid,
        nonce: Option<&str>,
        previous: Option<[u8; 32]>,
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
        self.store_refresh(
            hash_token(&refresh_token),
            RefreshGrant {
                client_id: client_id.to_owned(),
                xid,
                sub: sub.clone(),
            },
            previous,
        )
        .await?;
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

    /// Whether a browser `Origin` may call `/token` (and other SPA endpoints).
    ///
    /// Public clients exchange the authorization code from JavaScript. The
    /// origin must match a registered redirect (scheme + host + port), with
    /// RFC 8252 loopback port flexibility so Vite can hop 5173 → 5174.
    #[must_use]
    pub fn allows_browser_origin(&self, origin: &str) -> bool {
        let Ok(clients) = self.clients.lock() else {
            return false;
        };
        clients.values().any(|client| {
            client
                .redirect_uris
                .iter()
                .any(|uri| origin_matches_redirect(uri, origin))
        })
    }

    #[cfg(test)]
    fn refresh_is_hashed(&self, raw: &str) -> bool {
        let Ok(map) = self.refresh.lock() else {
            return false;
        };
        map.contains_key(&hash_token(raw))
            && map.keys().all(|stored| stored.as_slice() != raw.as_bytes())
    }

    async fn lookup_refresh(&self, token: &str) -> Result<Option<RefreshGrant>, OidcError> {
        let hash = hash_token(token);
        if let Some(pool) = &self.refresh_pool {
            let row: Option<(String, Vec<u8>, String)> = sqlx::query_as(
                "SELECT client_id, xid, sub FROM oidc_refresh_sessions WHERE issuer = $1 AND token_hash = $2"
            ).bind(&self.issuer).bind(hash.as_slice()).fetch_optional(pool).await
                .map_err(refresh_store_error)?;
            row.map(|(client_id, bytes, sub)| {
                let xid = Xid::try_from_slice(&bytes)
                    .map_err(|_| OidcError::server_error("invalid refresh session identity"))?;
                Ok(RefreshGrant {
                    client_id,
                    xid,
                    sub,
                })
            })
            .transpose()
        } else {
            Ok(lock(&self.refresh)?.get(&hash).cloned())
        }
    }

    /// Rotation is one compare-and-swap, including across server instances.
    /// A failed database write leaves the previous credential usable.
    async fn store_refresh(
        &self,
        hash: [u8; 32],
        grant: RefreshGrant,
        previous: Option<[u8; 32]>,
    ) -> Result<(), OidcError> {
        if let Some(pool) = &self.refresh_pool {
            if let Some(old) = previous {
                let result = sqlx::query(
                    "UPDATE oidc_refresh_sessions SET token_hash = $3, sub = $4, refreshed_at = now() \
                     WHERE issuer = $1 AND token_hash = $2 AND client_id = $5"
                ).bind(&self.issuer).bind(old.as_slice()).bind(hash.as_slice())
                    .bind(&grant.sub).bind(&grant.client_id).execute(pool).await.map_err(refresh_store_error)?;
                if result.rows_affected() != 1 {
                    return Err(OidcError::invalid_grant("unknown or revoked refresh token"));
                }
            } else {
                sqlx::query(
                    "INSERT INTO oidc_refresh_sessions (issuer, token_hash, client_id, xid, sub) VALUES ($1, $2, $3, $4, $5)"
                ).bind(&self.issuer).bind(hash.as_slice()).bind(&grant.client_id)
                    .bind(grant.xid.as_bytes().as_slice()).bind(&grant.sub)
                    .execute(pool).await.map_err(refresh_store_error)?;
            }
        } else {
            let mut refresh = lock(&self.refresh)?;
            if let Some(old) = previous {
                if refresh.remove(&old).is_none() {
                    return Err(OidcError::invalid_grant("unknown or revoked refresh token"));
                }
            }
            refresh.insert(hash, grant);
        }
        Ok(())
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

fn ensure_grant(client: &Client, grant: &str) -> Result<(), OidcError> {
    if client.allows_grant(grant) {
        Ok(())
    } else {
        Err(OidcError::unauthorized_client(format!(
            "client is not allowed grant {grant}"
        )))
    }
}

fn hyphenate_user_code(raw: &str) -> String {
    if raw.len() == 8 && raw.is_ascii() {
        format!("{}-{}", &raw[..4], &raw[4..])
    } else {
        raw.to_owned()
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

fn unix_now() -> Result<u64, OidcError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| OidcError::server_error("clock before epoch"))
}

fn subject_key(public_key: &ClassicalPublicKey) -> Vec<u8> {
    let tag = public_key.alg.tag().as_bytes();
    let mut key = Vec::with_capacity(tag.len() + 1 + public_key.bytes.len());
    key.extend_from_slice(tag);
    key.push(0);
    key.extend_from_slice(&public_key.bytes);
    key
}

fn auth_to_oidc(err: AuthError) -> OidcError {
    match err {
        AuthError::NonceReplay => OidcError::invalid_grant("nonce replay"),
        AuthError::Audience | AuthError::TimeWindow | AuthError::BadSignature => {
            OidcError::invalid_grant("identikey-auth verification failed")
        }
        _ => OidcError::invalid_grant("response is not a valid identikey-auth Response"),
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

fn origin_of(uri: &str) -> Option<String> {
    let parsed = url::Url::parse(uri).ok()?;
    Some(parsed.origin().ascii_serialization())
}

fn loopback_origin_flexible(registered_origin: &str, requested_origin: &str) -> bool {
    fn split(origin: &str) -> Option<(&str, &str)> {
        for host in ["http://127.0.0.1", "http://localhost", "http://[::1]"] {
            if origin == host {
                return Some((host, ""));
            }
            if let Some(rest) = origin.strip_prefix(host)
                && rest.starts_with(':')
            {
                return Some((host, rest));
            }
        }
        None
    }
    match (split(registered_origin), split(requested_origin)) {
        (Some((a, _)), Some((b, _))) => a == b,
        _ => false,
    }
}

fn origin_matches_redirect(redirect: &str, origin: &str) -> bool {
    let Some(registered) = origin_of(redirect) else {
        return false;
    };
    registered == origin || loopback_origin_flexible(&registered, origin)
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

fn refresh_store_error(err: sqlx::Error) -> OidcError {
    tracing::error!(error = %err, "refresh session persistence failed");
    OidcError::server_error("refresh session storage unavailable")
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
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

    fn refresh_request(token: &str) -> TokenRequest {
        TokenRequest {
            grant_type: Some("refresh_token".into()),
            client_id: Some("smoke".into()),
            refresh_token: Some(token.into()),
            ..TokenRequest::default()
        }
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn durable_refresh_survives_restart_rotation_and_revocation(pool: sqlx::PgPool) {
        let p = provider().with_refresh_pool(pool.clone());
        let first = p.mint_tokens("smoke", xid(), None, None).await.unwrap();
        let refresh = first.refresh_token.unwrap();
        let initial_sub = p.introspect(&refresh).await.sub;
        let hash: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM oidc_refresh_sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(hash, hash_token(&refresh));
        assert_ne!(hash, refresh.as_bytes());
        drop(p);

        let restarted = provider().with_refresh_pool(pool.clone());
        assert!(restarted.introspect(&refresh).await.active);
        let mut wrong_client = refresh_request(&refresh);
        wrong_client.client_id = Some("other".into());
        assert_eq!(
            restarted.token(&wrong_client).await.unwrap_err().error,
            "invalid_grant"
        );
        let second = restarted.token(&refresh_request(&refresh)).await.unwrap();
        let rotated = second.refresh_token.unwrap();
        assert_ne!(rotated, refresh);
        assert_eq!(restarted.introspect(&rotated).await.sub, initial_sub);
        assert_eq!(
            restarted
                .token(&refresh_request(&refresh))
                .await
                .unwrap_err()
                .error,
            "invalid_grant"
        );
        drop(restarted);

        let restarted = provider().with_refresh_pool(pool.clone());
        assert!(restarted.introspect(&rotated).await.active);
        restarted.revoke(&rotated).await.unwrap();
        drop(restarted);
        let restarted = provider().with_refresh_pool(pool);
        assert!(!restarted.introspect(&rotated).await.active);
        assert_eq!(
            restarted
                .token(&refresh_request(&rotated))
                .await
                .unwrap_err()
                .error,
            "invalid_grant"
        );
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn durable_refresh_has_one_winner_across_server_instances(pool: sqlx::PgPool) {
        let a = provider().with_refresh_pool(pool.clone());
        let b = provider().with_refresh_pool(pool.clone());
        let first = a.mint_tokens("smoke", xid(), None, None).await.unwrap();
        let refresh = first.refresh_token.unwrap();
        let req = refresh_request(&refresh);
        let (left, right) = tokio::join!(a.token(&req), b.token(&req));
        assert_ne!(left.is_ok(), right.is_ok());
        let winner = left.or(right).unwrap().refresh_token.unwrap();
        assert!(a.introspect(&winner).await.active);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_refresh_sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);

        let mut other_issuer = provider().with_refresh_pool(pool);
        other_issuer.issuer = "https://other.example".into();
        assert!(!other_issuer.introspect(&winner).await.active);
        other_issuer.revoke(&winner).await.unwrap();
        assert!(a.introspect(&winner).await.active);
    }

    #[sqlx::test(migrator = "identikey_keys::MIGRATOR")]
    async fn failed_rotation_preserves_previous_session(pool: sqlx::PgPool) {
        let p = provider().with_refresh_pool(pool.clone());
        let first = p.mint_tokens("smoke", xid(), None, None).await.unwrap();
        let refresh = first.refresh_token.unwrap();
        // Force the single rotation statement to fail after lookup, then repair.
        sqlx::query("ALTER TABLE oidc_refresh_sessions ADD CONSTRAINT reject_rotation CHECK (false) NOT VALID")
            .execute(&pool).await.unwrap();
        assert_eq!(
            p.token(&refresh_request(&refresh)).await.unwrap_err().error,
            "server_error"
        );
        assert!(p.introspect(&refresh).await.active);
        sqlx::query("ALTER TABLE oidc_refresh_sessions DROP CONSTRAINT reject_rotation")
            .execute(&pool)
            .await
            .unwrap();
        assert!(p.token(&refresh_request(&refresh)).await.is_ok());
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

    #[tokio::test]
    async fn code_is_one_time() {
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
            response: None,
            device_code: None,
        };
        let first = p.token(&req).await.unwrap();
        assert!(!first.access_token.is_empty());
        assert_eq!(first.id_token.split('.').count(), 3);
        let second = p.token(&req).await.unwrap_err();
        assert_eq!(second.error, "invalid_grant");
        assert!(p.userinfo(&first.access_token).is_err());
    }

    #[tokio::test]
    async fn pkce_downgrade_refused() {
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
                response: None,
                device_code: None,
            })
            .await
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
                response: None,
                device_code: None,
            })
            .await
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

    #[tokio::test]
    async fn refresh_rotates_and_stores_only_hash() {
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
                response: None,
                device_code: None,
            })
            .await
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
                response: None,
                device_code: None,
            })
            .await
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
                response: None,
                device_code: None,
            })
            .await
            .unwrap_err();
        assert_eq!(replay.error, "invalid_grant");
    }

    #[tokio::test]
    async fn revoked_refresh_is_inactive() {
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
                response: None,
                device_code: None,
            })
            .await
            .unwrap();
        let refresh = issued.refresh_token.unwrap();
        assert!(p.introspect(&refresh).await.active);
        p.revoke(&refresh).await.unwrap();
        assert!(!p.introspect(&refresh).await.active);
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
                response: None,
                device_code: None,
            })
            .await
            .unwrap_err();
        assert_eq!(err.error, "invalid_grant");
    }

    #[test]
    fn spa_origin_matches_redirect_and_loopback_port() {
        let p = provider();
        p.register(
            Client::new("wtnf-web", "worldtree.network")
                .with_redirect("https://worldtree.network/admin/callback/")
                .with_redirect("http://127.0.0.1:5173/admin/callback/"),
        );
        assert!(p.allows_browser_origin("https://worldtree.network"));
        assert!(p.allows_browser_origin("http://127.0.0.1:5173"));
        assert!(p.allows_browser_origin("http://127.0.0.1:5174"));
        assert!(!p.allows_browser_origin("https://evil.example"));
        assert!(!p.allows_browser_origin("http://localhost:5173"));
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

    #[tokio::test]
    async fn wrong_secret_is_refused() {
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
                response: None,
                device_code: None,
            })
            .await
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
                response: None,
                device_code: None,
            })
            .await
            .unwrap();
        assert!(!issued.access_token.is_empty());
    }

    #[tokio::test]
    async fn public_client_still_uses_pkce_only() {
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
                response: None,
                device_code: None,
            })
            .await
            .unwrap();
        assert!(!issued.access_token.is_empty());
    }

    #[tokio::test]
    async fn public_client_sending_secret_is_refused() {
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
                response: None,
                device_code: None,
            })
            .await
            .unwrap_err();
        assert_eq!(err.error, "invalid_client");
    }

    #[tokio::test]
    async fn confidential_still_requires_pkce() {
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
                response: None,
                device_code: None,
            })
            .await
            .unwrap_err();
        assert_eq!(err.error, "invalid_request");
    }

    #[tokio::test]
    async fn client_secret_post_succeeds() {
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
                response: None,
                device_code: None,
            })
            .await
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

    fn allow_urn(p: &Provider) {
        p.register(
            Client::new("smoke", "127.0.0.1")
                .with_redirect("http://127.0.0.1:9999/cb")
                .with_grant(CHALLENGE_RESPONSE_GRANT),
        );
    }

    fn urn_signed(p: &Provider) -> (identikey_auth::SoftwareSigner, String) {
        use identikey_auth::{Challenge, Signer};
        allow_urn(p);
        let signer = identikey_auth::SoftwareSigner::generate_ed25519();
        p.register_subject(&signer.classical_public_key(), xid());
        let chal = Challenge::from_bytes(&p.issue_challenge().unwrap()).unwrap();
        let resp = signer.respond(&chal).unwrap();
        (signer, URL_SAFE_NO_PAD.encode(resp.to_bytes()))
    }

    fn urn_req(encoded: String) -> TokenRequest {
        TokenRequest {
            grant_type: Some(CHALLENGE_RESPONSE_GRANT.into()),
            client_id: Some("smoke".into()),
            response: Some(encoded),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn urn_grant_mints_through_subject_seam() {
        let p = provider();
        let (_signer, encoded) = urn_signed(&p);
        let issued = p.token(&urn_req(encoded)).await.unwrap();
        let expected = subject(
            &PairwiseSalt::from_hex(&"ab".repeat(32)).unwrap(),
            xid(),
            &Client::new("smoke", "127.0.0.1").with_redirect("http://127.0.0.1:9999/cb"),
        )
        .unwrap();
        let info = p.userinfo(&issued.access_token).unwrap();
        assert_eq!(info.sub, expected);
    }

    #[tokio::test]
    async fn urn_grant_refuses_webauthn_assertion() {
        let p = provider();
        allow_urn(&p);
        let fake = URL_SAFE_NO_PAD.encode(
            br#"{"id":"cred","response":{"authenticatorData":"AA","clientDataJSON":"AA","signature":"AA"}}"#,
        );
        let err = p.token(&urn_req(fake)).await.unwrap_err();
        assert_eq!(err.error, "invalid_grant");
    }

    #[tokio::test]
    async fn urn_grant_refuses_nonce_replay() {
        let p = provider();
        let (_signer, encoded) = urn_signed(&p);
        let first = p.token(&urn_req(encoded.clone())).await.unwrap();
        assert!(!first.access_token.is_empty());
        let replay = p.token(&urn_req(encoded)).await.unwrap_err();
        assert_eq!(replay.error, "invalid_grant");
        assert!(replay.description.contains("replay"));
    }

    fn device_request(client_id: &str, device_code: Option<String>) -> TokenRequest {
        TokenRequest {
            grant_type: Some(GRANT_DEVICE_CODE.into()),
            client_id: Some(client_id.into()),
            device_code,
            ..TokenRequest::default()
        }
    }

    fn register_device_client(p: &Provider, id: &str) {
        p.register(
            Client::new(id, "cli.example")
                .with_subject_type(crate::subject::SubjectType::Public)
                .with_display_name("Mjolnir CLI")
                .with_grants([GRANT_DEVICE_CODE, GRANT_REFRESH_TOKEN]),
        );
    }

    #[test]
    fn default_client_cannot_start_a_device_authorization() {
        let p = provider();
        let err = p
            .start_device(
                &TokenRequest {
                    client_id: Some("smoke".into()),
                    ..TokenRequest::default()
                },
                Some("openid"),
            )
            .unwrap_err();
        assert_eq!(err.error, "unauthorized_client");
    }

    #[test]
    fn device_only_client_is_refused_at_authorize_before_redirect_match() {
        let p = provider();
        register_device_client(&p, "headless");
        let err = p
            .validate_authorize(&AuthorizeQuery {
                response_type: Some("code".into()),
                client_id: Some("headless".into()),
                redirect_uri: Some("https://evil.example/cb".into()),
                code_challenge: Some("abc".into()),
                code_challenge_method: Some("S256".into()),
                state: None,
                nonce: None,
                scope: Some("openid".into()),
            })
            .unwrap_err();
        match err {
            AuthorizeError::Deny { error, .. } => assert_eq!(error, "unauthorized_client"),
            other => panic!("expected a deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn device_grant_mints_once_and_matches_the_code_flow_subject() {
        let p = provider();
        p.register(
            Client::new("both", "127.0.0.1")
                .with_redirect("http://127.0.0.1:9999/cb")
                .with_grant(GRANT_DEVICE_CODE),
        );
        let started = p
            .start_device(&device_request("both", None), Some("openid"))
            .unwrap();
        assert_eq!(started.expires_in, 900);
        assert_eq!(started.interval, 5);
        assert!(started.verification_uri.ends_with("/device"));
        assert!(started.verification_uri_complete.contains("user_code="));
        assert!(started.user_code.contains('-'));
        let watched = p.start_device(&device_request("both", None), None).unwrap();
        let pending = p
            .token(&device_request("both", Some(watched.device_code)))
            .await
            .unwrap_err();
        assert_eq!(pending.error, "authorization_pending");

        p.bind_device_assertion(&started.user_code, b"challenge")
            .unwrap();
        let mismatch = p
            .approve_device(&started.user_code, xid(), b"other")
            .unwrap_err();
        assert_eq!(mismatch.error, "invalid_request");
        p.approve_device(&started.user_code, xid(), b"challenge")
            .unwrap();
        let issued = p
            .token(&device_request("both", Some(started.device_code.clone())))
            .await
            .unwrap();
        assert_eq!(issued.expires_in, 3600);
        let again = p
            .token(&device_request("both", Some(started.device_code)))
            .await
            .unwrap_err();
        assert_eq!(again.error, "invalid_grant");

        let expected = subject(
            &PairwiseSalt::from_hex(&"ab".repeat(32)).unwrap(),
            xid(),
            &Client::new("both", "127.0.0.1").with_redirect("http://127.0.0.1:9999/cb"),
        )
        .unwrap();
        assert_eq!(p.userinfo(&issued.access_token).unwrap().sub, expected);
        let payload = issued.id_token.split('.').nth(1).unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(claims["sub"], expected);
        let audience = &claims["aud"];
        assert!(audience == "both" || audience[0] == "both");
        assert_eq!(claims["iss"], "http://127.0.0.1:8080");
        let numeric = |value: &serde_json::Value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().map(|number| number as u64))
                .or_else(|| value.as_f64().map(|number| number as u64))
                .unwrap()
        };
        assert_eq!(numeric(&claims["exp"]) - numeric(&claims["iat"]), 3600);
    }

    #[tokio::test]
    async fn another_client_cannot_redeem_a_device_code() {
        let p = provider();
        register_device_client(&p, "cli");
        register_device_client(&p, "other");
        let started = p.start_device(&device_request("cli", None), None).unwrap();
        let err = p
            .token(&device_request("other", Some(started.device_code)))
            .await
            .unwrap_err();
        assert_eq!(err.error, "invalid_grant");
        let unknown = p
            .start_device(
                &TokenRequest {
                    client_id: Some("missing".into()),
                    ..TokenRequest::default()
                },
                None,
            )
            .unwrap_err();
        assert_eq!(unknown.error, "invalid_client");
    }

    #[tokio::test]
    async fn concurrent_device_polls_issue_one_token() {
        let p = std::sync::Arc::new(provider());
        register_device_client(&p, "cli");
        let started = p.start_device(&device_request("cli", None), None).unwrap();
        p.bind_device_assertion(&started.user_code, b"challenge")
            .unwrap();
        p.approve_device(&started.user_code, xid(), b"challenge")
            .unwrap();
        let req = device_request("cli", Some(started.device_code));
        let first = {
            let p = p.clone();
            let req = req.clone();
            tokio::spawn(async move { p.token(&req).await })
        };
        let second = tokio::spawn(async move { p.token(&req).await });
        let (left, right) = tokio::join!(first, second);
        let results = [left.unwrap(), right.unwrap()];
        let ok = results.iter().filter(|result| result.is_ok()).count();
        assert_eq!(ok, 1);
        assert!(results.iter().any(|result| {
            result
                .as_ref()
                .err()
                .is_some_and(|err| err.error == "invalid_grant")
        }));
    }

    #[tokio::test]
    async fn password_grant_stays_refused() {
        let err = provider()
            .token(&TokenRequest {
                grant_type: Some("password".into()),
                client_id: Some("smoke".into()),
                ..TokenRequest::default()
            })
            .await
            .unwrap_err();
        assert_eq!(err.error, "unsupported_grant_type");
    }

    #[tokio::test]
    async fn urn_grant_without_allowance_is_unauthorized() {
        let p = provider();
        let (_signer, encoded) = {
            use identikey_auth::{Challenge, Signer};
            let signer = identikey_auth::SoftwareSigner::generate_ed25519();
            p.register_subject(&signer.classical_public_key(), xid());
            let chal = Challenge::from_bytes(&p.issue_challenge().unwrap()).unwrap();
            let resp = signer.respond(&chal).unwrap();
            (signer, URL_SAFE_NO_PAD.encode(resp.to_bytes()))
        };
        let err = p.token(&urn_req(encoded)).await.unwrap_err();
        assert_eq!(err.error, "unauthorized_client");
    }
}
