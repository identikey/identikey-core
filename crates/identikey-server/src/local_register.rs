//! Loopback dynamic client registration.
//!
//! `IDENTIKEY_LOCAL_REGISTER=1` mounts `POST /register` and persists clients
//! under the data directory. The process must bind a loopback address, and
//! every redirect URI must be loopback. Env-pinned clients cannot be replaced.
//! Production leaves the flag unset, so `/register` is 404 and discovery does
//! not advertise a registration endpoint.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use identikey_oidc::{
    Client, GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN, KNOWN_GRANTS, Provider, SubjectType,
    TokenEndpointAuthMethod,
};
use serde::{Deserialize, Serialize};

use crate::clients::{RegisteredParts, client_from_registered};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const FILE_VERSION: u32 = 1;
const MAX_REDIRECTS: usize = 8;
const MAX_REDIRECT_LEN: usize = 2048;
const MAX_CLIENT_ID_LEN: usize = 64;
const MAX_NAME_LEN: usize = 128;

#[derive(Clone)]
struct RegState {
    registry: Arc<LocalRegistry>,
    provider: Arc<Provider>,
}

pub struct LocalRegistry {
    path: PathBuf,
    pinned: HashSet<String>,
    lock: Mutex<()>,
}

#[derive(Debug)]
pub struct RegisterFailure {
    status: StatusCode,
    error: &'static str,
    description: std::string::String,
}

impl RegisterFailure {
    fn meta(description: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_client_metadata",
            description: description.to_string(),
        }
    }

    fn reserved(description: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error: "invalid_request",
            description: description.to_string(),
        }
    }

    fn server(description: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "server_error",
            description: description.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RegisterBody {
    client_id: String,
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    grant_types: Option<Vec<String>>,
    #[serde(default)]
    response_types: Option<Vec<String>>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    subject_type: Option<String>,
    #[serde(default)]
    sector_identifier: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterResponse {
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret_expires_at: Option<u64>,
    client_name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    response_types: Vec<&'static str>,
    token_endpoint_auth_method: String,
    subject_type: String,
    sector_identifier: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredClient {
    id: String,
    redirects: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
    auth: String,
    subject_type: String,
    sector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    grants: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct FileDoc {
    version: u32,
    clients: Vec<StoredClient>,
}

struct Outcome {
    created: bool,
    client: Client,
    body: RegisterResponse,
}

/// `IDENTIKEY_LOCAL_REGISTER` enables the registrar only when it is exactly `1`.
pub fn flag_from_env(raw: Option<&str>) -> Result<bool, BoxError> {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(false),
        Some("1") => Ok(true),
        Some(other) => {
            let shown = if other.len() > 16 {
                "a value other than 1"
            } else {
                other
            };
            Err(format!("IDENTIKEY_LOCAL_REGISTER must be unset or exactly 1 (got {shown})").into())
        }
    }
}

/// The registrar is a local test surface. A public bind with the flag set
/// would accept client metadata from anywhere that can reach the port.
pub fn require_loopback_bind(addr: SocketAddr) -> Result<(), BoxError> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(format!(
            "IDENTIKEY_LOCAL_REGISTER=1 refuses to bind {addr}; use a loopback address such as 127.0.0.1:8070"
        )
        .into())
    }
}

impl LocalRegistry {
    pub fn open(path: PathBuf, pinned: HashSet<String>) -> Result<Self, BoxError> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let registry = Self {
            path,
            pinned,
            lock: Mutex::new(()),
        };
        let _clients = registry.read_clients()?;
        Ok(registry)
    }

    pub fn load_into(&self, provider: &Provider) -> Result<usize, BoxError> {
        let clients = self.read_clients()?;
        let count = clients.len();
        for client in clients {
            provider.register(client);
        }
        Ok(count)
    }

    fn upsert(&self, body: &RegisterBody) -> Result<Outcome, RegisterFailure> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| RegisterFailure::server("local registry lock poisoned"))?;
        let mut doc = self.read_doc().map_err(RegisterFailure::server)?;
        let previous = doc
            .clients
            .iter()
            .find(|client| client.id == body.client_id)
            .cloned();
        let created = previous.is_none();
        let stored = materialize(body, &self.pinned, previous.as_ref())?;
        let client = client_from_registered(parts_from(&stored))
            .map_err(|err| RegisterFailure::meta(err.to_string()))?;
        if let Some(slot) = doc.clients.iter_mut().find(|client| client.id == stored.id) {
            *slot = stored.clone();
        } else {
            doc.clients.push(stored.clone());
        }
        self.write_doc(&doc).map_err(RegisterFailure::server)?;
        let body = response_from(&stored);
        Ok(Outcome {
            created,
            client,
            body,
        })
    }

    fn read_clients(&self) -> Result<Vec<Client>, BoxError> {
        let doc = self.read_doc()?;
        let mut seen = HashSet::new();
        let mut clients = Vec::new();
        for stored in doc.clients {
            if !seen.insert(stored.id.clone()) {
                return Err(format!("duplicate local client id {}", stored.id).into());
            }
            if self.pinned.contains(&stored.id) {
                return Err(format!(
                    "local client {} collides with an env-registered client",
                    stored.id
                )
                .into());
            }
            audit_stored(&stored)?;
            clients.push(client_from_registered(parts_from(&stored))?);
        }
        Ok(clients)
    }

    fn read_doc(&self) -> Result<FileDoc, BoxError> {
        if !self.path.exists() {
            return Ok(FileDoc {
                version: FILE_VERSION,
                clients: Vec::new(),
            });
        }
        let text = fs::read_to_string(&self.path)?;
        let doc: FileDoc = serde_json::from_str(&text).map_err(|err| {
            format!(
                "{} is not a local client registry: {err}",
                self.path.display()
            )
        })?;
        if doc.version != FILE_VERSION {
            return Err(format!(
                "{} has registry version {}, expected {FILE_VERSION}",
                self.path.display(),
                doc.version
            )
            .into());
        }
        Ok(doc)
    }

    fn write_doc(&self, doc: &FileDoc) -> Result<(), BoxError> {
        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&tmp)?;
            let mut bytes = serde_json::to_vec_pretty(doc)?;
            bytes.push(b'\n');
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

pub fn router(registry: Arc<LocalRegistry>, provider: Arc<Provider>) -> Router {
    Router::new()
        .route("/register", post(register))
        .with_state(RegState { registry, provider })
}

async fn register(State(state): State<RegState>, Json(body): Json<RegisterBody>) -> Response {
    match state.registry.upsert(&body) {
        Ok(outcome) => {
            tracing::info!(
                client_id = %outcome.body.client_id,
                created = outcome.created,
                "registered local OIDC client"
            );
            state.provider.register(outcome.client);
            let status = if outcome.created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            let mut response = (status, Json(outcome.body)).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(err) => {
            let mut response = (
                err.status,
                Json(serde_json::json!({
                    "error": err.error,
                    "error_description": err.description,
                })),
            )
                .into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
    }
}

fn parts_from(stored: &StoredClient) -> RegisteredParts {
    RegisteredParts {
        id: stored.id.clone(),
        redirects: stored.redirects.clone(),
        secret: stored.secret.clone(),
        auth: Some(stored.auth.clone()),
        subject_type: Some(stored.subject_type.clone()),
        sector: Some(stored.sector.clone()),
        name: stored.name.clone(),
        grants: Some(stored.grants.clone()),
    }
}

fn response_from(stored: &StoredClient) -> RegisterResponse {
    let confidential = stored.auth != TokenEndpointAuthMethod::None.as_str();
    RegisterResponse {
        client_id: stored.id.clone(),
        client_secret_expires_at: confidential.then_some(0),
        client_secret: if confidential {
            stored.secret.clone()
        } else {
            None
        },
        client_name: stored.name.clone().unwrap_or_else(|| stored.id.clone()),
        redirect_uris: stored.redirects.clone(),
        grant_types: stored.grants.clone(),
        response_types: vec!["code"],
        token_endpoint_auth_method: stored.auth.clone(),
        subject_type: stored.subject_type.clone(),
        sector_identifier: stored.sector.clone(),
    }
}

fn materialize(
    body: &RegisterBody,
    pinned: &HashSet<String>,
    previous: Option<&StoredClient>,
) -> Result<StoredClient, RegisterFailure> {
    if !valid_client_id(&body.client_id) {
        return Err(RegisterFailure::meta(
            "client_id must be 1-64 characters of ASCII letters, digits, '.', '_' or '-'",
        ));
    }
    if pinned.contains(&body.client_id) {
        return Err(RegisterFailure::reserved(format!(
            "client_id {} is reserved by the server configuration",
            body.client_id
        )));
    }
    if let Some(types) = &body.response_types {
        if types.is_empty() || types.iter().any(|value| value != "code") {
            return Err(RegisterFailure::meta(
                "only response_types code is supported",
            ));
        }
    }
    if let Some(scope) = &body.scope {
        let mut tokens = scope.split_whitespace();
        if tokens.any(|token| token != "openid") {
            return Err(RegisterFailure::meta("only scope openid is supported"));
        }
    }
    let grants = normalize_grants(body.grant_types.as_deref())?;
    let redirects = normalize_redirects(&body.redirect_uris)?;
    if grants.iter().any(|grant| grant == GRANT_AUTHORIZATION_CODE) && redirects.is_empty() {
        return Err(RegisterFailure::meta(
            "authorization_code requires at least one redirect_uri",
        ));
    }
    let subject = match body
        .subject_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        None => SubjectType::Public,
        Some(raw) => SubjectType::parse(raw).map_err(RegisterFailure::meta)?,
    };
    let sector = choose_sector(
        subject,
        body.sector_identifier.as_deref(),
        &redirects,
        &body.client_id,
    )?;
    let auth = match body
        .token_endpoint_auth_method
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        None => TokenEndpointAuthMethod::None,
        Some(raw) => TokenEndpointAuthMethod::parse(raw).map_err(RegisterFailure::meta)?,
    };
    let name = match body
        .client_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        None => None,
        Some(name) if name.len() > MAX_NAME_LEN || name.chars().any(char::is_control) => {
            return Err(RegisterFailure::meta(
                "client_name must be at most 128 characters without control characters",
            ));
        }
        Some(name) => Some(name.to_owned()),
    };
    let secret = choose_secret(auth, body.client_secret.as_deref(), previous)?;
    let stored = StoredClient {
        id: body.client_id.clone(),
        redirects,
        secret,
        auth: auth.as_str().to_owned(),
        subject_type: subject.as_str().to_owned(),
        sector,
        name,
        grants,
    };
    audit_stored(&stored).map_err(RegisterFailure::meta)?;
    Ok(stored)
}

fn choose_sector(
    subject: SubjectType,
    requested: Option<&str>,
    redirects: &[String],
    client_id: &str,
) -> Result<String, RegisterFailure> {
    let requested = requested.map(str::trim).filter(|value| !value.is_empty());
    let hosts = redirect_hosts(redirects)?;
    match subject {
        SubjectType::Pairwise => {
            if hosts.iter().any(|host| hosts.first() != Some(host)) {
                return Err(RegisterFailure::meta(
                    "pairwise redirects must share one host",
                ));
            }
            if let Some(host) = hosts.first() {
                match requested {
                    None => Ok(host.clone()),
                    Some(sector) if canonical_name(sector) == *host => Ok(host.clone()),
                    Some(_) => Err(RegisterFailure::meta(
                        "pairwise sector_identifier must match the redirect host",
                    )),
                }
            } else {
                match requested {
                    Some(sector) if is_loopback_name(&canonical_name(sector)) => {
                        Ok(canonical_name(sector))
                    }
                    _ => Err(RegisterFailure::meta(
                        "pairwise registration without a redirect requires a loopback sector_identifier",
                    )),
                }
            }
        }
        SubjectType::Public => match requested {
            None => Ok(client_id.to_owned()),
            Some(sector) if sector == client_id => Ok(client_id.to_owned()),
            Some(sector) if hosts.iter().any(|host| host == &canonical_name(sector)) => {
                Ok(canonical_name(sector))
            }
            Some(_) => Err(RegisterFailure::meta(
                "public sector_identifier must be the client_id or a loopback redirect host",
            )),
        },
    }
}

fn redirect_hosts(redirects: &[String]) -> Result<Vec<String>, RegisterFailure> {
    let mut hosts = Vec::new();
    for uri in redirects {
        let host = host_of(uri)?;
        if !hosts.iter().any(|existing| existing == &host) {
            hosts.push(host);
        }
    }
    Ok(hosts)
}

fn choose_secret(
    auth: TokenEndpointAuthMethod,
    requested: Option<&str>,
    previous: Option<&StoredClient>,
) -> Result<Option<String>, RegisterFailure> {
    let requested = requested.filter(|secret| !secret.is_empty());
    if auth == TokenEndpointAuthMethod::None {
        if requested.is_some() {
            return Err(RegisterFailure::meta(
                "public client (token_endpoint_auth_method=none) must not have a secret",
            ));
        }
        return Ok(None);
    }
    if let Some(secret) = requested {
        vet_secret(secret)?;
        return Ok(Some(secret.to_owned()));
    }
    if let Some(secret) = previous.and_then(|client| client.secret.clone()) {
        return Ok(Some(secret));
    }
    Ok(Some(new_secret()))
}

fn vet_secret(secret: &str) -> Result<(), RegisterFailure> {
    if !(16..=256).contains(&secret.len())
        || secret.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(RegisterFailure::meta(
            "client_secret must be 16-256 characters without whitespace",
        ));
    }
    Ok(())
}

fn normalize_grants(grants: Option<&[String]>) -> Result<Vec<String>, RegisterFailure> {
    let Some(grants) = grants else {
        return Ok(vec![
            GRANT_AUTHORIZATION_CODE.to_owned(),
            GRANT_REFRESH_TOKEN.to_owned(),
        ]);
    };
    if grants.is_empty() {
        return Err(RegisterFailure::meta("grant_types must not be empty"));
    }
    let mut out = Vec::new();
    for grant in grants {
        if !KNOWN_GRANTS.contains(&grant.as_str()) {
            return Err(RegisterFailure::meta(format!("unknown grant_type {grant}")));
        }
        if !out.iter().any(|existing| existing == grant) {
            out.push(grant.clone());
        }
    }
    Ok(out)
}

fn normalize_redirects(uris: &[String]) -> Result<Vec<String>, RegisterFailure> {
    if uris.len() > MAX_REDIRECTS {
        return Err(RegisterFailure::meta(format!(
            "at most {MAX_REDIRECTS} redirect URIs"
        )));
    }
    let mut out = Vec::new();
    for uri in uris {
        if uri.len() > MAX_REDIRECT_LEN {
            return Err(RegisterFailure::meta("redirect_uri is too long"));
        }
        vet_redirect(uri)?;
        if !out.iter().any(|existing| existing == uri) {
            out.push(uri.clone());
        }
    }
    Ok(out)
}

fn vet_redirect(uri: &str) -> Result<(), RegisterFailure> {
    let url = url::Url::parse(uri)
        .map_err(|_| RegisterFailure::meta(format!("redirect_uri is not a URI: {uri}")))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(RegisterFailure::meta("redirect_uri must use http or https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(RegisterFailure::meta(
            "redirect_uri must not contain userinfo",
        ));
    }
    if url.fragment().is_some() {
        return Err(RegisterFailure::meta(
            "redirect_uri must not contain a fragment",
        ));
    }
    let host = host_of(uri)?;
    if !is_loopback_name(&host) {
        return Err(RegisterFailure::meta(format!(
            "local registration only accepts loopback redirect URIs ({uri})"
        )));
    }
    Ok(())
}

fn audit_stored(stored: &StoredClient) -> Result<(), String> {
    vet_stored(stored)?;
    let subject = SubjectType::parse(&stored.subject_type)?;
    let hosts = stored
        .redirects
        .iter()
        .map(|uri| host_of(uri).map_err(|err| err.description))
        .collect::<Result<Vec<_>, _>>()?;
    match subject {
        SubjectType::Pairwise => {
            if hosts.iter().any(|host| hosts.first() != Some(host)) {
                return Err("pairwise local client redirects must share one host".into());
            }
            if let Some(host) = hosts.first() {
                if canonical_name(&stored.sector) != *host {
                    return Err(format!(
                        "pairwise local client {} sector does not match its redirect host",
                        stored.id
                    ));
                }
            } else if !is_loopback_name(&canonical_name(&stored.sector)) {
                return Err(format!(
                    "pairwise local client {} requires a loopback sector",
                    stored.id
                ));
            }
        }
        SubjectType::Public => {
            let sector_ok = stored.sector == stored.id
                || hosts
                    .iter()
                    .any(|host| host == &canonical_name(&stored.sector));
            if !sector_ok {
                return Err(format!(
                    "public local client {} has a sector outside its client_id and redirect hosts",
                    stored.id
                ));
            }
        }
    }
    if stored
        .grants
        .iter()
        .any(|grant| grant == GRANT_AUTHORIZATION_CODE)
        && stored.redirects.is_empty()
    {
        return Err("authorization_code requires a redirect".into());
    }
    Ok(())
}

fn vet_stored(stored: &StoredClient) -> Result<(), String> {
    if !valid_client_id(&stored.id) {
        return Err(format!("invalid local client id {}", stored.id));
    }
    TokenEndpointAuthMethod::parse(&stored.auth)?;
    SubjectType::parse(&stored.subject_type)?;
    if stored.auth == TokenEndpointAuthMethod::None.as_str() && stored.secret.is_some() {
        return Err("public local client must not store a secret".into());
    }
    if stored.auth != TokenEndpointAuthMethod::None.as_str() && stored.secret.is_none() {
        return Err(format!(
            "confidential local client {} is missing a secret",
            stored.id
        ));
    }
    for uri in &stored.redirects {
        vet_redirect(uri).map_err(|err| err.description)?;
    }
    for grant in &stored.grants {
        if !KNOWN_GRANTS.contains(&grant.as_str()) {
            return Err(format!("unknown grant_type {grant}"));
        }
    }
    Ok(())
}

fn host_of(uri: &str) -> Result<String, RegisterFailure> {
    let url = url::Url::parse(uri)
        .map_err(|_| RegisterFailure::meta(format!("redirect_uri is not a URI: {uri}")))?;
    url.host_str()
        .map(canonical_name)
        .ok_or_else(|| RegisterFailure::meta("redirect_uri is missing a host"))
}

fn canonical_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn is_loopback_name(host: &str) -> bool {
    if host == "localhost" || host == "::1" {
        return true;
    }
    host.parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| ip.is_loopback())
        || host
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn valid_client_id(id: &str) -> bool {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    id.len() <= MAX_CLIENT_ID_LEN
        && !id.contains("..")
        && first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn new_secret() -> String {
    use base64::Engine;
    let first = uuid::Uuid::new_v4().into_bytes();
    let second = uuid::Uuid::new_v4().into_bytes();
    let mut bytes = [0_u8; 32];
    for (slot, byte) in bytes.iter_mut().zip(first.into_iter().chain(second)) {
        *slot = byte;
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;
    use axum::body::{self, Body};
    use axum::http::Request;
    use identikey_oidc::{AuthorizeQuery, PairwiseSalt, s256_challenge};
    use tower::ServiceExt;

    fn registry(pinned: &[&str]) -> (Arc<LocalRegistry>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("identikey-local-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("local-clients.json");
        let pinned = pinned.iter().map(|id| (*id).to_owned()).collect();
        let registry = Arc::new(LocalRegistry::open(path, pinned).unwrap());
        (registry, dir)
    }

    fn provider() -> Arc<Provider> {
        let salt = PairwiseSalt::from_hex(&"ab".repeat(32)).unwrap();
        Arc::new(Provider::generate("http://127.0.0.1:8070", salt).unwrap())
    }

    fn must_fail(result: Result<Outcome, RegisterFailure>) -> RegisterFailure {
        match result {
            Ok(_) => panic!("registration succeeded"),
            Err(err) => err,
        }
    }

    fn public_body(id: &str, redirect: &str) -> RegisterBody {
        RegisterBody {
            client_id: id.to_owned(),
            client_name: Some("Lightning Mesh".into()),
            redirect_uris: vec![redirect.to_owned()],
            grant_types: None,
            response_types: None,
            token_endpoint_auth_method: None,
            subject_type: None,
            sector_identifier: None,
            client_secret: None,
            scope: None,
        }
    }

    #[test]
    fn flag_is_exactly_one() {
        assert!(!flag_from_env(None).unwrap());
        assert!(!flag_from_env(Some("")).unwrap());
        assert!(flag_from_env(Some("1")).unwrap());
        assert!(flag_from_env(Some(" 1 ")).unwrap());
        assert!(flag_from_env(Some("true")).is_err());
        assert!(flag_from_env(Some("0")).is_err());
    }

    #[test]
    fn registrar_refuses_a_public_bind() {
        let loopback: SocketAddr = "127.0.0.1:8070".parse().unwrap();
        let v6: SocketAddr = "[::1]:8070".parse().unwrap();
        let open: SocketAddr = "0.0.0.0:8070".parse().unwrap();
        assert!(require_loopback_bind(loopback).is_ok());
        assert!(require_loopback_bind(v6).is_ok());
        assert!(require_loopback_bind(open).is_err());
    }

    #[test]
    fn rejects_a_public_redirect_and_a_pinned_id() {
        let (registry, dir) = registry(&["smoke"]);
        let err = must_fail(
            registry.upsert(&public_body("mesh", "https://taskmaster.dev/auth/callback")),
        );
        assert_eq!(err.error, "invalid_client_metadata");
        let err = must_fail(registry.upsert(&public_body("smoke", "http://127.0.0.1:9/cb")));
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert!(!registry.path.exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn persists_a_loopback_client_and_reloads_it() {
        let (registry, dir) = registry(&[]);
        let op = provider();
        let created = registry
            .upsert(&public_body(
                "lightning-mesh",
                "http://127.0.0.1:3000/callback",
            ))
            .unwrap();
        assert!(created.created);
        assert!(created.body.client_secret.is_none());
        assert_eq!(created.body.subject_type, "public");
        assert_eq!(created.body.sector_identifier, "lightning-mesh");
        op.register(created.client);

        let again = registry
            .upsert(&public_body(
                "lightning-mesh",
                "http://localhost:3000/callback",
            ))
            .unwrap();
        assert!(!again.created);
        op.register(again.client);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&registry.path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0);
        }

        let reloaded = provider();
        let count = LocalRegistry::open(registry.path.clone(), HashSet::new())
            .unwrap()
            .load_into(&reloaded)
            .unwrap();
        assert_eq!(count, 1);
        let pending = reloaded
            .validate_authorize(&AuthorizeQuery {
                response_type: Some("code".into()),
                client_id: Some("lightning-mesh".into()),
                redirect_uri: Some("http://localhost:3000/callback".into()),
                code_challenge: Some(s256_challenge("verifier-verifier-verifier-verifier")),
                code_challenge_method: Some("S256".into()),
                state: None,
                nonce: None,
                scope: Some("openid".into()),
            })
            .unwrap();
        assert_eq!(pending.client_id, "lightning-mesh");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn confidential_secret_is_stable_across_updates() {
        let (registry, dir) = registry(&[]);
        let mut body = public_body("basic-local", "http://127.0.0.1:8443/callback");
        body.token_endpoint_auth_method = Some("client_secret_basic".into());
        let created = registry.upsert(&body).unwrap();
        let secret = created.body.client_secret.clone().unwrap();
        assert!(secret.len() >= 16);
        body.client_name = Some("renamed".into());
        let updated = registry.upsert(&body).unwrap();
        assert_eq!(updated.body.client_secret.as_deref(), Some(secret.as_str()));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn post_register_creates_then_updates() {
        let (registry, dir) = registry(&[]);
        let app = router(registry, provider());
        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"client_id":"lightning-mesh","redirect_uris":["http://127.0.0.1:3000/callback"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        assert_eq!(
            first.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let created: serde_json::Value =
            serde_json::from_slice(&body::to_bytes(first.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(created["client_id"], "lightning-mesh");
        assert!(created.get("client_secret").is_none());

        let second = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"client_id":"lightning-mesh","redirect_uris":["http://127.0.0.1:3000/callback"],"scope":"profile"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::BAD_REQUEST);
        let _ = fs::remove_dir_all(dir);
    }
}
