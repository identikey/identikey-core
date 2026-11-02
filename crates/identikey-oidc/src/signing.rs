//! OP token-signing key (EdDSA / Ed25519). Not a user key.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use josekit::jwk::alg::ed::EdCurve;
use josekit::jwk::{Jwk, JwkSet, KeyPair};
use josekit::jws::{EdDSA, JwsHeader};
use josekit::jwt::{self, JwtPayload};

const FILE_NAME: &str = "signing.jwk";
const RETIRING_FILE: &str = "signing-retiring.json";
// ID tokens use the provider's ACCESS_TTL (3600 seconds).
const OVERLAP: Duration = Duration::from_secs(3600);

#[derive(Clone)]
pub struct SigningKey {
    state: Arc<RwLock<SigningState>>,
    // Environment keys remain externally managed; rotation requires file storage.
    data_dir: Option<PathBuf>,
}

struct SigningState {
    jwk: Jwk,
    retiring: Vec<RetiringKey>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct RetiringKey {
    public: Jwk,
    retired_at: SystemTime,
}

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("IDENTIKEY_SIGNING_KEY is empty or not an Ed25519 private JWK")]
    BadKey,
    #[error("rotation requires a file-backed signing key")]
    NotFileBacked,
    #[error("signing key state lock poisoned")]
    Poisoned,
    #[error("could not generate signing key: {0}")]
    Entropy(String),
    #[error("signing key file: {0}")]
    Io(#[from] std::io::Error),
    #[error("jose: {0}")]
    Jose(String),
}

impl SigningKey {
    pub fn generate() -> Result<Self, SigningError> {
        let mut pair = EdDSA
            .generate_key_pair(EdCurve::Ed25519)
            .map_err(|e| SigningError::Entropy(e.to_string()))?;
        let kid = random_kid()?;
        pair.set_key_id(Some(kid));
        pair.set_algorithm(Some("EdDSA"));
        let mut jwk = pair.to_jwk_key_pair();
        jwk.set_key_use("sig");
        jwk.set_algorithm("EdDSA");
        Ok(Self::new(jwk))
    }

    pub fn from_jwk_json(raw: &str) -> Result<Self, SigningError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(SigningError::BadKey);
        }
        let jwk = Jwk::from_bytes(trimmed.as_bytes()).map_err(|_| SigningError::BadKey)?;
        if jwk.key_type() != "OKP" {
            return Err(SigningError::BadKey);
        }
        if jwk.curve() != Some("Ed25519") {
            return Err(SigningError::BadKey);
        }
        // Must be able to sign — a public-only JWK is not an OP signing key.
        EdDSA
            .signer_from_jwk(&jwk)
            .map_err(|_| SigningError::BadKey)?;
        Ok(Self::new(jwk))
    }

    /// Env wins when set. Otherwise read or create `data_dir/signing.jwk`.
    pub fn load(env: Option<&str>, data_dir: &Path) -> Result<Self, SigningError> {
        match env {
            Some(raw) => Self::from_jwk_json(raw),
            None => load_or_create(data_dir),
        }
    }

    fn new(jwk: Jwk) -> Self {
        Self {
            state: Arc::new(RwLock::new(SigningState {
                jwk,
                retiring: Vec::new(),
            })),
            data_dir: None,
        }
    }

    #[must_use]
    pub fn kid(&self) -> Option<String> {
        self.state.read().ok()?.jwk.key_id().map(str::to_owned)
    }

    #[must_use]
    pub fn public_jwks(&self) -> JwkSet {
        self.public_jwks_at(SystemTime::now())
    }

    fn public_jwks_at(&self, now: SystemTime) -> JwkSet {
        let mut set = JwkSet::new();
        if let Ok(state) = self.state.read() {
            if let Ok(public) = public_key(&state.jwk) {
                set.push_key(public);
            }
            for retired in &state.retiring {
                if retired.public.key_id() != state.jwk.key_id() && in_overlap(retired, now) {
                    set.push_key(retired.public.clone());
                }
            }
        }
        set
    }

    /// Publish and persist a new signing key, retaining public verification keys
    /// for every still-valid ID token. Clones share the cutover. Callers must
    /// reload file-backed keys after restart; environment keys are not rotated.
    pub fn rotate(&self) -> Result<(), SigningError> {
        self.rotate_at(None)
    }

    fn rotate_at(&self, now: Option<SystemTime>) -> Result<(), SigningError> {
        let dir = self.data_dir.as_ref().ok_or(SigningError::NotFileBacked)?;
        let next = Self::generate()?;
        let next = next.state.read().map_err(|_| SigningError::Poisoned)?;
        let mut state = self.state.write().map_err(|_| SigningError::Poisoned)?;
        let now = now.unwrap_or_else(SystemTime::now);
        // The write lock drains in-flight signatures and blocks new ones until
        // both disk records and the published key set are ready.
        let mut retiring: Vec<_> = state
            .retiring
            .iter()
            .filter(|key| in_overlap(key, now) && key.public.key_id() != state.jwk.key_id())
            .cloned()
            .collect();
        retiring.push(RetiringKey {
            public: public_key(&state.jwk)?,
            retired_at: now,
        });
        let record =
            serde_json::to_vec(&retiring).map_err(|e| SigningError::Jose(e.to_string()))?;
        replace_file(&dir.join(RETIRING_FILE), &record)?;
        // Make the retiring record durable before committing the new signer.
        fs::File::open(dir)?.sync_all()?;
        replace_file(&dir.join(FILE_NAME), next.jwk.to_string().as_bytes())?;
        // JWKS includes the new key at the cut, before any caller can sign with
        // it. No old private key is kept in the retiring record or state.
        state.retiring = retiring;
        state.jwk = next.jwk.clone();
        fs::File::open(dir)?.sync_all()?;
        Ok(())
    }

    pub fn sign_id_token(
        &self,
        issuer: &str,
        audience: &str,
        sub: &str,
        nonce: Option<&str>,
        ttl_secs: u64,
    ) -> Result<String, SigningError> {
        let state = self.state.read().map_err(|_| SigningError::Poisoned)?;
        let signer = EdDSA
            .signer_from_jwk(&state.jwk)
            .map_err(|e| SigningError::Jose(e.to_string()))?;
        let mut header = JwsHeader::new();
        header.set_algorithm("EdDSA");
        if let Some(kid) = state.jwk.key_id() {
            header.set_key_id(kid);
        }
        let now = std::time::SystemTime::now();
        let exp = now + std::time::Duration::from_secs(ttl_secs);
        let mut payload = JwtPayload::new();
        payload.set_issuer(issuer);
        payload.set_subject(sub);
        payload.set_audience(vec![audience]);
        payload.set_issued_at(&now);
        payload.set_expires_at(&exp);
        if let Some(nonce) = nonce {
            payload
                .set_claim("nonce", Some(josekit::Value::String(nonce.to_owned())))
                .map_err(|e| SigningError::Jose(e.to_string()))?;
        }
        jwt::encode_with_signer(&payload, &header, &signer)
            .map_err(|e| SigningError::Jose(e.to_string()))
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey([redacted])")
    }
}

fn random_kid() -> Result<String, SigningError> {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).map_err(|e| SigningError::Entropy(e.to_string()))?;
    let mut hex = String::with_capacity(16);
    for byte in bytes {
        let _ = fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}"));
    }
    Ok(hex)
}

fn public_key(jwk: &Jwk) -> Result<Jwk, SigningError> {
    let mut public = jwk
        .to_public_key()
        .map_err(|e| SigningError::Jose(e.to_string()))?;
    if let Some(kid) = jwk.key_id() {
        public.set_key_id(kid);
    }
    public.set_algorithm("EdDSA");
    public.set_key_use("sig");
    Ok(public)
}

fn in_overlap(key: &RetiringKey, now: SystemTime) -> bool {
    now.duration_since(key.retired_at)
        .map_or(true, |age| age < OVERLAP)
}

fn load_or_create(data_dir: &Path) -> Result<SigningKey, SigningError> {
    let path = data_dir.join(FILE_NAME);
    let mut key = if path.exists() {
        SigningKey::from_jwk_json(&fs::read_to_string(&path)?)?
    } else {
        fs::create_dir_all(data_dir)?;
        let key = SigningKey::generate()?;
        let state = key.state.read().map_err(|_| SigningError::Poisoned)?;
        write_private(&path, state.jwk.to_string().as_bytes())?;
        drop(state);
        key
    };
    let retiring = match fs::read(data_dir.join(RETIRING_FILE)) {
        Ok(bytes) => serde_json::from_slice::<Vec<RetiringKey>>(&bytes)
            .map_err(|e| SigningError::Jose(e.to_string()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    // Validate and sanitize persisted records so even a malformed record can
    // never expose private material through JWKS.
    let mut state = key.state.write().map_err(|_| SigningError::Poisoned)?;
    for retired in retiring {
        if retired.public.key_type() != "OKP" || retired.public.curve() != Some("Ed25519") {
            return Err(SigningError::BadKey);
        }
        state.retiring.push(RetiringKey {
            public: public_key(&retired.public)?,
            retired_at: retired.retired_at,
        });
    }
    drop(state);
    key.data_dir = Some(data_dir.to_owned());
    Ok(key)
}

fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), SigningError> {
    let temporary = path.with_extension(format!("{}.tmp", random_kid()?));
    let result = (|| {
        write_private(&temporary, bytes)?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    let _ = fs::remove_file(&temporary);
    result
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), SigningError> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch() -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("identikey-signing-{n}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn generate_signs_and_jwks_has_no_private() {
        let key = SigningKey::generate().unwrap();
        let jwt = key
            .sign_id_token("http://iss", "client", "subvalue", Some("n"), 60)
            .unwrap();
        assert_eq!(jwt.split('.').count(), 3);
        let jwks = key.public_jwks().to_string();
        assert!(jwks.contains("Ed25519"));
        assert!(jwks.contains("EdDSA"));
        assert!(!jwks.contains("\"d\""));
    }

    #[test]
    fn load_persists() {
        let dir = scratch();
        let first = SigningKey::load(None, &dir).unwrap();
        let second = SigningKey::load(None, &dir).unwrap();
        assert_eq!(first.kid(), second.kid());
        fs::remove_dir_all(&dir).unwrap();
    }

    fn token(key: &SigningKey) -> String {
        key.sign_id_token("http://iss", "client", "sub", None, 3600)
            .unwrap()
    }

    fn verify_with_published_key(key: &SigningKey, token: &str, kid: &str) {
        let set = key.public_jwks();
        let public = set
            .keys()
            .into_iter()
            .find(|jwk| jwk.key_id() == Some(kid))
            .unwrap();
        let verifier = EdDSA.verifier_from_jwk(public).unwrap();
        let (_, header) = jwt::decode_with_verifier(token, &verifier).unwrap();
        assert_eq!(header.key_id(), Some(kid));
    }

    #[test]
    fn signing_rotation_publishes_new_signer_and_survives_restart_without_old_private_key() {
        let dir = scratch();
        let key = SigningKey::load(None, &dir).unwrap();
        let clone = key.clone();
        let old_kid = key.kid().unwrap();
        let old_token = token(&key);
        key.rotate().unwrap();
        let new_kid = key.kid().unwrap();
        assert_ne!(new_kid, old_kid);
        assert_eq!(clone.kid(), Some(new_kid.clone()));
        assert_eq!(key.public_jwks().keys().len(), 2);
        verify_with_published_key(&key, &old_token, &old_kid);
        verify_with_published_key(&key, &token(&clone), &new_kid);
        let record = fs::read_to_string(dir.join(RETIRING_FILE)).unwrap();
        assert!(!record.contains("\"d\""));
        let current = fs::read_to_string(dir.join(FILE_NAME)).unwrap();
        assert!(!current.contains(&old_kid));
        drop(key);
        drop(clone);
        let reloaded = SigningKey::load(None, &dir).unwrap();
        assert_eq!(reloaded.kid(), Some(new_kid.clone()));
        assert_eq!(reloaded.public_jwks().keys().len(), 2);
        verify_with_published_key(&reloaded, &old_token, &old_kid);
        verify_with_published_key(&reloaded, &token(&reloaded), &new_kid);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn signing_rotation_expires_at_3600_seconds_including_after_restart() {
        let dir = scratch();
        let key = SigningKey::load(None, &dir).unwrap();
        let cut = SystemTime::now();
        key.rotate_at(Some(cut)).unwrap();
        let reloaded = SigningKey::load(None, &dir).unwrap();
        for handle in [&key, &reloaded] {
            assert_eq!(
                handle
                    .public_jwks_at(cut + OVERLAP - Duration::from_nanos(1))
                    .keys()
                    .len(),
                2
            );
            let set = handle.public_jwks_at(cut + OVERLAP);
            assert_eq!(set.keys().len(), 1);
            assert_eq!(set.keys()[0].key_id(), handle.kid().as_deref());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn signing_rotation_retiring_persist_failure_preserves_signer() {
        let dir = scratch();
        let key = SigningKey::load(None, &dir).unwrap();
        let kid = key.kid().unwrap();
        let private_before = fs::read(dir.join(FILE_NAME)).unwrap();
        fs::create_dir(dir.join(RETIRING_FILE)).unwrap();
        assert!(key.rotate().is_err());
        assert_eq!(key.kid(), Some(kid.clone()));
        assert_eq!(fs::read(dir.join(FILE_NAME)).unwrap(), private_before);
        assert_eq!(key.public_jwks().keys().len(), 1);
        verify_with_published_key(&key, &token(&key), &kid);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn signing_rotation_current_persist_failure_preserves_signer() {
        let dir = scratch();
        let key = SigningKey::load(None, &dir).unwrap();
        let kid = key.kid().unwrap();
        fs::remove_file(dir.join(FILE_NAME)).unwrap();
        fs::create_dir(dir.join(FILE_NAME)).unwrap();
        assert!(key.rotate().is_err());
        assert_eq!(key.kid(), Some(kid.clone()));
        verify_with_published_key(&key, &token(&key), &kid);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn signing_rotation_preserves_salt_bytes_and_file() {
        let dir = scratch();
        let salt = crate::salt::PairwiseSalt::load(None, &dir).unwrap();
        let bytes = *salt.as_bytes();
        let file = fs::read(dir.join("pairwise.salt")).unwrap();
        let key = SigningKey::load(None, &dir).unwrap();
        key.rotate().unwrap();
        assert_eq!(*salt.as_bytes(), bytes);
        assert_eq!(fs::read(dir.join("pairwise.salt")).unwrap(), file);
        assert_eq!(
            *crate::salt::PairwiseSalt::load(None, &dir)
                .unwrap()
                .as_bytes(),
            bytes
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn signing_rotation_repeated_cuts_keep_all_unexpired_public_keys() {
        let dir = scratch();
        let key = SigningKey::load(None, &dir).unwrap();
        let first_kid = key.kid().unwrap();
        let first_token = token(&key);
        key.rotate().unwrap();
        let second_kid = key.kid().unwrap();
        let second_token = token(&key);
        key.rotate().unwrap();
        let reloaded = SigningKey::load(None, &dir).unwrap();
        assert_eq!(reloaded.public_jwks().keys().len(), 3);
        verify_with_published_key(&reloaded, &first_token, &first_kid);
        verify_with_published_key(&reloaded, &second_token, &second_kid);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn signing_rotation_rejects_externally_managed_env_keys() {
        let dir = scratch();
        let file_key = SigningKey::load(None, &dir).unwrap();
        let raw = fs::read_to_string(dir.join(FILE_NAME)).unwrap();
        let env_key = SigningKey::load(Some(&raw), &dir).unwrap();
        assert!(matches!(env_key.rotate(), Err(SigningError::NotFileBacked)));
        assert_eq!(env_key.kid(), file_key.kid());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn debug_is_redacted() {
        let key = SigningKey::generate().unwrap();
        assert_eq!(format!("{key:?}"), "SigningKey([redacted])");
    }
}
