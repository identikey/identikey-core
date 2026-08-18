//! OP token-signing key (EdDSA / Ed25519). Not a user key.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::Path;

use josekit::jwk::alg::ed::EdCurve;
use josekit::jwk::{Jwk, JwkSet, KeyPair};
use josekit::jws::{EdDSA, JwsHeader};
use josekit::jwt::{self, JwtPayload};

const FILE_NAME: &str = "signing.jwk";

#[derive(Clone)]
pub struct SigningKey {
    jwk: Jwk,
}

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("IDENTIKEY_SIGNING_KEY is empty or not an Ed25519 private JWK")]
    BadKey,
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
        Ok(Self { jwk })
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
        Ok(Self { jwk })
    }

    /// Env wins when set. Otherwise read or create `data_dir/signing.jwk`.
    pub fn load(env: Option<&str>, data_dir: &Path) -> Result<Self, SigningError> {
        match env {
            Some(raw) => Self::from_jwk_json(raw),
            None => load_or_create(data_dir),
        }
    }

    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.jwk.key_id()
    }

    #[must_use]
    pub fn public_jwks(&self) -> JwkSet {
        let mut set = JwkSet::new();
        if let Ok(mut public) = self.jwk.to_public_key() {
            if let Some(kid) = self.jwk.key_id() {
                public.set_key_id(kid);
            }
            if let Some(alg) = self.jwk.algorithm() {
                public.set_algorithm(alg);
            }
            set.push_key(public);
        }
        set
    }

    pub fn sign_id_token(
        &self,
        issuer: &str,
        audience: &str,
        sub: &str,
        nonce: Option<&str>,
        ttl_secs: u64,
    ) -> Result<String, SigningError> {
        let signer = EdDSA
            .signer_from_jwk(&self.jwk)
            .map_err(|e| SigningError::Jose(e.to_string()))?;
        let mut header = JwsHeader::new();
        header.set_algorithm("EdDSA");
        if let Some(kid) = self.jwk.key_id() {
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

fn load_or_create(data_dir: &Path) -> Result<SigningKey, SigningError> {
    let path = data_dir.join(FILE_NAME);
    if path.exists() {
        let text = fs::read_to_string(&path)?;
        return SigningKey::from_jwk_json(&text);
    }
    fs::create_dir_all(data_dir)?;
    let key = SigningKey::generate()?;
    write_private(&path, key.jwk.to_string().as_bytes())?;
    Ok(key)
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

    #[test]
    fn debug_is_redacted() {
        let key = SigningKey::generate().unwrap();
        assert_eq!(format!("{key:?}"), "SigningKey([redacted])");
    }
}
