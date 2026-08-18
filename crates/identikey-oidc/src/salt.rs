//! Pairwise salt (ADR-009). Install-generated, never logged, never rotated.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::Path;

const LEN: usize = 32;
const FILE_NAME: &str = "pairwise.salt";

#[derive(Clone)]
pub struct PairwiseSalt([u8; LEN]);

#[derive(Debug, thiserror::Error)]
pub enum SaltError {
    #[error("IDENTIKEY_PAIRWISE_SALT is empty or a placeholder")]
    Placeholder,
    #[error("IDENTIKEY_PAIRWISE_SALT must be {LEN} bytes (64 hex characters)")]
    BadLength,
    #[error("could not generate pairwise salt: {0}")]
    Entropy(String),
    #[error("pairwise salt file: {0}")]
    Io(#[from] std::io::Error),
}

impl PairwiseSalt {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; LEN] {
        &self.0
    }

    /// Hex for export. The caller must not log this string.
    #[must_use]
    pub fn export_hex(&self) -> String {
        let mut out = String::with_capacity(LEN * 2);
        for byte in self.0 {
            let _ = fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
        }
        out
    }

    pub fn from_hex(hex: &str) -> Result<Self, SaltError> {
        let trimmed = hex.trim();
        if is_placeholder(trimmed) {
            return Err(SaltError::Placeholder);
        }
        if trimmed.len() != LEN * 2 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(SaltError::BadLength);
        }
        let mut bytes = [0u8; LEN];
        for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
            let text = std::str::from_utf8(chunk).map_err(|_| SaltError::BadLength)?;
            let slot = bytes.get_mut(i).ok_or(SaltError::BadLength)?;
            *slot = u8::from_str_radix(text, 16).map_err(|_| SaltError::BadLength)?;
        }
        if bytes.iter().all(|b| *b == 0) {
            return Err(SaltError::Placeholder);
        }
        Ok(Self(bytes))
    }

    pub fn generate() -> Result<Self, SaltError> {
        let mut bytes = [0u8; LEN];
        getrandom::getrandom(&mut bytes).map_err(|e| SaltError::Entropy(e.to_string()))?;
        if bytes.iter().all(|b| *b == 0) {
            return Err(SaltError::Entropy("CSPRNG returned all zeros".into()));
        }
        Ok(Self(bytes))
    }

    /// Env wins when set. Otherwise read or create `data_dir/pairwise.salt`.
    pub fn load(env: Option<&str>, data_dir: &Path) -> Result<Self, SaltError> {
        match env {
            Some(raw) => Self::from_hex(raw),
            None => load_or_create(data_dir),
        }
    }
}

impl fmt::Debug for PairwiseSalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairwiseSalt([redacted])")
    }
}

fn is_placeholder(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    raw.is_empty() || lower == "changeme" || lower == "replace-me" || raw.bytes().all(|b| b == b'0')
}

fn load_or_create(data_dir: &Path) -> Result<PairwiseSalt, SaltError> {
    let path = data_dir.join(FILE_NAME);
    if path.exists() {
        let text = fs::read_to_string(&path)?;
        return PairwiseSalt::from_hex(text.trim());
    }
    fs::create_dir_all(data_dir)?;
    let salt = PairwiseSalt::generate()?;
    write_private(&path, salt.export_hex().as_bytes())?;
    Ok(salt)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), SaltError> {
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
        let dir = std::env::temp_dir().join(format!("identikey-salt-{n}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn placeholder_fails_closed() {
        assert!(matches!(
            PairwiseSalt::from_hex(""),
            Err(SaltError::Placeholder)
        ));
        assert!(matches!(
            PairwiseSalt::from_hex("changeme"),
            Err(SaltError::Placeholder)
        ));
        assert!(matches!(
            PairwiseSalt::from_hex(&"0".repeat(64)),
            Err(SaltError::Placeholder)
        ));
        assert!(matches!(
            PairwiseSalt::load(Some(""), Path::new("/tmp")),
            Err(SaltError::Placeholder)
        ));
    }

    #[test]
    fn generate_persists_and_reloads() {
        let dir = scratch();
        let first = PairwiseSalt::load(None, &dir).unwrap();
        let second = PairwiseSalt::load(None, &dir).unwrap();
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_eq!(first.export_hex().len(), 64);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn debug_does_not_print_bytes() {
        let salt = PairwiseSalt::generate().unwrap();
        let shown = format!("{salt:?}");
        assert_eq!(shown, "PairwiseSalt([redacted])");
        assert!(!shown.contains(&salt.export_hex()));
    }
}
