//! Passkeys that have succeeded in this browser.
//!
//! The cookie is a first-party hint for the login and account pages. It is
//! not a session, and a ceremony still accepts any live passkey.

use axum::http::HeaderValue;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub const COOKIE_NAME: &str = "identikey_device_passkeys";
const MAX_IDS: usize = 8;
const MAX_ID_LEN: usize = 1023;
const MAX_AGE: &str = "31536000";

/// Credential ids from the request `Cookie` header, most recent first.
#[must_use]
pub fn parse(header: Option<&str>) -> Vec<Vec<u8>> {
    let Some(header) = header else {
        return Vec::new();
    };
    for part in header.split(';') {
        let part = part.trim();
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        if name == COOKIE_NAME {
            return decode_ids(value);
        }
    }
    Vec::new()
}

/// Remember `credential_id`, moving it ahead of ids already stored.
#[must_use]
pub fn remember(existing: &[Vec<u8>], credential_id: &[u8]) -> Vec<Vec<u8>> {
    if credential_id.is_empty() || credential_id.len() > MAX_ID_LEN {
        return existing.to_vec();
    }
    let mut ids = Vec::with_capacity(MAX_IDS);
    ids.push(credential_id.to_vec());
    for id in existing {
        if id != credential_id && ids.len() < MAX_IDS {
            ids.push(id.clone());
        }
    }
    ids
}

#[must_use]
pub fn encode(ids: &[Vec<u8>]) -> String {
    ids.iter()
        .take(MAX_IDS)
        .map(|id| URL_SAFE_NO_PAD.encode(id))
        .collect::<Vec<_>>()
        .join(".")
}

#[must_use]
pub fn set_cookie(ids: &[Vec<u8>], secure: bool) -> HeaderValue {
    header_value(&encode(ids), MAX_AGE, secure)
}

#[must_use]
pub fn clear_cookie(secure: bool) -> HeaderValue {
    header_value("", "0", secure)
}

fn decode_ids(value: &str) -> Vec<Vec<u8>> {
    let mut ids = Vec::new();
    if value.is_empty() {
        return ids;
    }
    for part in value.split('.') {
        if ids.len() == MAX_IDS {
            break;
        }
        let Ok(bytes) = URL_SAFE_NO_PAD.decode(part) else {
            continue;
        };
        if bytes.is_empty() || bytes.len() > MAX_ID_LEN {
            continue;
        }
        if !ids.contains(&bytes) {
            ids.push(bytes);
        }
    }
    ids
}

fn header_value(payload: &str, max_age: &str, secure: bool) -> HeaderValue {
    let mut value =
        format!("{COOKIE_NAME}={payload}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}");
    if secure {
        value.push_str("; Secure");
    }
    HeaderValue::from_str(&value).unwrap_or_else(|_| {
        HeaderValue::from_static("identikey_device_passkeys=; Path=/; HttpOnly; Max-Age=0")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remember_moves_the_latest_id_first_and_caps_the_list() {
        let older = vec![b"one".to_vec(), b"two".to_vec()];
        let next = remember(&older, b"two");
        assert_eq!(next, vec![b"two".to_vec(), b"one".to_vec()]);
        let mut existing = Vec::new();
        for byte in 0..u8::try_from(MAX_IDS).unwrap() {
            existing = remember(&existing, &[byte]);
        }
        let capped = remember(&existing, b"newest");
        assert_eq!(capped.len(), MAX_IDS);
        assert_eq!(capped[0], b"newest");
        assert!(capped.iter().any(|id| id.as_slice() == [MAX_IDS as u8 - 1]));
        assert!(!capped.iter().any(|id| id.as_slice() == [0]));
    }

    #[test]
    fn parse_reads_only_this_cookie_and_skips_garbage() {
        let header = format!(
            "identikey_account=abc; {COOKIE_NAME}={}.not-base64.{}",
            URL_SAFE_NO_PAD.encode(b"kept"),
            URL_SAFE_NO_PAD.encode(b"also"),
        );
        assert_eq!(
            parse(Some(&header)),
            vec![b"kept".to_vec(), b"also".to_vec()]
        );
        assert!(parse(Some("identikey_account=abc")).is_empty());
        let set = set_cookie(&[b"kept".to_vec()], true);
        let text = set.to_str().unwrap();
        assert!(text.contains("HttpOnly"));
        assert!(text.contains("Secure"));
        assert!(text.contains("SameSite=Lax"));
        assert!(clear_cookie(false).to_str().unwrap().contains("Max-Age=0"));
    }
}
