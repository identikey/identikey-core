//! First-party account session after hosted signup.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::{HeaderValue, header};
use identikey_keys::Xid;
use uuid::Uuid;

const COOKIE_NAME: &str = "identikey_account";
const SESSION_TTL: Duration = Duration::from_secs(60 * 60 * 24);
const MAX_AGE: &str = "86400";

#[derive(Clone, Copy)]
struct Slot {
    xid: Xid,
    expires_at: Instant,
}

#[derive(Default)]
pub struct AccountSessions {
    inner: Mutex<HashMap<String, Slot>>,
}

impl AccountSessions {
    pub fn issue(&self, xid: Xid) -> Result<String, ()> {
        let token = Uuid::new_v4().as_simple().to_string();
        let mut map = self.inner.lock().map_err(|_| ())?;
        map.retain(|_, slot| slot.expires_at > Instant::now());
        map.insert(
            token.clone(),
            Slot {
                xid,
                expires_at: Instant::now() + SESSION_TTL,
            },
        );
        Ok(token)
    }

    pub fn lookup(&self, token: &str) -> Result<Option<Xid>, ()> {
        let mut map = self.inner.lock().map_err(|_| ())?;
        map.retain(|_, slot| slot.expires_at > Instant::now());
        Ok(map.get(token).map(|slot| slot.xid))
    }
}

#[must_use]
pub fn set_cookie(token: &str, secure: bool) -> HeaderValue {
    let mut value =
        format!("{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={MAX_AGE}");
    if secure {
        value.push_str("; Secure");
    }
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("identikey_account="))
}

#[must_use]
pub fn cookie_header() -> header::HeaderName {
    header::SET_COOKIE
}

#[must_use]
pub fn parse_cookie(header: Option<&str>) -> Option<&str> {
    let header = header?;
    for part in header.split(';') {
        let part = part.trim();
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        if name == COOKIE_NAME && !value.is_empty() {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_cookie_reads_the_account_token() {
        assert_eq!(
            parse_cookie(Some("identikey_account=abc; Path=/")),
            Some("abc")
        );
        assert_eq!(parse_cookie(Some("other=1")), None);
        assert_eq!(parse_cookie(None), None);
    }

    #[test]
    fn set_cookie_is_httponly() {
        let value = set_cookie("tok", true);
        let text = value.to_str().unwrap();
        assert!(text.contains("HttpOnly"));
        assert!(text.contains("Secure"));
        assert!(text.contains("SameSite=Lax"));
    }
}
