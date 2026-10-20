//! RFC 8628 device-authorization sessions.
//!
//! Raw device codes and user codes never sit in this map. A passkey
//! assertion is not accepted here; the HTTP layer verifies it and then
//! calls [`DeviceSessions::approve`] with the challenge bytes that
//! ceremony stored on the row.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use identikey_keys::Xid;
use sha2::{Digest, Sha256};

use crate::error::OidcError;

pub const DEVICE_TTL_SECS: u64 = 900;
pub const DEVICE_INTERVAL_SECS: u64 = 5;
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE_LEN: usize = 8;
const ROW_MISS_LIMIT: u32 = 3;
const SOURCE_MISS_LIMIT: u32 = 20;
const GLOBAL_MISS_LIMIT: u32 = 100;
const MISS_WINDOW: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Pending,
    Approved,
    Denied,
    Consumed,
    Burned,
}

struct Row {
    client_id: String,
    created_unix: u64,
    expires_unix: u64,
    interval_secs: u64,
    last_poll: Option<Instant>,
    status: Status,
    xid: Option<Xid>,
    assertion_challenge: Option<Vec<u8>>,
    misses: u32,
}

struct MissWindow {
    count: u32,
    started: Instant,
}

pub struct DeviceSessions {
    by_device: HashMap<[u8; 32], Row>,
    user_to_device: HashMap<[u8; 32], [u8; 32]>,
    by_source: HashMap<String, MissWindow>,
    global: MissWindow,
}

pub struct StartedDevice {
    pub device_hash: [u8; 32],
    pub user_hash: [u8; 32],
}

pub struct DevicePrompt {
    pub client_id: String,
    pub created_unix: u64,
}

#[derive(Debug)]
pub enum Poll {
    Pending,
    SlowDown,
    Ready { client_id: String, xid: Xid },
}

impl Default for DeviceSessions {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceSessions {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            by_device: HashMap::new(),
            user_to_device: HashMap::new(),
            by_source: HashMap::new(),
            global: MissWindow {
                count: 0,
                started: now,
            },
        }
    }

    pub fn insert(
        &mut self,
        client_id: &str,
        device_code: &str,
        user_code: &str,
        now_unix: u64,
    ) -> StartedDevice {
        let device_hash = hash_code(device_code);
        let user_hash = hash_code(&normalize_user_code(user_code));
        self.by_device.insert(
            device_hash,
            Row {
                client_id: client_id.to_owned(),
                created_unix: now_unix,
                expires_unix: now_unix.saturating_add(DEVICE_TTL_SECS),
                interval_secs: DEVICE_INTERVAL_SECS,
                last_poll: None,
                status: Status::Pending,
                xid: None,
                assertion_challenge: None,
                misses: 0,
            },
        );
        self.user_to_device.insert(user_hash, device_hash);
        StartedDevice {
            device_hash,
            user_hash,
        }
    }

    pub fn prompt(
        &mut self,
        user_code: &str,
        source: &str,
        now_unix: u64,
        now: Instant,
    ) -> Result<DevicePrompt, OidcError> {
        self.expire_misses(now);
        if self.over_limit(source) {
            return Err(OidcError::invalid_request("too many attempts"));
        }
        let user_hash = hash_code(&normalize_user_code(user_code));
        let Some(device_hash) = self.user_to_device.get(&user_hash).copied() else {
            self.record_miss(source, now);
            return Err(OidcError::invalid_request("unknown user code"));
        };
        let row = self
            .by_device
            .get_mut(&device_hash)
            .ok_or_else(|| OidcError::invalid_request("unknown user code"))?;
        if now_unix >= row.expires_unix {
            row.status = Status::Burned;
            return Err(OidcError::new("expired_token", "device code expired"));
        }
        if row.status != Status::Pending && row.status != Status::Approved {
            return Err(OidcError::new(
                "access_denied",
                "device authorization is not pending",
            ));
        }
        Ok(DevicePrompt {
            client_id: row.client_id.clone(),
            created_unix: row.created_unix,
        })
    }

    pub fn miss(&mut self, user_code: &str, source: &str, now: Instant) -> Result<(), OidcError> {
        self.expire_misses(now);
        if self.over_limit(source) {
            return Err(OidcError::invalid_request("too many attempts"));
        }
        let user_hash = hash_code(&normalize_user_code(user_code));
        if let Some(device_hash) = self.user_to_device.get(&user_hash).copied() {
            if let Some(row) = self.by_device.get_mut(&device_hash) {
                row.misses = row.misses.saturating_add(1);
                if row.misses >= ROW_MISS_LIMIT {
                    row.status = Status::Burned;
                }
            }
        }
        self.record_miss(source, now);
        if self.over_limit(source) {
            return Err(OidcError::invalid_request("too many attempts"));
        }
        Err(OidcError::invalid_request("unknown user code"))
    }

    pub fn contains_user(&self, user_code: &str) -> bool {
        let user_hash = hash_code(&normalize_user_code(user_code));
        self.user_to_device.contains_key(&user_hash)
    }

    pub fn contains_device(&self, device_code: &str) -> bool {
        self.by_device.contains_key(&hash_code(device_code))
    }

    pub fn bind(
        &mut self,
        user_code: &str,
        challenge: &[u8],
        now_unix: u64,
    ) -> Result<(), OidcError> {
        let row = self.pending_row(user_code, now_unix)?;
        if challenge.is_empty() {
            return Err(OidcError::invalid_request(
                "assertion challenge is required",
            ));
        }
        row.assertion_challenge = Some(challenge.to_vec());
        Ok(())
    }

    pub fn approve(
        &mut self,
        user_code: &str,
        xid: Xid,
        challenge: &[u8],
        now_unix: u64,
    ) -> Result<(), OidcError> {
        let row = self.pending_row(user_code, now_unix)?;
        match &row.assertion_challenge {
            Some(stored) if stored.as_slice() == challenge => {}
            _ => {
                return Err(OidcError::invalid_request(
                    "passkey assertion does not match this device request",
                ));
            }
        }
        row.status = Status::Approved;
        row.xid = Some(xid);
        Ok(())
    }

    pub fn deny(&mut self, user_code: &str, now_unix: u64) -> Result<(), OidcError> {
        let row = self.pending_row(user_code, now_unix)?;
        row.status = Status::Denied;
        Ok(())
    }

    pub fn poll(
        &mut self,
        device_code: &str,
        client_id: &str,
        now_unix: u64,
        now: Instant,
    ) -> Result<Poll, OidcError> {
        let device_hash = hash_code(device_code);
        let Some(row) = self.by_device.get_mut(&device_hash) else {
            return Err(OidcError::invalid_grant("unknown device code"));
        };
        if row.client_id != client_id {
            return Err(OidcError::invalid_grant(
                "device code belongs to another client",
            ));
        }
        if now_unix >= row.expires_unix {
            row.status = Status::Burned;
            return Err(OidcError::new("expired_token", "device code expired"));
        }
        match row.status {
            Status::Denied | Status::Burned => {
                return Err(OidcError::new(
                    "access_denied",
                    "device authorization was denied",
                ));
            }
            Status::Consumed => {
                return Err(OidcError::invalid_grant("device code already redeemed"));
            }
            Status::Pending | Status::Approved => {}
        }
        if let Some(last) = row.last_poll {
            if now.saturating_duration_since(last) < Duration::from_secs(row.interval_secs) {
                row.interval_secs = row.interval_secs.saturating_add(DEVICE_INTERVAL_SECS);
                return Ok(Poll::SlowDown);
            }
        }
        row.last_poll = Some(now);
        if row.status == Status::Pending {
            return Ok(Poll::Pending);
        }
        let xid = row
            .xid
            .ok_or_else(|| OidcError::server_error("approved device row has no subject"))?;
        let client_id = row.client_id.clone();
        row.status = Status::Consumed;
        Ok(Poll::Ready { client_id, xid })
    }

    fn pending_row(&mut self, user_code: &str, now_unix: u64) -> Result<&mut Row, OidcError> {
        let user_hash = hash_code(&normalize_user_code(user_code));
        let device_hash = self
            .user_to_device
            .get(&user_hash)
            .copied()
            .ok_or_else(|| OidcError::invalid_request("unknown user code"))?;
        let row = self
            .by_device
            .get_mut(&device_hash)
            .ok_or_else(|| OidcError::invalid_request("unknown user code"))?;
        if now_unix >= row.expires_unix {
            row.status = Status::Burned;
            return Err(OidcError::new("expired_token", "device code expired"));
        }
        if row.status == Status::Burned {
            return Err(OidcError::new(
                "access_denied",
                "device authorization was denied",
            ));
        }
        if row.status != Status::Pending {
            return Err(OidcError::invalid_request(
                "device authorization is not awaiting approval",
            ));
        }
        Ok(row)
    }

    fn over_limit(&self, source: &str) -> bool {
        self.global.count >= GLOBAL_MISS_LIMIT
            || self
                .by_source
                .get(source)
                .is_some_and(|window| window.count >= SOURCE_MISS_LIMIT)
    }

    fn expire_misses(&mut self, now: Instant) {
        if now.saturating_duration_since(self.global.started) >= MISS_WINDOW {
            self.global = MissWindow {
                count: 0,
                started: now,
            };
        }
        self.by_source
            .retain(|_, window| now.saturating_duration_since(window.started) < MISS_WINDOW);
    }

    fn record_miss(&mut self, source: &str, now: Instant) {
        self.global.count = self.global.count.saturating_add(1);
        let window = self
            .by_source
            .entry(source.to_owned())
            .or_insert(MissWindow {
                count: 0,
                started: now,
            });
        window.count = window.count.saturating_add(1);
    }
}

pub fn normalize_user_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

pub fn hash_code(raw: &str) -> [u8; 32] {
    Sha256::digest(raw.as_bytes()).into()
}

pub fn new_user_code() -> Result<String, OidcError> {
    // Rejection sampling: 20 symbols divide 256 with a remainder, so bytes
    // at or above 240 are discarded instead of biasing the low symbols.
    let mut out = String::with_capacity(USER_CODE_LEN);
    let mut bytes = [0u8; 16];
    while out.len() < USER_CODE_LEN {
        getrandom::getrandom(&mut bytes)
            .map_err(|err| OidcError::server_error(format!("entropy: {err}")))?;
        for byte in bytes {
            if byte >= 240 {
                continue;
            }
            let index = usize::from(byte % 20);
            let Some(symbol) = USER_CODE_ALPHABET.get(index).copied() else {
                continue;
            };
            out.push(symbol as char);
            if out.len() == USER_CODE_LEN {
                break;
            }
        }
    }
    Ok(out)
}

pub fn new_device_code() -> Result<String, OidcError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|err| OidcError::server_error(format!("entropy: {err}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;

    #[test]
    fn user_code_ignores_hyphen_and_case() {
        assert_eq!(normalize_user_code(" abcd-efgh "), "ABCDEFGH");
    }

    #[test]
    fn misses_burn_the_row_and_a_later_poll_is_denied() {
        let mut sessions = DeviceSessions::new();
        let user = "BCDFGHJK";
        sessions.insert("cli", "device-raw", user, 1_000);
        let now = Instant::now();
        sessions.miss(user, "src", now).unwrap_err();
        sessions.miss(user, "src", now).unwrap_err();
        sessions.miss(user, "src", now).unwrap_err();
        let err = sessions.poll("device-raw", "cli", 1_001, now).unwrap_err();
        assert_eq!(err.error, "access_denied");
    }

    #[test]
    fn one_poll_consumes_an_approval() {
        let mut sessions = DeviceSessions::new();
        sessions.insert("cli", "device-raw", "BCDFGHJK", 1_000);
        sessions.bind("BCDFGHJK", b"challenge", 1_001).unwrap();
        let xid = Xid::from_bytes([7; 32]);
        sessions
            .approve("BCDFGHJK", xid, b"challenge", 1_002)
            .unwrap();
        let now = Instant::now();
        match sessions.poll("device-raw", "cli", 1_003, now).unwrap() {
            Poll::Ready {
                client_id,
                xid: got,
            } => {
                assert_eq!(client_id, "cli");
                assert_eq!(got, xid);
            }
            other => panic!("expected ready, got pending/slow: {other:?}"),
        }
        let err = sessions
            .poll("device-raw", "cli", 1_100, now + Duration::from_secs(10))
            .unwrap_err();
        assert_eq!(err.error, "invalid_grant");
    }

    #[test]
    fn other_client_cannot_redeem() {
        let mut sessions = DeviceSessions::new();
        sessions.insert("cli", "device-raw", "BCDFGHJK", 1_000);
        let err = sessions
            .poll("device-raw", "other", 1_001, Instant::now())
            .unwrap_err();
        assert_eq!(err.error, "invalid_grant");
    }
}
