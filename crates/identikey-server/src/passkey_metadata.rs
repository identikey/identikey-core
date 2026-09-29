//! Local, presentation-only AAGUID metadata.
//!
//! Source: https://github.com/passkeydeveloper/passkey-authenticator-aaguids/blob/main/aaguid.json,
//! pinned 2026-09-27. This data is never a ceremony or authorization input.
//! The compact pin contains common providers and can be refreshed independently
//! of the authentication implementation.

use std::collections::HashMap;

use serde::Deserialize;

const PINNED_AAGUIDS: &str = include_str!("passkey-authenticator-aaguids.json");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyMetadata {
    pub name: String,
    pub icon: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    name: String,
    #[serde(default)]
    icon_dark: Option<String>,
    #[serde(default)]
    icon_light: Option<String>,
}

#[must_use]
pub fn resolve(aaguid: &[u8; 16]) -> Option<PasskeyMetadata> {
    resolve_from_json(PINNED_AAGUIDS, aaguid)
}

fn resolve_from_json(json: &str, aaguid: &[u8; 16]) -> Option<PasskeyMetadata> {
    let entries: HashMap<String, Entry> = serde_json::from_str(json).ok()?;
    let key = uuid::Uuid::from_bytes(*aaguid).hyphenated().to_string();
    let entry = entries.get(&key)?;
    let name = entry.name.trim();
    if name.is_empty() {
        return None;
    }
    let icon = [entry.icon_dark.as_deref(), entry.icon_light.as_deref()]
        .into_iter()
        .flatten()
        .find_map(safe_embedded_svg)
        .map(str::to_owned);
    Some(PasskeyMetadata {
        name: name.to_owned(),
        icon,
    })
}

/// The upstream pin embeds icons. Refuse remote loads and active URL schemes.
fn safe_embedded_svg(value: &str) -> Option<&str> {
    const PREFIX: &str = "data:image/svg+xml;base64,";
    let payload = value.strip_prefix(PREFIX)?;
    (!payload.is_empty()
        && payload
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')))
    .then_some(value)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;

    const GOOGLE: [u8; 16] = [
        0xea, 0x9b, 0x8d, 0x66, 0x4d, 0x01, 0x1d, 0x21, 0x3c, 0xe4, 0xb6, 0xb4, 0x8c, 0xb5, 0x75,
        0xd4,
    ];

    #[test]
    fn passkey_legibility_resolves_known_and_unknown_aaguids() {
        let known = resolve(&GOOGLE).expect("pinned Google metadata");
        assert_eq!(known.name, "Google Password Manager");
        assert!(known.icon.is_some());
        assert!(resolve(&[0xff; 16]).is_none());
    }

    #[test]
    fn passkey_legibility_malformed_metadata_falls_back() {
        assert!(resolve_from_json("not json", &GOOGLE).is_none());
        assert!(
            resolve_from_json(r#"{"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4":{}}"#, &GOOGLE).is_none()
        );
    }

    #[test]
    fn passkey_legibility_rejects_unsafe_icon_schemes() {
        let json = r#"{
            "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": {
                "name": "Provider <unsafe>",
                "icon_dark": "javascript:alert(1)"
            }
        }"#;
        let metadata = resolve_from_json(json, &GOOGLE).expect("name remains usable");
        assert_eq!(metadata.name, "Provider <unsafe>");
        assert!(metadata.icon.is_none());
    }
}
