//! Fail-closed WebAuthn RP ID and origin allowlist (`identikey-core-62j`).
//!
//! ADR-004: the production RP ID is `auth.identikey.me` and the expected
//! origin allowlist is strict — never a wildcard. Missing config must not
//! boot a permissive default.

use std::net::IpAddr;

use serde::Serialize;
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub expected_origins: Vec<String>,
}

impl WebAuthnConfig {
    /// `webauthn-rs` verifier for this RP ID / origin allowlist.
    pub fn verifier(&self) -> Result<webauthn_rs::Webauthn, Error> {
        let urls: Result<Vec<url::Url>, _> = self
            .expected_origins
            .iter()
            .map(|origin| url::Url::parse(origin).map_err(|_| Error::InvalidOrigin))
            .collect();
        let urls = urls?;
        let Some(primary) = urls.iter().find(|u| u.domain().is_some()) else {
            return Err(Error::InvalidOrigin);
        };
        let mut builder = webauthn_rs::WebauthnBuilder::new(&self.rp_id, primary)
            .map_err(|_| Error::InvalidOrigin)?
            .rp_name("IdentiKey");
        for extra in &urls {
            if extra.as_str() != primary.as_str() {
                builder = builder.append_allowed_origin(extra);
            }
        }
        builder.build().map_err(|_| Error::InvalidOrigin)
    }

    /// Related Origin Requests list: https expected origins only.
    ///
    /// Profile / user-content origins never appear here — they cannot pass
    /// the RP ID host check (`identikey.me` is a parent of `auth.identikey.me`,
    /// not a subdomain).
    #[must_use]
    pub fn related_origins(&self) -> RelatedOrigins {
        RelatedOrigins {
            origins: self
                .expected_origins
                .iter()
                .filter(|origin| origin.starts_with("https://"))
                .cloned()
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RelatedOrigins {
    pub origins: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("WEBAUTHN_RP_ID is required")]
    MissingRpId,
    #[error("WEBAUTHN_EXPECTED_ORIGIN is required")]
    MissingOrigins,
    #[error("WEBAUTHN_RP_ID is not a valid RP ID")]
    InvalidRpId,
    #[error("WEBAUTHN_EXPECTED_ORIGIN is not a valid origin")]
    InvalidOrigin,
    #[error("WEBAUTHN_RP_ID and WEBAUTHN_EXPECTED_ORIGIN must not contain wildcards")]
    Wildcard,
    #[error("WEBAUTHN_EXPECTED_ORIGIN host is not the RP ID or a subdomain of it")]
    HostMismatch,
    #[error(
        "http origins are allowed only for localhost / 127.0.0.1 when WEBAUTHN_RP_ID is localhost"
    )]
    HttpNotLoopback,
}

/// Parse RP ID and comma-separated expected origins without reading process env.
pub fn parse_webauthn_config(
    rp_id: Option<&str>,
    origins: Option<&str>,
) -> Result<WebAuthnConfig, Error> {
    let rp_id = parse_rp_id(rp_id)?;
    let expected_origins = parse_origins(origins, &rp_id)?;
    Ok(WebAuthnConfig {
        rp_id,
        expected_origins,
    })
}

fn parse_rp_id(raw: Option<&str>) -> Result<String, Error> {
    let Some(raw) = raw else {
        return Err(Error::MissingRpId);
    };
    let rp_id = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if rp_id.is_empty() {
        return Err(Error::MissingRpId);
    }
    if rp_id.contains('*') {
        return Err(Error::Wildcard);
    }
    if rp_id.contains('/')
        || rp_id.contains(':')
        || rp_id.contains("..")
        || rp_id.starts_with('.')
        || rp_id.contains(char::is_whitespace)
    {
        return Err(Error::InvalidRpId);
    }
    if rp_id.parse::<IpAddr>().is_ok() {
        return Err(Error::InvalidRpId);
    }
    if rp_id != "localhost" && !rp_id.contains('.') {
        return Err(Error::InvalidRpId);
    }
    Ok(rp_id)
}

fn parse_origins(raw: Option<&str>, rp_id: &str) -> Result<Vec<String>, Error> {
    let Some(raw) = raw else {
        return Err(Error::MissingOrigins);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::MissingOrigins);
    }
    if trimmed.contains('*') {
        return Err(Error::Wildcard);
    }

    let mut expected_origins = Vec::new();
    for part in trimmed.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part.contains('*') {
            return Err(Error::Wildcard);
        }
        let origin = parse_one_origin(part, rp_id)?;
        if !expected_origins.contains(&origin) {
            expected_origins.push(origin);
        }
    }
    if expected_origins.is_empty() {
        return Err(Error::MissingOrigins);
    }
    Ok(expected_origins)
}

fn parse_one_origin(raw: &str, rp_id: &str) -> Result<String, Error> {
    if raw.contains('*') {
        return Err(Error::Wildcard);
    }
    let url = Url::parse(raw).map_err(|_| Error::InvalidOrigin)?;
    if url.cannot_be_a_base() {
        return Err(Error::InvalidOrigin);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::InvalidOrigin);
    }
    let path = url.path();
    if !path.is_empty() && path != "/" {
        return Err(Error::InvalidOrigin);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::InvalidOrigin);
    }

    let scheme = url.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(Error::InvalidOrigin);
    }
    let Some(host) = url.host_str() else {
        return Err(Error::InvalidOrigin);
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.contains('*') {
        return Err(Error::Wildcard);
    }

    let loopback = is_loopback_host(&host);
    let localhost_dev = rp_id == "localhost" && loopback;
    if !host_matches_rp_id(&host, rp_id) && !localhost_dev {
        return Err(Error::HostMismatch);
    }
    if scheme == "http" && !localhost_dev {
        return Err(Error::HttpNotLoopback);
    }

    let origin = url.origin();
    if !origin.is_tuple() {
        return Err(Error::InvalidOrigin);
    }
    Ok(origin.ascii_serialization())
}

fn host_matches_rp_id(host: &str, rp_id: &str) -> bool {
    if host == rp_id {
        return true;
    }
    host.strip_suffix(rp_id)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1"
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;

    #[test]
    fn production_origin_is_accepted() {
        let cfg =
            parse_webauthn_config(Some("auth.identikey.me"), Some("https://auth.identikey.me"))
                .unwrap();
        assert_eq!(cfg.rp_id, "auth.identikey.me");
        assert_eq!(
            cfg.expected_origins,
            vec!["https://auth.identikey.me".to_owned()]
        );
        assert_eq!(
            cfg.related_origins().origins,
            vec!["https://auth.identikey.me".to_owned()]
        );
    }

    #[test]
    fn wildcard_origin_is_rejected() {
        assert_eq!(
            parse_webauthn_config(Some("auth.identikey.me"), Some("*")).unwrap_err(),
            Error::Wildcard
        );
        assert_eq!(
            parse_webauthn_config(Some("auth.identikey.me"), Some("https://*.identikey.me"))
                .unwrap_err(),
            Error::Wildcard
        );
        assert_eq!(
            parse_webauthn_config(
                Some("auth.identikey.me"),
                Some("https://auth.identikey.me, *")
            )
            .unwrap_err(),
            Error::Wildcard
        );
        assert_eq!(
            parse_webauthn_config(Some("*.identikey.me"), Some("https://auth.identikey.me"))
                .unwrap_err(),
            Error::Wildcard
        );
    }

    #[test]
    fn host_not_matching_rp_id_is_rejected() {
        assert_eq!(
            parse_webauthn_config(Some("auth.identikey.me"), Some("https://evil.example"))
                .unwrap_err(),
            Error::HostMismatch
        );
        // Profile / user-content surface: parent of the RP ID, not a subdomain.
        assert_eq!(
            parse_webauthn_config(Some("auth.identikey.me"), Some("https://identikey.me"))
                .unwrap_err(),
            Error::HostMismatch
        );
        assert_eq!(
            parse_webauthn_config(Some("auth.identikey.me"), Some("https://app.identikey.io"))
                .unwrap_err(),
            Error::HostMismatch
        );
    }

    #[test]
    fn missing_config_fails_closed() {
        assert_eq!(
            parse_webauthn_config(None, Some("https://auth.identikey.me")).unwrap_err(),
            Error::MissingRpId
        );
        assert_eq!(
            parse_webauthn_config(Some(""), Some("https://auth.identikey.me")).unwrap_err(),
            Error::MissingRpId
        );
        assert_eq!(
            parse_webauthn_config(Some("auth.identikey.me"), None).unwrap_err(),
            Error::MissingOrigins
        );
        assert_eq!(
            parse_webauthn_config(Some("auth.identikey.me"), Some("")).unwrap_err(),
            Error::MissingOrigins
        );
        assert_eq!(
            parse_webauthn_config(Some("auth.identikey.me"), Some("   ,  ")).unwrap_err(),
            Error::MissingOrigins
        );
    }

    #[test]
    fn loopback_http_only_when_rp_id_is_localhost() {
        let cfg = parse_webauthn_config(
            Some("localhost"),
            Some("http://localhost, http://127.0.0.1"),
        )
        .unwrap();
        assert_eq!(
            cfg.expected_origins,
            vec!["http://localhost".to_owned(), "http://127.0.0.1".to_owned()]
        );
        assert!(cfg.related_origins().origins.is_empty());

        assert_eq!(
            parse_webauthn_config(Some("auth.identikey.me"), Some("http://localhost")).unwrap_err(),
            Error::HostMismatch
        );
        assert_eq!(
            parse_webauthn_config(Some("auth.identikey.me"), Some("http://auth.identikey.me"))
                .unwrap_err(),
            Error::HttpNotLoopback
        );
    }

    #[test]
    fn subdomain_of_rp_id_is_accepted() {
        let cfg = parse_webauthn_config(
            Some("auth.identikey.me"),
            Some("https://auth.identikey.me, https://login.auth.identikey.me"),
        )
        .unwrap();
        assert_eq!(
            cfg.related_origins().origins,
            vec![
                "https://auth.identikey.me".to_owned(),
                "https://login.auth.identikey.me".to_owned()
            ]
        );
    }
}
