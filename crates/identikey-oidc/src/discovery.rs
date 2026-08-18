//! OpenID Provider metadata (OIDC Discovery 1.0 / RFC 8414).

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub revocation_endpoint: String,
    pub introspection_endpoint: String,
    pub response_types_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub scopes_supported: Vec<&'static str>,
}

impl DiscoveryDocument {
    #[must_use]
    pub fn for_issuer(issuer: &str) -> Self {
        let base = issuer.trim_end_matches('/');
        Self {
            issuer: base.to_owned(),
            authorization_endpoint: format!("{base}/authorize"),
            token_endpoint: format!("{base}/token"),
            userinfo_endpoint: format!("{base}/userinfo"),
            jwks_uri: format!("{base}/.well-known/jwks.json"),
            revocation_endpoint: format!("{base}/revoke"),
            introspection_endpoint: format!("{base}/introspect"),
            response_types_supported: vec!["code"],
            grant_types_supported: vec!["authorization_code", "refresh_token"],
            code_challenge_methods_supported: vec!["S256"],
            subject_types_supported: vec!["pairwise", "public"],
            id_token_signing_alg_values_supported: vec!["EdDSA"],
            token_endpoint_auth_methods_supported: vec!["none"],
            scopes_supported: vec!["openid"],
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "panicking on failure is the assertion in a test"
)]
mod tests {
    use super::*;

    #[test]
    fn advertises_code_and_s256_only() {
        let doc = DiscoveryDocument::for_issuer("https://auth.example/");
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("authorization_endpoint"));
        assert!(json.contains("token_endpoint"));
        assert!(json.contains("jwks_uri"));
        assert!(json.contains("\"code\""));
        assert!(json.contains("S256"));
        assert!(json.contains("EdDSA"));
        assert!(!json.contains("password"));
        assert!(!json.contains("\"token\""));
        assert_eq!(doc.issuer, "https://auth.example");
        assert_eq!(doc.authorization_endpoint, "https://auth.example/authorize");
    }
}
