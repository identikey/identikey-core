//! OAuth / OIDC errors. `error` values are the RFC 6749 tokens.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcError {
    pub error: &'static str,
    pub description: String,
}

impl OidcError {
    #[must_use]
    pub fn new(error: &'static str, description: impl Into<String>) -> Self {
        Self {
            error,
            description: description.into(),
        }
    }

    #[must_use]
    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new("invalid_request", description)
    }

    #[must_use]
    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new("invalid_grant", description)
    }

    #[must_use]
    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self::new("invalid_client", description)
    }

    #[must_use]
    pub fn unsupported_grant_type(description: impl Into<String>) -> Self {
        Self::new("unsupported_grant_type", description)
    }

    #[must_use]
    pub fn unsupported_response_type(description: impl Into<String>) -> Self {
        Self::new("unsupported_response_type", description)
    }

    #[must_use]
    pub fn server_error(description: impl Into<String>) -> Self {
        Self::new("server_error", description)
    }
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error, self.description)
    }
}

impl std::error::Error for OidcError {}

/// `/authorize` failure. A valid registered redirect gets the error on
/// the redirect; a bad redirect must not be followed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeError {
    Redirect {
        uri: String,
        error: &'static str,
        description: String,
        state: Option<String>,
    },
    Deny {
        error: &'static str,
        description: String,
    },
}

impl AuthorizeError {
    #[must_use]
    pub fn redirect(
        uri: impl Into<String>,
        error: &'static str,
        description: impl Into<String>,
        state: Option<String>,
    ) -> Self {
        Self::Redirect {
            uri: uri.into(),
            error,
            description: description.into(),
            state,
        }
    }

    #[must_use]
    pub fn deny(error: &'static str, description: impl Into<String>) -> Self {
        Self::Deny {
            error,
            description: description.into(),
        }
    }
}
