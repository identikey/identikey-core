## MODIFIED Requirements

### Requirement: Discovery and JWKS

`identikey-server` SHALL serve OpenID discovery and a JWKS for the
token-signing key. Discovery SHALL advertise `response_types_supported`
containing `code` only, `code_challenge_methods_supported` containing
`S256`, and `subject_types_supported` containing `pairwise` and
`public`. It SHALL advertise `token_endpoint_auth_methods_supported`
containing `none`, `client_secret_basic`, and `client_secret_post`.
It SHALL NOT advertise implicit or password grants.

#### Scenario: Discovery names code and S256

- GIVEN a booted server
- WHEN `GET /.well-known/openid-configuration` is called
- THEN the document includes `authorization_endpoint`, `token_endpoint`,
  `jwks_uri`, `code`, and `S256`, and does not list `token` or `password`

#### Scenario: Discovery names confidential client auth

- GIVEN a booted server
- WHEN discovery is fetched
- THEN `token_endpoint_auth_methods_supported` includes
  `client_secret_basic` and `client_secret_post`

## ADDED Requirements

### Requirement: Confidential clients authenticate at /token

A confidential client SHALL present its secret via HTTP Basic or
`client_secret_post`. The system SHALL store only a hash of the
secret. A wrong or missing secret SHALL fail as `invalid_client`.
PKCE `S256` SHALL still be required.

#### Scenario: Wrong secret is refused

- GIVEN a confidential client
- WHEN `/token` is called with a valid code and the wrong secret
- THEN the response is `invalid_client` and no tokens are issued

#### Scenario: Public client still uses PKCE only

- GIVEN a public client registered with `none`
- WHEN `/token` is called with a valid code and matching verifier
- THEN tokens are issued without a client secret
