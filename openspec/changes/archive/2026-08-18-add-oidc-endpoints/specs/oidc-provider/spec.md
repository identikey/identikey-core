## ADDED Requirements

### Requirement: Discovery and JWKS

`identikey-server` SHALL serve OpenID discovery and a JWKS for the
token-signing key. Discovery SHALL advertise `response_types_supported`
containing `code` only, `code_challenge_methods_supported` containing
`S256`, and `subject_types_supported` containing `pairwise` and
`public`. It SHALL NOT advertise implicit or password grants.

#### Scenario: Discovery names code and S256

- GIVEN a booted server
- WHEN `GET /.well-known/openid-configuration` is called
- THEN the document includes `authorization_endpoint`, `token_endpoint`,
  `jwks_uri`, `code`, and `S256`, and does not list `token` or `password`

### Requirement: Authorization code with PKCE

`/authorize` SHALL accept `response_type=code` with PKCE `S256` and an
exact-match redirect URI. It SHALL refuse requests without
`code_challenge`, with `code_challenge_method` other than `S256`, or
with `response_type=token`. `/token` SHALL require the matching
`code_verifier`, SHALL reject a verifier when no challenge was stored,
and SHALL invalidate an authorization code after first use.

#### Scenario: Missing PKCE is refused

- GIVEN a registered public client
- WHEN `/authorize` is called without `code_challenge`
- THEN the request fails and no code is issued

#### Scenario: Code is one-time

- GIVEN a valid authorization code
- WHEN `/token` is called twice with the same code
- THEN the second call fails
