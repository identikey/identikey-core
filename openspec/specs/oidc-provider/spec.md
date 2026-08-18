# oidc-provider

Living truth for the OIDC projection in `identikey-oidc` and the
routes on `identikey-server`. Folded from `add-pairwise-salt`,
`add-sub-seam`, `add-oidc-endpoints`, `add-dev-authorize`,
`add-refresh-lifecycle`, and `add-pairwise-export` (2026-08-18).

The refuse-list is `docs/oidc-implementation-checklist.md`. OIDF
Basic OP + Config OP CI is still `add-oidf-conformance`.

### Requirement: Pairwise salt is install-generated and non-rotating

The system SHALL generate a pairwise salt from the OS CSPRNG at first
boot when none is configured. It SHALL fail boot if the configured
value is empty or a placeholder. The committed tree SHALL NOT contain
a usable default salt. The salt SHALL NOT appear in logs or `/health`.
Rotation SHALL be unsupported.

#### Scenario: First boot creates a salt

- GIVEN no pairwise salt is configured
- WHEN the server boots
- THEN a salt is generated and subsequent pairwise `sub` values are
  stable for that deployment

#### Scenario: Placeholder salt fails closed

- GIVEN `IDENTIKEY_PAIRWISE_SALT` is empty or a known placeholder
- WHEN the server boots
- THEN boot fails and names the salt

### Requirement: One seam computes every token subject

Every OIDC `sub` SHALL be produced by a single function in
`identikey-oidc`. Pairwise clients SHALL receive
`KDF(salt, xid, sector)`. `public` clients SHALL receive the 64-hex
XID. The XID SHALL remain the internal key; a pairwise `sub` SHALL
NOT be used as a database primary key.

#### Scenario: Two sectors differ

- GIVEN one XID and two clients with distinct sector identifiers
- WHEN `sub` is computed for each
- THEN the two values differ and neither equals the XID hex

#### Scenario: Same sector is stable

- GIVEN one XID and one pairwise client
- WHEN `sub` is computed twice
- THEN the values are identical

#### Scenario: public is the XID

- GIVEN a client with `subject_type=public`
- WHEN `sub` is computed
- THEN the value is the 64-lowercase-hex XID

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

### Requirement: Dev login is flag-gated and absent in production

When `IDENTIKEY_DEV_LOGIN` is exactly `1`, `/authorize` SHALL be able
to complete for an XID that already exists in the store. When the
variable is unset, that login path SHALL NOT be registered. The flag
SHALL NOT create accounts. `/health` SHALL NOT report the flag.

#### Scenario: Flag on issues a code

- GIVEN `IDENTIKEY_DEV_LOGIN=1` and a stored C2 identity
- WHEN `/authorize` is completed as that XID with valid PKCE
- THEN a code is issued to the registered redirect

#### Scenario: Flag off has no login path

- GIVEN `IDENTIKEY_DEV_LOGIN` is unset
- WHEN a client requests the dev-login path
- THEN the response is 404 and no code is issued

### Requirement: Refresh tokens are hashed, rotated, and revocation-checked

The system SHALL persist only a SHA-256 hash of each refresh token.
A successful refresh SHALL issue a new refresh token and invalidate
the previous one. A revoked refresh token SHALL be rejected at both
the token endpoint (refresh grant) and `/introspect`.

#### Scenario: Rotation kills the old token

- GIVEN a valid refresh token T1
- WHEN `/token` is called with T1
- THEN a new refresh token T2 is returned and a later refresh with
  T1 fails

#### Scenario: Revoke is honoured on introspect

- GIVEN a refresh token that has been revoked
- WHEN `/introspect` is called with it
- THEN the response is inactive

### Requirement: Pairwise export reproduces issued subjects

A user’s export SHALL include enough material for a successor OP to
recompute every pairwise `sub` already issued for that user. A test
SHALL prove that `sub()` over the export matches the values previously
returned to clients. Export SHALL NOT write the salt to logs.

#### Scenario: Successor matches issued sub

- GIVEN a pairwise `sub` S issued to client C for XID H
- WHEN a successor computes `sub` from the user’s export for C
- THEN the result equals S
