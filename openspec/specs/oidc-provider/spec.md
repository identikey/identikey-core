# oidc-provider

Living truth for the OIDC projection in `identikey-oidc` and the
routes on `identikey-server`. Folded from `add-pairwise-salt`,
`add-sub-seam`, `add-oidc-endpoints`, `add-dev-authorize`,
`add-refresh-lifecycle`, and `add-pairwise-export` (2026-08-18),
`add-oidf-conformance`, `add-confidential-clients`, and
`add-urn-grant` (2026-08-19), `add-passkey-ceremonies`
(2026-08-20), `add-hosted-login-ui` (2026-08-27),
`add-reference-reading-log` (2026-09-26), and
`add-client-sector-pin` (2026-10-27).

The refuse-list is `docs/oidc-implementation-checklist.md`. OIDF
Basic OP is documented locally and is not a required CI job.

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
`KDF(salt, xid, sector)`. `public` clients SHALL receive the base58btc
text form of the 32-byte XID. The XID SHALL remain the internal key; a
pairwise `sub` SHALL NOT be used as a database primary key. Hex SHALL
NOT appear as an identifier form.

#### Scenario: Two sectors differ

- GIVEN one XID and two clients with distinct sector identifiers
- WHEN `sub` is computed for each
- THEN the two values differ and neither equals the XID text form

#### Scenario: Same sector is stable

- GIVEN one XID and one pairwise client
- WHEN `sub` is computed twice
- THEN the values are identical

#### Scenario: public is the XID

- GIVEN a client with `subject_type=public`
- WHEN `sub` is computed
- THEN the value is the base58btc XID (same 32 bytes as the internal key)

### Requirement: Discovery and JWKS

`identikey-server` SHALL serve OpenID discovery and a JWKS for the
token-signing key. Discovery SHALL advertise `response_types_supported`
containing `code` only, `code_challenge_methods_supported` containing
`S256`, and `subject_types_supported` containing `pairwise` and
`public`. It SHALL advertise `token_endpoint_auth_methods_supported`
containing `none`, `client_secret_basic`, and `client_secret_post`.
It SHALL NOT advertise implicit or password grants. It SHALL
advertise `device_authorization_endpoint` and include
`urn:ietf:params:oauth:grant-type:device_code` in
`grant_types_supported`. Advertising the grant does not give it to a
client. A client receives `authorization_code` and `refresh_token`
unless its registration lists a different set.

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

#### Scenario: Discovery names the device grant

- GIVEN a booted server
- WHEN discovery is fetched
- THEN `grant_types_supported` includes
  `urn:ietf:params:oauth:grant-type:device_code` and
  `device_authorization_endpoint` is `{issuer}/device_authorization`

### Requirement: Device authorization is an explicit grant

`POST /device_authorization` SHALL mint an RFC 8628 device code only
for a client whose registration lists
`urn:ietf:params:oauth:grant-type:device_code`. The verification page
SHALL require a fresh passkey assertion whose challenge was stored on
that pending row, and an explicit confirmation. An account cookie
SHALL NOT approve the row. `verification_uri_complete` MAY prefill the
user code and MUST NOT skip confirmation. Polling
`urn:ietf:params:oauth:grant-type:device_code` SHALL mint the same
token response as the authorization-code grant, once. A client without
`authorization_code` SHALL receive `unauthorized_client` from
`/authorize` before redirect matching.

#### Scenario: A default client cannot start the device grant

- GIVEN a client registered without the device grant
- WHEN it calls `POST /device_authorization`
- THEN the response is `unauthorized_client` and no device code is issued

#### Scenario: Confirm is required

- GIVEN a pending device code whose user code was prefilled
- WHEN the verification page is shown
- THEN it names the client and shows the code, and the row stays pending
  until the person approves with a passkey

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

### Requirement: Config OP is CI-gated

CI SHALL run the OpenID Foundation **OIDC Config OP** plan
(`oidcc-config-certification-test-plan`) against a local
`identikey-server`. The suite SHALL NOT be a Rust crate
dependency. A failing Config OP plan SHALL fail the build. CI
SHALL NOT run OIDC Basic OP as a required job until that plan
is green locally.

#### Scenario: Config OP hits discovery

- GIVEN CI of this repository
- WHEN the conformance job runs
- THEN the Config OP plan GETs the server’s
  `/.well-known/openid-configuration` from a URL reachable
  inside the suite container

#### Scenario: A red Config OP plan fails the build

- GIVEN a Config OP test failure
- WHEN the job finishes
- THEN the workflow is failed

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

### Requirement: URN grant accepts only identikey-auth Response

`/token` SHALL accept
`grant_type=urn:identikey:params:oauth:grant-type:challenge-response`
with an `identikey-auth` `Response`. It SHALL refuse a WebAuthn
assertion for this grant and SHALL NOT mint tokens in that case.
Every issued `sub` SHALL be computed by the existing `subject()`
seam. `identikey-oidc` SHALL NOT hold a user private key.

#### Scenario: Valid Response mints tokens

- GIVEN a stored XID and a valid `identikey-auth` Response for it
- WHEN `/token` is called with the URN grant
- THEN access and ID tokens are issued with `sub` from `subject()`

#### Scenario: WebAuthn assertion is refused

- GIVEN a WebAuthn assertion bound to a passkey on the account
- WHEN `/token` is called with the URN grant and that assertion
- THEN the request fails and no tokens are issued

### Requirement: Passkey assertion can finish /authorize

When a user completes WebAuthn assertion during `/authorize` with
valid PKCE, the system SHALL issue an authorization code to the
registered redirect for that account's XID. A WebAuthn assertion
SHALL NOT satisfy the URN grant.

#### Scenario: Assertion issues a code

- GIVEN a registered passkey on a stored XID and a valid authorize
  request with PKCE S256
- WHEN assertion verifies
- THEN a code is issued to the registered redirect

### Requirement: Authorize login is the passkey page

When `IDENTIKEY_DEV_LOGIN` is unset, completing `/authorize` SHALL
send the user to `/authorize/passkey`. That page SHALL be the
production login surface.

#### Scenario: Authorize redirects to the passkey page

- GIVEN a registered public client and valid PKCE
- WHEN `GET /authorize` is called
- THEN the response redirects to `/authorize/passkey`
- AND that page is HTML for assertion, not the flag-gated dev form

### Requirement: Reference reading is recorded and not copied

The repository SHALL keep a reference-reading note at
`docs/oidc/reference-reading.md`. That note SHALL name ory/fosite,
panva/node-oidc-provider, and zitadel/oidc as Apache-2.0 or MIT
works that may be read and SHALL NOT be pasted into this tree. It
SHALL name kanidm as MPL-2.0 and read-only at a distance, with no
checkout in this repository. The note SHALL NOT contain source from
those projects. A later reading SHALL be recordable there as what
was consulted and what was decided, without a code excerpt.

#### Scenario: A note names the set

- GIVEN the reference-reading note
- WHEN someone looks up where to read about an OIDC ambiguity
- THEN fosite, node-oidc-provider, and zitadel/oidc are listed as
  readable and not to be pasted
- AND kanidm is listed as not to be checked out

#### Scenario: No reference source is committed

- GIVEN this repository
- WHEN the tree is searched for a checkout of those projects
- THEN none is present

### Requirement: Pairwise sector is registered, not derived

A pairwise client's sector identifier SHALL be part of its registration,
for both the primary client and clients in `IDENTIKEY_CLIENTS`, and SHALL be
the only sector input to its `sub`. The configured value SHALL reach the
subject function byte-for-byte, without trimming or normalization. Client
construction at boot and request time SHALL NOT derive a sector from a
redirect URI; only the operator preflight MAY compute the legacy derived
value, and only to compare it. The system SHALL refuse to start when a
pairwise client's sector is missing or empty, naming that client. A public
client SHALL NOT require a sector.

#### Scenario: Redirects change, identity does not

- GIVEN a pairwise client with sector `taskmaster.dev` and one redirect
- WHEN a redirect on another host is added before it, or the original redirect is replaced or removed
- THEN the `sub` for a given XID is unchanged

#### Scenario: Pinned legacy value preserves today's subject

- GIVEN a pairwise client whose pin equals the sector previously derived from its first merged redirect
- WHEN `sub` is computed for a given XID and salt
- THEN it equals the `sub` the previous derivation produced

#### Scenario: Missing sector refuses boot

- GIVEN a pairwise client registered with no sector or an empty one
- WHEN the server starts
- THEN startup fails and the error names that client

#### Scenario: Public client needs no sector

- GIVEN a client with `subject_type=public` and no sector
- WHEN the server starts
- THEN it starts and that client's `sub` is the base58btc XID

### Requirement: Client preflight compares pins with legacy sectors

The system SHALL provide an operator preflight that loads the complete
client configuration through the boot loader and reports, for each client,
its id, configuration source, subject type, pinned sector, and legacy
derived sector. It SHALL NOT output client secrets. It SHALL exit with
failure when the loader refuses the configuration or any pairwise client's
pin differs from its legacy value.

#### Scenario: Mismatched pin fails preflight

- GIVEN a pairwise client whose first redirect host is `taskmaster.dev` and whose pin is `www.taskmaster.dev`
- WHEN the preflight runs
- THEN it exits with failure and names that client

#### Scenario: Complete matching configuration passes

- GIVEN every pairwise client pinned to its legacy sector and every public client without one
- WHEN the preflight runs
- THEN it exits successfully and prints no secret
