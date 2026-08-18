# add-oidc-endpoints

> **ACTIVE BUILD**

Activated from `nod-oidc-endpoints` (`identikey-core-ccf.4`).

**Rigor:** change

## Why

An app cannot speak OIDC until discovery, JWKS, `/authorize`,
`/token`, `/userinfo`, `/introspect`, and `/revoke` exist. The
checklist (`ccf.1`) is the refuse-list; this change implements only
what that file allows.

## What

- `GET /.well-known/openid-configuration` and `jwks_uri`
- `/authorize` (code + PKCE `S256`; no implicit, no ROPC)
- `/token` (authorization_code; refresh if already specified)
- `/userinfo`, `/introspect`, `/revoke`
- Wire them on `identikey-server`
- Capability `oidc-provider` (ADDED)

## Impact

- Capabilities: ADDED requirements on `oidc-provider`
- ADRs: none (RFC 9700 via the checklist)

## User journey & surfaces

No new UI because login at `/authorize` is `add-dev-authorize`.
This change may leave `/authorize` unable to finish a login until
that node lands.

Intended path once login exists: RP hits discovery → authorize
(PKCE) → token → userinfo.

## Out of scope

- Dev “continue as XID” — `add-dev-authorize`
- OIDF CI — `add-oidf-conformance`
- Refresh storage model — `add-refresh-lifecycle` (endpoint stubs ok)
- URN grant — `ccf.5`
- Production passkeys — `5gh.1`
- Checklist file — must already exist (`ccf.1`)
