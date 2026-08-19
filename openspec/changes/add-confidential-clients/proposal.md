# add-confidential-clients

> **ACTIVE BUILD**

Activated from `identikey-core-ccf.12`.

**Rigor:** change

## Why

OIDF Basic OP will not referee this OP while discovery advertises
only `token_endpoint_auth_methods_supported: ["none"]`. Confidential
clients (`client_secret_basic` and `client_secret_post`) are the
missing product surface. PKCE `S256` stays required for every
client (checklist / RFC 9700).

## What

- Register and authenticate confidential clients
- Two extra clients besides the public one (Basic OP needs two
  `client_secret_basic` and one `client_secret_post`)
- Advertise those methods on discovery
- Document how to run `oidcc-basic-certification-test-plan` and
  how login is completed
- Capability `oidc-provider` (ADDED + MODIFIED)

## Impact

- Capabilities: ADDED + MODIFIED on `oidc-provider`
- ADRs: none

## User journey & surfaces

No new UI because confidential-client auth is token-endpoint
plumbing. The RP's token POST is the surface. Login at
`/authorize` stays the existing code+PKCE path (dev-login or
later passkeys).

## Out of scope

- Required Basic OP CI job until the plan can pass — living spec
  already forbids failing `main` for it
- DCR — not this slice
- URN grant — `add-urn-grant` / `ccf.5`
- Passkeys — `add-passkey-ceremonies` / `5gh.1`
- Official OIDF certification mark
