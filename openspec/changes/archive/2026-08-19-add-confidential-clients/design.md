# Design — confidential clients, then Basic OP

Security: client secrets are hashed at rest (SHA-256), never logged.
Public clients keep `token_endpoint_auth_methods_supported` including
`none`. PKCE `S256` remains required even when a secret is presented.

## Auth methods

- `client_secret_basic` — `Authorization: Basic base64(id:secret)`
- `client_secret_post` — `client_id` + `client_secret` in the form
- `none` — public clients, PKCE only

Mismatch or missing secret on a confidential client is
`invalid_client`. A public client that sends a secret is
`invalid_client`.

## Registration

In-memory or env for v1 (same shape as `IDENTIKEY_CLIENT_ID` today),
enough to stand up two `basic` clients and one `post` client for the
suite. Persist later if needed; not a new table unless the store
already has a natural place.

## Basic OP

Plan id: `oidcc-basic-certification-test-plan`. Document the
command and login automation (suite will not paste a XID into
`/authorize/dev` by itself). Do **not** add a required GitHub job
until that plan is green locally. Config OP job stays as-is.

## Discovery

`token_endpoint_auth_methods_supported` becomes
`["none", "client_secret_basic", "client_secret_post"]`.
Do not advertise `password` or implicit.
