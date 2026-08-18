# add-dev-authorize

> **ACTIVE BUILD**

Activated from `nod-dev-authorize`. No bead — do not wait for
`ccf.11` or `5gh.1`.

**Rigor:** change

## Why

`/authorize` cannot finish a login until passkeys or the account UI
exist. A local-only “continue as this XID” is how we get an app
hooked and how the OIDF suite has a user. It must be impossible in
production.

## What

- When `IDENTIKEY_DEV_LOGIN` is set, `/authorize` can complete as a
  known stored XID (test user).
- When the flag is unset, that path is absent; boot does not mention
  it; a request that looks like the dev login is ignored / 404.
- Capability `oidc-provider` (ADDED).

## Impact

- Capabilities: ADDED requirements on `oidc-provider`
- ADRs: none

## User journey & surfaces

Intended path (local only): operator sets the flag, opens
`/authorize?...`, picks or pastes a test XID, lands on the client's
redirect with a `code`.

No production UI. Account UI is `ccf.11`. Passkeys are `5gh.1`.

## Out of scope

- Production authentication
- Relocating SvelteKit — `ccf.11`
- OIDF job — `add-oidf-conformance`
