# add-hosted-login-ui

> **ACTIVE BUILD**

**Rigor:** change

Activated from Taskmaster `nod-ik-hosted-login` after host ADR 0001.
Weave with Taskmaster `add-host-postgres`. Does not wait on
Taskmaster `add-oidc-rp`.

## Why

Production `/authorize/passkey` is inline HTML: a `<pre>` of
options and a script that calls `credentials.get`. That is enough
to issue codes and not a product surface. First-account signup has
no HTTP: `create_managed` exists; assertion still must not insert
accounts.

`web/` relocation (`ccf.11`) is not this change. Pages are served
by `identikey-server`.

## What

- Capability `passkeys` (ADDED): a real assertion page (usernameless
  `credentials.get`, conditional UI when the browser allows).
- Capability `passkeys` (ADDED): signup creates a C2 managed
  identity (`c2_native` + `create_managed`) then starts passkey
  registration. Assertion still refuses unknown credentials.
- Capability `oidc-provider` (ADDED): `/authorize/passkey` is that
  assertion page, not a debug dump.

## Impact

- Capabilities: ADDED on `passkeys`; ADDED on `oidc-provider`
- ADRs: none (implements existing passkey + C2 store)

## User journey & surfaces

An RP redirects to `/authorize`. The user lands on
`/authorize/passkey`.

- **Working** — returning user asserts a passkey; OP redirects with
  `code`. New user opens `/signup`, a C2 account is created, they
  enroll the first passkey, then they can complete `/authorize`.
- **Empty** — no credential: assertion fails; no account is
  inserted.
- **Failed** — cancelled WebAuthn or unknown credential: the page
  states the error; they can retry.
- **Off** — `IDENTIKEY_DEV_LOGIN` remains a separate flag-gated
  route.

Passkey prompts run on this origin only.

## Out of scope

- Relocating frozen SvelteKit to `web/` — `ccf.11`
- AAGUID nicknames / account passkey list — `5gh.2`
- User Elect-key download / Gordian export at signup (exit for C3
  climb). This slice creates C2 and an A3 passkey. Tracked as
  identikey-core follow-up, not Taskmaster.
- Consent page — parked (access-credential proof)
- Taskmaster RP chrome — `add-login-surfaces`
