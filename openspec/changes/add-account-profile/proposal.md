# add-account-profile

> **ACTIVE BUILD**

**Rigor:** change

## Why

First-party signup at `auth.identikey.me` currently ends with "return to
the app and sign in." The person who just created the account should
see that account: XID, custody rung, and passkeys. OIDC app signup
still returns to `/authorize/passkey`.

## What

- After hosted signup registration finishes, issue an HttpOnly account
  session cookie and send the browser to `GET /account`.
- `/account` shows the signed-in identity. No Elect export, no private
  keys, no pairwise `sub`.
- Missing cookie is a sign-in/signup prompt, not an implicit account.

## Impact

- Capabilities: ADDED on `passkeys`
- ADRs: none

## User journey & surfaces

A person opens `https://auth.identikey.me/signup`, creates a passkey,
and lands on `/account` showing their XID and that a passkey is saved.
An app-driven signup (`client_id` in the query) still returns to
`/authorize/passkey` to finish OIDC.

## Out of scope

- Credential nicknames / AAGUID — `identikey-core-5gh.2`
- Elect-key export at signup
- Pairwise `sub` on this page
- Wrapping to `managed_key_blob`
