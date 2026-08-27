# Design — hosted login / signup pages

Pages live in `identikey-server`, not the frozen repo-root SvelteKit
app. Relocating to `web/` is `ccf.11`.

## Assertion

Keep the existing ceremony JSON (`session` + `publicKey`). Replace
the debug `<pre>` with a short page: one primary control, then
`navigator.credentials.get`. Conditional mediation when supported.
On success, POST `/webauthn/assert/finish` (already bound to the
pending authorize) and follow the redirect.

## Signup

`KeysStore::create_managed` + `c2_native(user, ours)`. Server
generates both keys. `managed_key_blob` is ours. The user inception
private is **not** returned in this slice (Elect-key export is a
follow-up; passkey is A3 access to C2). Assertion still does not
create accounts.

Flow: GET `/signup` → POST `/signup` → registration options →
`credentials.create` → POST `/webauthn/register/finish`.

## Not this change

Account list, nicknames, consent UI, `web/` move.
