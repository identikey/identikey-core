# Hosted passkey recovery

The Rust provider's `/authorize/passkey` and `/signup` pages share feedback,
diagnostics and styling. `pages.rs` embeds the adjacent `pages-*.js` and
`pages.css` files into the binary; rebuild and restart the provider to publish
changes. No frontend asset server or new package is required.

The journey is: choose a passkey → either return to the requesting app, or
recover using another passkey / an explicit new account. Both actions precede
longer help text. A new account is explicitly not account recovery. The browser
controls which password managers, security keys and nearby-device options it
offers; this page provides guidance rather than pretending to select them.

Unknown credentials, cancellation/timeouts, expired challenges, unsupported
browsers and network/service failures receive distinct messages. Native details
elements keep error code, description and HTTP status selectable for developers;
the original JSON API is unchanged. Error strings use textContent, never HTML.
Credentials, signatures and complete authorization URLs are not logged or
included in diagnostics.

Assertion retries fetch a fresh `/authorize/passkey` page and extract its new
ceremony options. The query is preserved, so the provider still validates the
request and binds the challenge to its pending OIDC authorization. The server's
single-use challenge and signature checks are unchanged.

Signup retries retain the account only in page memory after receiving signup
options and use `/webauthn/register/begin` for a new ceremony. Reloading the page,
or losing the initial signup response, cannot resume that memory; this change
does not introduce an account-recovery or cross-refresh enrollment protocol.
Successful enrollment keeps the original application context and explains why
the user is asked to choose the new passkey to finish sign-in.

## Verification

With the local OP running (`scripts/dev-server.sh`):

```sh
cd web && node --test scripts/hosted-auth.test.mjs
```

`IDENTIKEY_ORIGIN`, `IDENTIKEY_CLIENT_ID` and `IDENTIKEY_CLIENT_REDIRECT` point
it elsewhere (defaults match `.env.example`); `PLAYWRIGHT_EXECUTABLE_PATH`
replaces installed Google Chrome. It covers an actual unregistered virtual
authenticator, mocked API/browser failures, fresh retry challenges, safe
diagnostics, signup retry identity, preserved context, focus, and mobile
overflow. It creates no database accounts. Desktop/mobile screenshots are
written to the OS temp directory as `identikey-recovery-{desktop,mobile}.png`.

Signup retries call `/webauthn/register/begin`, which since 2026-09-28 requires
the new account's `identikey_account` session. `POST /signup` issues it, so a
retry in the same browser works and nobody else can add a passkey by XID.

Taskmaster's `bun run test:auth:local` separately exercises real enrollment,
assertion, OIDC/PKCE callback, logout and two-user isolation in its local databases.
Hardware authenticators and native password-manager chooser layouts remain a
manual check. The page cannot determine where an unrecognized passkey was
originally registered or recover access to that other installation.

Wired into `pages.rs` 2026-09-29 (the files had existed since 2026-09-19 without
being embedded; `hosted_pages_embed_recovery_ui` now pins that). Verified
against the local OP: nine browser recovery checks, the Rust page tests, the hosted
HTML/authorization routing tests, and Taskmaster's complete virtual-passkey
journey pass. The provider builds and the embedded scripts pass syntax checks.
Two existing Rust enrollment/assertion tests fail with `NotSupported`: their
`SoftPasskey` helper rejects `require_resident_key`, which this server requires.
The browser authenticator supports resident keys and exercises those actual
paths successfully; the security requirement was not weakened for the helper.
