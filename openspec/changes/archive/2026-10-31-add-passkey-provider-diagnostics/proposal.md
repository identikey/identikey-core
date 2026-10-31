# add-passkey-provider-diagnostics

> **ACTIVE BUILD**

Bead `identikey-core-5gh.7`. Node `identikey-core-zlf.5`.
Preparation 2026-10-30: living requirement "Recoverable hosted
authentication" in `openspec/specs/passkeys/spec.md` already
separates status copy from collapsed technical details.
`checkSupport` in `pages-common.js` disables the control when
`PublicKeyCredential` is missing or the origin is not a secure
context, and reports that as `NotSupportedError`. `showFailure`
already has distinct copy for `credential not found`,
`unknown or expired ceremony`, `NotAllowedError` / `AbortError`,
`SecurityError` / `NotSupportedError`, `NetworkError`, and HTTP 5xx.
`NotAllowedError` copy says the prompt may have been closed or timed
out. There is no copy action. Outcome: revised. Amended 2026-10-30 after
`reviews/2026-10-30-advise.md` (send-back, `astra-arch-review`):
the copied stage names `prepare` for a failure before the browser
prompt and `deny` for a failed device denial. Authority: the
account-keys first-wave grant on `identikey-core-zlf` ("activate
first wave"). It covers this dependency-ready node and does not
include act.

## Why

The page already tells the person that something failed. It still
collapses several different facts into one paragraph, and the only
record is the technical `<pre>`. A person who needs help cannot copy
a report that is safe to send, and a `NotAllowedError` must not be
read as proof that they cancelled, that the account is missing, or
that a provider is not installed.

## What

- Capability `passkeys`. Modify "Recoverable hosted authentication".
- Login (`/authorize/passkey`), signup, and device approval keep
  separate visible status for: WebAuthn unavailable or a non-secure
  context, an unfinished prompt (`NotAllowedError` or `AbortError`),
  an unregistered passkey, an expired ceremony, and a network or
  server failure.
- The unfinished-prompt status does not say the account is missing,
  that the person cancelled, or that a provider is absent.
- A copy control places a sanitized report on the clipboard.
- `isUserVerifyingPlatformAuthenticatorAvailable` is not an install
  detector. AAGUID is not an allowlist and is not an install detector.
- Diagnostics do not insert, list, or revoke a `credentials` row.

## Impact

- Capabilities: MODIFIED `passkeys`.
- ADRs: none.

## User journey & surfaces

The person is on `/authorize/passkey`, `/signup`, or the device
approval page. Those pages stay the ceremony pages they are now.
`pages-common.js` (`checkSupport`, `showFailure`) is the shared
failure path.

Working: a supported secure page still starts the prompt. After a
failure, the status title and description match that failure, the
technical details stay collapsed until opened, and Copy diagnostics
copies the sanitized report.

Empty: a browser with no passkey for this account still reaches the
prompt. The page does not invent a provider name.

Failed: each case below keeps the existing retry or disabled control.

- No `PublicKeyCredential`, or the origin is not a secure context:
  the control stays disabled and the status says passkeys are
  unavailable on this page.
- `NotAllowedError` or `AbortError`: the status says the prompt was
  not completed. It does not name a cause the browser did not give.
- `credential not found`: the existing "not registered here" status,
  with retry and signup.
- `unknown or expired ceremony`: the existing expired-attempt status.
- `NetworkError` or HTTP 5xx: the existing reachability status.

Off: there is no diagnostics flag. The copy control appears with the
failure status. A browser that refuses clipboard write leaves the
status on screen.

## Out of scope

- A support-submission route. The copy stays on this page.
  `identikey-core-5gh.7` still holds that later decision.
- A versioned browser/OS/provider compatibility matrix. The initial
  matrix is a human decision on `identikey-core-5gh.7`.
- Server-rendered QR (`identikey-core-5gh.5`, folded in
  `add-hybrid-transport`).
- Inserting, listing, or revoking credentials
  (`add-passkey-account-management`).
- Signal APIs (`add-passkey-signal-api`).
- Synced-passkey counter policy (`add-passkey-counter-policy`).
- Inferring which password manager is installed.
