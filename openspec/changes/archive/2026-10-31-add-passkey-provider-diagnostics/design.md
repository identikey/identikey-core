# add-passkey-provider-diagnostics

## What the page may say

`NotAllowedError` and `AbortError` mean the prompt ended without a
credential. The browser does not say whether the person dismissed it,
whether it timed out, or whether no authenticator answered. The
status says the prompt was not completed and offers another try.
It does not say the account is missing.

`checkSupport` already treats a missing `PublicKeyCredential` and a
non-secure context as one `NotSupportedError`, and disables the
control. Keep that pairing. Do not split them into a guess about
which one failed when the page only knows the combined check.

`isUserVerifyingPlatformAuthenticatorAvailable` is not used. A true
result would not mean 1Password, iCloud, or Google Password Manager
is installed. A false result would not mean they are absent.

AAGUID stays the display hint from "Passkey rows name the
authenticator". This change does not read it to allow or refuse a
ceremony, and it does not add it to the copied report.

## Sanitized report

The copy includes only:

- ceremony stage, one of `support`, `prepare`, `prompt`, `finish`, or `deny`
  - `support`: `checkSupport` failed before any request
  - `prepare`: `POST /signup`, registration begin, login options renewal, or device assert begin failed before `navigator.credentials.create` or `get`
  - `prompt`: the browser prompt ran or ended without a credential
  - `finish`: the server rejected a credential the page already posted
  - `deny`: `POST /device/deny` failed
  A stage names an operation that ran. A prepare failure is not `prompt` or `finish`. A deny failure is not `prompt` or `finish`.
- whether the origin is a secure context
- whether `PublicKeyCredential` and `navigator.credentials` exist
- the error name
- the server error code and HTTP status when the server returned one

The copy excludes cookies, authorization codes, PKCE verifiers,
challenges, WebAuthn credential ids, raw `PublicKeyCredential`
payloads, recovery tokens, the managed key blob, and email addresses.
The existing technical `<pre>` stays on the page and is not the
clipboard payload.

The server error code is a string, or it is absent. An object or any other nested payload is omitted, even when the parsed response put one on the error.

If the clipboard write fails, the failure status stays, the page says the copy did not happen, and it does not say the report was copied.

No request is sent. Submission to a person or a tracker is a later
decision on `identikey-core-5gh.7`.
