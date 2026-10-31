# Tasks

- [x] Login, signup, and device approval show distinct status for an unavailable WebAuthn API or non-secure context, an unfinished prompt, an unregistered passkey, an expired ceremony, and a network or server failure
- [x] `NotAllowedError` and `AbortError` do not say the account is missing, that the person cancelled, or that a provider is not installed
- [x] Copy diagnostics writes the sanitized report and does not write cookies, authorization codes, PKCE verifiers, challenges, credential ids, raw ceremony payloads, recovery tokens, or email addresses
- [x] The page does not call `isUserVerifyingPlatformAuthenticatorAvailable` to claim a provider is installed or absent, and does not treat AAGUID as an allowlist
- [x] Tests cover the five statuses, the ambiguous-prompt wording, and a copy payload that contains the error name and omits a credential id

Out of scope: support submission, the compatibility matrix, server QR, credential insert/list/revoke, Signal APIs, and counter policy.

## Owed from advise (2026-10-30, astra-arch-review)

- [x] R1: The report stage is `support`, `prepare`, `prompt`, `finish`, or `deny`. `prepare` is signup, registration begin, login options renewal, or device assert begin before the prompt. `deny` is a failed `POST /device/deny`. Neither is labeled `prompt` or `finish`.
- [x] R1: Tests fail preparation before the browser prompt on login, signup, and device approval, and assert the copied stage is `prepare` and the prompt was not invoked. A failed device denial copies `deny`.
