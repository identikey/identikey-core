# Story 7.4: Token Verification Service

**Status:** done
**Epic:** 7 - JWT Infrastructure  
**FR Coverage:** FR126 (token validation for refresh/introspection)  
**Story Key:** 7-4-token-verification-service

---

## Story

As the **auth system**,  
I want **to verify tokens issued by IdentiKey**,  
So that **token refresh and introspection work** and only valid tokens are accepted.

---

## Acceptance Criteria

### AC1: verifyToken(token) Returns Decoded Payload or Throws
- [x] `verifyToken(token: string)` returns the decoded JWT payload (claims) as a typed object
- [x] Verification uses the **local** public key from `getSigningKey().publicKey` (same key that signed the token). No HTTP fetch to JWKS in this story; JWKS endpoint is for external validators.
- [x] Uses `jose.jwtVerify(token, publicKey, options)` with options for issuer and audience validation
- [x] Returns payload type that includes at least `iss`, `sub`, `aud`, `exp`, `iat`, `jti`; plus optional `device_id`, `device_trust`, `auth_method`, `scope`, `email`, etc. (match what 7.3 signs)

### AC2: Signature and Claim Validation
- [x] Verifies signature against the known public key (EdDSA Ed25519)
- [x] Validates `exp` (token not expired), `iat` (optional: reject future iat if desired), `iss` (matches configured issuer)
- [x] Optional: validate `aud` (audience) when expected audience is configured
- [x] Clock skew: use small tolerance (e.g. a few seconds) for exp/iat to avoid rejections due to clock drift

### AC3: Structured Error on Failure
- [x] On failure (invalid signature, expired, wrong issuer, malformed token), throw a **typed error** (e.g. `TokenVerificationError`) with a stable code or reason (e.g. `EXPIRED`, `INVALID_SIGNATURE`, `INVALID_ISSUER`, `MALFORMED`) so callers can handle appropriately
- [x] Do not expose raw jose errors or stack traces to API consumers; wrap in structured error with safe message
- [x] Error must be distinguishable (e.g. subclass of Error or name/code) for refresh vs introspection flows (e.g. 401 vs 400)

---

## Tasks / Subtasks

- [x] **Task 1: Verification module** (AC: 1, 2)
  - [x] Create `src/lib/auth/jwt/verification.ts`
  - [x] Implement `verifyToken(token: string, options?: { issuer?: string; audience?: string | string[] })` using `jose.jwtVerify`
  - [x] Obtain public key via `getSigningKey().publicKey`; pass to `jwtVerify` with `issuer`, `audience`, and `clockTolerance` (e.g. 5–10 seconds)
  - [x] Return decoded payload (typed; can use `JWTPayload` from jose or extend with known claims)
  - [x] Read issuer/audience from options or env (IDENTIKEY_ISSUER, IDENTIKEY_AUDIENCE) to align with 7.3

- [x] **Task 2: Typed verification error** (AC: 3)
  - [x] Add `TokenVerificationError` in `src/lib/auth/errors.ts` (or keep in verification.ts and re-export). Include `code` or `reason`: `EXPIRED`, `INVALID_SIGNATURE`, `INVALID_ISSUER`, `INVALID_AUDIENCE`, `MALFORMED`
  - [x] In verification.ts catch jose errors (e.g. JWTExpired, JWSSignatureVerificationFailed, JWTClaimValidationFailed), map to TokenVerificationError with appropriate code

- [x] **Task 3: Exports** (AC: all)
  - [x] Export `verifyToken` and error type from `src/lib/auth/jwt/index.ts`

- [x] **Task 4: Tests** (AC: all)
  - [x] Unit tests in `src/lib/auth/jwt/verification.spec.ts`: sign a token with 7.3, verify with verifyToken, assert payload. Test expired token throws with EXPIRED; wrong issuer throws with INVALID_ISSUER; tampered token throws with INVALID_SIGNATURE; malformed string throws with MALFORMED
  - [x] Test: uninitialized key (getSigningKey throws) propagates or is handled

---

## Dev Notes

### Architecture Constraints
- **In-process verification:** This service runs in the same process as the signer. Use the local key from `getSigningKey()`; do not fetch JWKS from `/.well-known/jwks.json` for our own tokens. (External resource servers use the JWKS endpoint; see 7.2.)
- **Algorithm:** Only EdDSA; jose.jwtVerify will validate alg from header.
- **File location:** Architecture specifies `src/lib/auth/jwt/verification.ts`.

### Previous Stories (7.1–7.3) Intelligence
- **7.1/7.2:** `getSigningKey()` returns `SigningKeyPair` (privateKey, publicKey, kid). Public key is used for verification.
- **7.3:** Tokens are signed with `getSigningKey()`, header has `alg: 'EdDSA'`, `kid`. Issuer and audience come from env or params. Use same issuer/audience when verifying so validation passes.
- **jose:** `jwtVerify(token, publicKey, { issuer, audience, clockTolerance })` returns `{ payload, protectedHeader }`. Throws `JWTExpired`, `JWSSignatureVerificationFailed`, `JWTClaimValidationFailed` etc. Map these to TokenVerificationError.

### Security
- **Clock tolerance:** Use a small value (e.g. 5–10 s) to avoid rejecting valid tokens on minor clock skew; do not make it large enough to allow stale tokens.
- **Error messages:** Do not leak key material or internal details; use generic messages with a machine-readable code for logging and handling.

### References
- [Source: _bmad-output/planning-artifacts/epics.md#7.4] — AC and technical notes
- [Source: src/lib/auth/jwt/signing.ts] — token shape and issuer/audience (7.3)
- [Source: src/lib/auth/jwt/init.ts] — getSigningKey()
- [Source: src/lib/auth/errors.ts] — InvalidSigningKeyError pattern for new TokenVerificationError

### Developer Context (Guardrails)
- **Do not** add revocation checks in this story (no DB or cache lookup). Revocation is Epic 12; verification here is signature + claims only.
- **Do not** fetch JWKS over HTTP for verifying our own tokens; use local key only.
- **Do not** change signing or JWKS endpoint; only add verification API.

### Testing Requirements
- Use 7.3 signing to produce tokens; verify with verifyToken. Test success and each failure mode (expired, wrong iss, tampered, bad format). Assert error code/reason.

### Story Completion Status
- **Status:** done
- **Completion note:** All 4 tasks implemented and tested. 15 unit tests covering success, expired, wrong issuer, wrong audience, tampered signature, different key, malformed, empty string, uninitialized key, round-trip with 7.3 signAccessToken, and error class properties. Full suite: 204 tests pass, 0 regressions.

---

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6

### Debug Log References

- Fixed jose error mapping: `msg.includes('exp')` falsely matched "unexpected" in issuer/audience error messages. Switched to using jose's `claim` property on `JWTClaimValidationFailed` errors for precise mapping.
- Fixed vitest `instanceof` across `vi.resetModules()` boundaries by dynamically importing `TokenVerificationError` in the same module context as `verifyToken`.

### Completion Notes List

- Task 1: Created `src/lib/auth/jwt/verification.ts` with `verifyToken(token, options?)` using `jose.jwtVerify`. Uses local public key from `getSigningKey().publicKey`. Clock tolerance: 5 seconds. Issuer/audience from options or env vars.
- Task 2: Added `TokenVerificationError` class and `VerificationFailureCode` enum to `src/lib/auth/errors.ts`. Static `fromJoseError()` maps `JWTExpired`, `JWSSignatureVerificationFailed`, `JWTClaimValidationFailed` (with `claim` property) to typed codes: EXPIRED, INVALID_SIGNATURE, INVALID_ISSUER, INVALID_AUDIENCE, MALFORMED.
- Task 3: Exported `verifyToken`, `VerifyTokenOptions`, `TokenVerificationError`, `VerificationFailureCode` from `src/lib/auth/jwt/index.ts`.
- Task 4: 15 unit tests in `verification.spec.ts` covering: success (standard claims, custom claims, per-call overrides, round-trip with 7.3 signAccessToken), expired, wrong issuer, wrong audience, tampered payload, different signing key, malformed string, empty string, uninitialized key, error class properties, safe error messages.

### Change Log

- 2026-02-05: Implemented token verification service (Story 7.4). Added verifyToken, TokenVerificationError, 15 tests. All 204 tests pass.

### File List

- src/lib/auth/jwt/verification.ts (new)
- src/lib/auth/jwt/verification.spec.ts (new)
- src/lib/auth/errors.ts (modified — added TokenVerificationError, VerificationFailureCode)
- src/lib/auth/jwt/index.ts (modified — added verification and error exports)
