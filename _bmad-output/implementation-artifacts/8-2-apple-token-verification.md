# Story 8.2: Apple Token Verification

**Status:** done
**Epic:** 8 - Bootstrap Verification  
**FR Coverage:** FR101, FR102, FR103, FR104  
**Story Key:** 8-2-apple-token-verification

---

## Story

As the **auth system**,  
I want **to verify Apple identity tokens**,  
So that **I can trust the user's identity** for bootstrap provisioning (8.4) and Apple provision endpoint (Epic 10).

---

## Acceptance Criteria

### AC1: Verify Signature Against Apple JWKS
- [x]Apple identity token (JWT) is verified using the key-resolution function from 8.1: `getAppleJwkSet()`. Use `jose.jwtVerify(token, getAppleJwkSet(), options)`.
- [x]Invalid or tampered signature results in a typed error (e.g. `TokenVerificationError` with code `INVALID_SIGNATURE` or equivalent). Reuse or mirror the pattern from `src/lib/auth/jwt/verification.ts` and `TokenVerificationError.fromJoseError`.

### AC2: Validate Claims
- [x]`iss` (issuer) must equal `https://appleid.apple.com`. Reject with typed error if not.
- [x]`aud` (audience) must equal the configured Apple Services ID (e.g. from env `APPLE_SERVICES_ID` or passed as option). Reject with typed error if not.
- [x]`exp` must be in the future (token not expired). Use a small clock tolerance (e.g. 5 seconds) if desired. Reject with typed error (e.g. `EXPIRED`) if expired.

### AC3: Extract and Return Structured Result
- [x]On success, return a structured result containing at least: `sub`, `email` (optional), `email_verified` (optional), `is_private_email` (optional). Apple only sends email/name on first auth — so `email` may be absent on subsequent tokens; document this.
- [x]Type the result (e.g. `AppleTokenPayload` or `VerifyAppleTokenResult`) so callers (8.4, Epic 10) get typed fields.

### AC4: Typed Error on Failure
- [x]On verification failure (signature, issuer, audience, expired, malformed), throw a typed error so callers can distinguish and handle (e.g. 401 vs 400). Reuse `TokenVerificationError` and `VerificationFailureCode` from `src/lib/auth/errors.ts` where applicable, or introduce a thin wrapper (e.g. `AppleVerificationError` that extends or wraps it). Do not expose raw jose or fetch errors to API consumers.

### AC5: Configuration
- [x]Apple Services ID (audience) is configurable: either env var (e.g. `APPLE_SERVICES_ID`) or required option `audience` when calling the verify function. Document in README or .env.example.

---

## Tasks / Subtasks

- [x]**Task 1: Apple verification module** (AC: 1–4)
  - [x]Create `src/lib/auth/apple/verify.ts` (or `src/lib/auth/bootstrap/apple.ts` — align with 8.1 layout; architecture suggests `auth/apple/verify.ts`).
  - [x]Implement `verifyAppleToken(token: string, options: { audience: string })` (or `audience` optional with fallback to `process.env.APPLE_SERVICES_ID`). Call `jose.jwtVerify(token, getAppleJwkSet(), { issuer: APPLE_ISSUER, audience: options.audience, clockTolerance })`.
  - [x]Define and export type for the result (e.g. `AppleTokenPayload`: `sub: string`, `email?: string`, `email_verified?: boolean`, `is_private_email?: boolean`). Map JWT payload claims to this type (Apple uses `sub`, `email`, `email_verified`, and may use `is_private_email` for private relay).
  - [x]On jose error, use `TokenVerificationError.fromJoseError(err)` (or equivalent) and throw. On `ProviderJwksError` from getAppleJwkSet, let it propagate or wrap with a clear message.

- [x]**Task 2: Constants and config** (AC: 2, 5)
  - [x]Define Apple issuer constant: `https://appleid.apple.com` (per architecture and epics). Use it in `jwtVerify` options.
  - [x]Document `APPLE_SERVICES_ID` in .env.example or README. Require audience (either via option or env) so verification never runs with wrong/missing audience.

- [x]**Task 3: Exports and tests** (AC: all)
  - [x]Export `verifyAppleToken` and result type from `src/lib/auth/apple/index.ts` and re-export from `src/lib/auth/index.ts`.
  - [x]Unit tests: (1) with a real Apple token (fixture or test token), assert success and payload shape. (2) Tampered token → INVALID_SIGNATURE. (3) Wrong audience → INVALID_AUDIENCE. (4) Expired token → EXPIRED. (5) Wrong issuer → INVALID_ISSUER. Mock or use getAppleJwkSet; if using real Apple JWKS in tests, mark as integration or skip when offline.

---

## Dev Notes

### Architecture Constraints
- **Apple issuer:** `https://appleid.apple.com` (architecture + epics). Do not make it configurable; only audience is configurable.
- **Bootstrap only:** We verify the token; we do not call Apple APIs beyond JWKS (8.1). No user provisioning in this story (8.4).

### Previous Story (8.1) Intelligence
- **8.1 delivers:** `getAppleJwkSet()` in `src/lib/auth/provider-jwks/provider-jwks.ts`. Returns a `GetKeyFunction` for use with `jose.jwtVerify(token, getAppleJwkSet(), options)`.
- **Errors:** `ProviderJwksError` is thrown if JWKS resolution fails. Use it as-is or rethrow from verify.

### Apple Token Claims (reference)
- Apple sends: `iss`, `aud`, `sub`, `exp`, `iat`; and on first auth only: `email`, `email_verified`, and may send `is_private_email` for private relay. `sub` is stable across tokens for the same user.

### Reuse from 7.4
- `TokenVerificationError` and `VerificationFailureCode` in `src/lib/auth/errors.ts` already support EXPIRED, INVALID_SIGNATURE, INVALID_ISSUER, INVALID_AUDIENCE, MALFORMED. Use `TokenVerificationError.fromJoseError(err)` when jwtVerify throws. If jose error shape for remote JWK set differs, map similarly.

### References
- [Source: _bmad-output/planning-artifacts/epics.md#8.2] — AC and technical notes
- [Source: _bmad-output/planning-artifacts/architecture.md#Apple Identity Services] — issuer, JWKS URL
- [Source: src/lib/auth/provider-jwks/provider-jwks.ts] — getAppleJwkSet()
- [Source: src/lib/auth/jwt/verification.ts] — verifyToken, VerifyTokenOptions, jwtVerify usage
- [Source: src/lib/auth/errors.ts] — TokenVerificationError, VerificationFailureCode

### Developer Context (Guardrails)
- **Do not** implement user creation or Keycloak calls; that is 8.4. Only verify the token and return claims.
- **Do not** implement Google verification in this story; that is 8.3.
- **Do not** add HTTP endpoints; this is a library used by future `/api/apple-provision` (Epic 10).

### Testing Requirements
- Unit tests with fixture tokens or mocked getAppleJwkSet. Cover success (payload shape), wrong aud, wrong iss, expired, invalid signature, malformed token. Optional: one integration test that hits real Apple JWKS with a valid test token if available.

### Story Completion Status
- **Status:** done
- **Completion note:** Ultimate context engine analysis completed. Consumes 8.1 (Apple JWKS). Feeds 8.4 (provisioning) and Epic 10 (Apple provision endpoint).

---

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6

### Debug Log References

None — all tests passed on first run.

### Completion Notes List

- Implemented `verifyAppleToken()` in `src/lib/auth/apple/verify.ts` following the same pattern as `verifyToken()` in jwt/verification.ts
- Reuses `TokenVerificationError.fromJoseError()` for all jose error mapping (EXPIRED, INVALID_SIGNATURE, INVALID_ISSUER, INVALID_AUDIENCE, MALFORMED)
- Consumes `getAppleJwkSet()` from 8.1 for Apple JWKS key resolution
- Apple issuer hardcoded as `https://appleid.apple.com` (not configurable per architecture)
- Audience configurable via `options.audience` or `APPLE_SERVICES_ID` env var; throws if neither provided
- Returns typed `AppleTokenPayload` with `sub` (required), `email`, `email_verified`, `is_private_email` (all optional — Apple only sends email/name on first auth)
- 13 unit tests covering: success (5), expired (1), wrong issuer (1), wrong audience (1), invalid signature (2), malformed (2), missing audience config (1)
- `ProviderJwksError` propagates from `getAppleJwkSet()` without wrapping

### File List

- `src/lib/auth/apple/verify.ts` — Apple token verification function and types
- `src/lib/auth/apple/verify.spec.ts` — Unit tests (13 tests)
- `src/lib/auth/apple/index.ts` — Barrel exports
- `src/lib/auth/index.ts` — Updated to re-export Apple verification
