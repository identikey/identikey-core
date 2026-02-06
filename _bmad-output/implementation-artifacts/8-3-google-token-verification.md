# Story 8.3: Google Token Verification

**Status:** done
**Epic:** 8 - Bootstrap Verification
**FR Coverage:** FR105, FR106, FR107, FR108, FR109
**Story Key:** 8-3-google-token-verification

---

## Story

As the **auth system**,
I want **to verify Google identity tokens**,
So that **Android users can bootstrap their accounts** via Google Sign In and proceed to passkey enrollment (8.4) and Google provision endpoint (Epic 10).

---

## Acceptance Criteria

### AC1: Verify Signature Against Google JWKS
- Google identity token (JWT) is verified using the key-resolution function from 8.1: `getGoogleJwkSet()`. Use `jose.jwtVerify(token, getGoogleJwkSet(), options)`.
- Invalid or tampered signature results in a typed error (`TokenVerificationError` with code `INVALID_SIGNATURE`). Reuse the pattern from `src/lib/auth/apple/verify.ts` and `TokenVerificationError.fromJoseError`.

### AC2: Validate Claims
- `iss` (issuer) must equal `https://accounts.google.com` **or** `accounts.google.com`. Google uses both formats. Pass both as an array to `jwtVerify`'s `issuer` option: `issuer: ['https://accounts.google.com', 'accounts.google.com']`. Reject with typed error if neither matches.
- `aud` (audience) must equal the configured Google OAuth client ID (e.g. from env `GOOGLE_CLIENT_ID` or passed as option). Reject with typed error if not.
- `exp` must be in the future (token not expired). Use clock tolerance of 5 seconds (matching Apple implementation). Reject with typed error (`EXPIRED`) if expired.

### AC3: Extract and Return Structured Result
- On success, return a structured result containing: `sub` (required), `email` (optional), `email_verified` (optional), `name` (optional), `picture` (optional).
- Unlike Apple, Google provides profile info on every token (when scopes are granted), not just first auth. Document this difference.
- Type the result as `GoogleTokenPayload` so callers (8.4, Epic 10) get typed fields.

### AC4: Typed Error on Failure
- On verification failure (signature, issuer, audience, expired, malformed), throw a typed error so callers can distinguish and handle (e.g. 401 vs 400). Reuse `TokenVerificationError` and `VerificationFailureCode` from `src/lib/auth/errors.ts`. Do not expose raw jose or fetch errors to API consumers.

### AC5: Configuration
- Google OAuth Client ID (audience) is configurable: either env var `GOOGLE_CLIENT_ID` or required option `audience` when calling the verify function. Document in .env.example.

---

## Tasks / Subtasks

- [x] **Task 1: Google verification module** (AC: 1-4)
  - [x] Create `src/lib/auth/google/verify.ts` (mirror `src/lib/auth/apple/verify.ts` exactly).
  - [x] Implement `verifyGoogleToken(token: string, options?: VerifyGoogleTokenOptions): Promise<GoogleTokenPayload>`.
  - [x] Call `jose.jwtVerify(token, getGoogleJwkSet(), { issuer: ['https://accounts.google.com', 'accounts.google.com'], audience: options.audience, clockTolerance: 5 })`.
  - [x] Define and export `GoogleTokenPayload` interface: `sub: string`, `email?: string`, `email_verified?: boolean`, `name?: string`, `picture?: string`. Include JSDoc noting Google sends profile claims on every token (unlike Apple).
  - [x] Define and export `VerifyGoogleTokenOptions` interface with optional `audience` field.
  - [x] On missing audience: throw `TokenVerificationError` with code `MALFORMED` and message guiding to `options.audience` or `GOOGLE_CLIENT_ID` env var.
  - [x] On jose error: use `TokenVerificationError.fromJoseError(err)` and throw. On `ProviderJwksError` from `getGoogleJwkSet`, let it propagate.

- [x] **Task 2: Constants and config** (AC: 2, 5)
  - [x] Define Google issuer constants: `GOOGLE_ISSUER = 'https://accounts.google.com'` and `GOOGLE_ISSUER_ALT = 'accounts.google.com'`. Both are valid per Google OIDC spec.
  - [x] Document `GOOGLE_CLIENT_ID` in `.env.example`. Require audience (either via option or env) so verification never runs with wrong/missing audience.

- [x] **Task 3: Exports and barrel** (AC: all)
  - [x] Create `src/lib/auth/google/index.ts` — barrel export `verifyGoogleToken`, `GoogleTokenPayload`, `VerifyGoogleTokenOptions`.
  - [x] Update `src/lib/auth/index.ts` — add re-exports for `verifyGoogleToken` and types (mirror Apple pattern at lines 2-3).

- [x] **Task 4: Tests** (AC: all)
  - [x] Create `src/lib/auth/google/verify.spec.ts` mirroring `src/lib/auth/apple/verify.spec.ts`.
  - [x] Mock `getGoogleJwkSet` from `'../provider-jwks'` to return test public key (same pattern as Apple mock).
  - [x] Create `signGoogleToken()` helper with Google-specific claims (`sub`, `email`, `email_verified`, `name`, `picture`).
  - [x] **Success tests:** (1) Valid token returns `sub`. (2) All profile claims returned when present. (3) Profile claims undefined when absent. (4) Audience from options overrides env. (5) Both issuer formats accepted (`https://accounts.google.com` and `accounts.google.com`).
  - [x] **Error tests:** (1) Expired token → `EXPIRED`. (2) Wrong issuer → `INVALID_ISSUER`. (3) Wrong audience → `INVALID_AUDIENCE`. (4) Tampered token → `INVALID_SIGNATURE`. (5) Different key → `INVALID_SIGNATURE`. (6) Garbage string → `MALFORMED`. (7) Empty string → `MALFORMED`. (8) Missing audience config → error containing 'audience'.

---

## Dev Notes

### Architecture Constraints
- **Google issuers:** `https://accounts.google.com` AND `accounts.google.com` (both valid per Google OIDC spec). Pass both to `jwtVerify` as an array. Do NOT make issuers configurable — only audience is configurable.
- **Bootstrap only:** We verify the token; we do not call Google APIs beyond JWKS (8.1). No user provisioning in this story (that's 8.4).
- **Social login is NOT a Keycloak IDP:** Per ADR-008, IdentiKey verifies Google tokens directly via JWKS. Do not configure Google as a Keycloak Identity Provider.

### Previous Story (8.2) Intelligence
- **8.2 delivers:** `verifyAppleToken()` in `src/lib/auth/apple/verify.ts`. Follow this exact pattern.
- **Implementation learnings from 8.2:**
  - Uses `jose.jwtVerify(token, getAppleJwkSet(), { issuer, audience, clockTolerance })` — Google uses identical jose API.
  - Error handling: `TokenVerificationError.fromJoseError(err)` maps all jose errors. Rethrows `TokenVerificationError` unchanged, lets `ProviderJwksError` propagate.
  - Audience fallback: `options?.audience ?? process.env.APPLE_SERVICES_ID` — Google uses `GOOGLE_CLIENT_ID`.
  - Payload mapping: Casts optional claims with `as string | undefined`. Asserts `sub` with `!`.
  - Tests: 13 tests covering success (5), expired (1), wrong issuer (1), wrong audience (1), invalid signature (2), malformed (2), missing config (1). Google should have ~14 tests (extra test for alternate issuer format).
  - All 13 Apple tests passed on first run — no debugging needed.

### Previous Story (8.1) Intelligence
- **8.1 delivers:** `getGoogleJwkSet()` in `src/lib/auth/provider-jwks/provider-jwks.ts` (line 70-72). Already implemented and ready to consume.
- **Google JWKS URI:** `https://www.googleapis.com/oauth2/v3/certs` — already defined as `GOOGLE_JWKS_URI` constant.
- **Errors:** `ProviderJwksError` is thrown if JWKS resolution fails. Let it propagate from `getGoogleJwkSet()` without wrapping.

### Google Token Claims (reference)
- **Always present:** `iss`, `aud`, `sub`, `exp`, `iat`, `azp`
- **When email+profile scopes granted:** `email`, `email_verified`, `name`, `given_name`, `family_name`, `picture`, `locale`
- **Google Workspace only:** `hd` (hosted domain)
- **Key difference from Apple:** Google provides profile info on EVERY token (not just first auth). No need to cache first-auth data.
- **`sub`** is stable user identifier across all tokens for the same user.

### Reuse from 8.2 and Shared Infrastructure
- `TokenVerificationError` and `VerificationFailureCode` in `src/lib/auth/errors.ts` — already support EXPIRED, INVALID_SIGNATURE, INVALID_ISSUER, INVALID_AUDIENCE, MALFORMED. Use `TokenVerificationError.fromJoseError(err)`.
- `getGoogleJwkSet()` in `src/lib/auth/provider-jwks/provider-jwks.ts` — already implemented, returns `JwkSetKeyFunction` for use with `jose.jwtVerify`.
- Test pattern from `src/lib/auth/apple/verify.spec.ts` — mock `getGoogleJwkSet`, use RS256 key pair, dynamic imports, env var setup/teardown.

### Project Structure Notes
- **New files:** Create `src/lib/auth/google/` directory with `verify.ts`, `verify.spec.ts`, `index.ts` — mirrors `src/lib/auth/apple/` exactly per architecture doc project structure.
- **Modified files:** `src/lib/auth/index.ts` — add Google re-exports after Apple exports.
- **No other files modified.** No HTTP endpoints, no user provisioning, no Keycloak calls.

### References
- [Source: _bmad-output/planning-artifacts/epics.md#8.3] — AC and technical notes
- [Source: _bmad-output/planning-artifacts/architecture.md#Google Identity Services] — issuer, JWKS URL
- [Source: _bmad-output/planning-artifacts/architecture.md#Bootstrap Methods] — bootstrap flow pattern
- [Source: _bmad-output/planning-artifacts/architecture.md#ADR-008] — social login as bootstrap only
- [Source: src/lib/auth/provider-jwks/provider-jwks.ts:70-72] — getGoogleJwkSet()
- [Source: src/lib/auth/apple/verify.ts] — verifyAppleToken (pattern to mirror)
- [Source: src/lib/auth/apple/verify.spec.ts] — Apple tests (pattern to mirror)
- [Source: src/lib/auth/errors.ts] — TokenVerificationError, VerificationFailureCode
- [Source: Google OIDC Docs] — Both issuer formats valid: `https://accounts.google.com` and `accounts.google.com`
- [Source: Google OIDC Discovery] — Claims: sub, email, email_verified, name, picture, given_name, family_name, locale, hd

### Developer Context (Guardrails)
- **Do not** implement user creation or Keycloak calls; that is 8.4. Only verify the token and return claims.
- **Do not** implement Apple verification in this story; that is 8.2 (already done).
- **Do not** add HTTP endpoints; this is a library used by future `/api/google-provision` (Epic 10).
- **Do not** add `given_name`, `family_name`, `locale`, or `hd` to `GoogleTokenPayload` — keep it minimal for the bootstrap flow (sub, email, email_verified, name, picture). Callers can extend later if needed.
- **Do** accept both Google issuer formats. This is a documented Google requirement.
- **Do** follow Apple's implementation exactly — same error handling, same options pattern, same test structure.
- **Run tests with:** `bun vitest` (per CLAUDE.md).

### Testing Requirements
- Unit tests with RS256 key pair and mocked `getGoogleJwkSet`. Cover: success with all claims, success without optional claims, both issuer formats, wrong aud, wrong iss, expired, invalid signature (tampered + different key), malformed (garbage + empty), missing audience config.
- Expected: ~14 tests (13 mirroring Apple + 1 for alternate issuer format).

### Story Completion Status
- **Status:** ready-for-dev
- **Completion note:** Ultimate context engine analysis completed. Consumes 8.1 (Google JWKS via `getGoogleJwkSet()`). Mirrors 8.2 (Apple verification pattern). Feeds 8.4 (user provisioning) and Epic 10 (Google provision endpoint).

---

## Dev Agent Record

### Agent Model Used

{{agent_model_name_version}}

### Debug Log References

### Completion Notes List

- Implemented `verifyGoogleToken()` in `src/lib/auth/google/verify.ts` mirroring Apple pattern: `jose.jwtVerify` with `getGoogleJwkSet()`, dual issuers, audience from options or `GOOGLE_CLIENT_ID`, clock tolerance 5s. Exported `GoogleTokenPayload`, `VerifyGoogleTokenOptions`.
- Added `GOOGLE_CLIENT_ID` to `.env.example`. Created `src/lib/auth/google/index.ts` and re-exports in `src/lib/auth/index.ts`.
- 14 unit tests in `verify.spec.ts`: 6 success (sub, profile claims, optional absent, audience override, both issuer formats), 1 expired, 1 wrong issuer, 1 wrong audience, 2 invalid signature, 2 malformed, 1 missing audience. All 252 project tests pass (20 node test files); 21st file is browser/Playwright and fails in env without Playwright installed (pre-existing).

### File List

- `src/lib/auth/google/verify.ts` (new)
- `src/lib/auth/google/verify.spec.ts` (new)
- `src/lib/auth/google/index.ts` (new)
- `src/lib/auth/index.ts` (modified)
- `.env.example` (modified)
