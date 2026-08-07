# Story 9.2: Registration Challenge Generation

**Status:** done
**Epic:** 9 - Passkey Management
**FR Coverage:** FR110–118 (WebAuthn registration flow)
**Story Key:** 9-2-registration-challenge-generation

---

## Story

As a **user enrolling a passkey**,
I want **to receive a registration challenge**,
So that **my device can create a credential** and Epic 10’s POST /passkey-register can later verify the attestation (9.3).

---

## Acceptance Criteria

### AC1: Generate Registration Options via @simplewebauthn/server
- Use `@simplewebauthn/server`’s `generateRegistrationOptions()` to produce a WebAuthn registration options object.
- The library generates a random challenge (e.g. 32 bytes, base64url). We use that challenge as the single source of truth — store it and return it in the options.

### AC2: Relying Party (rp) Configuration
- Return options with `rp`: `id` (relying party id, e.g. hostname or configured `rpId`), `name` (human-readable name, e.g. "IdentiKey" or from env).
- `rpId` must be configurable (env var, e.g. `WEBAUTHN_RP_ID` or `RELYING_PARTY_ID`) so production can use the app domain. Document in `.env.example`.

### AC3: User (WebAuthn user object)
- Include `user` in options: `id` (required — stable opaque identifier; use Keycloak user ID or a consistent encoding of it so the same user gets the same `user.id` across challenges), `name` (optional, e.g. username or email), `displayName` (optional, e.g. display name).
- Caller provides `userId` (Keycloak) and optionally `userName` / `displayName`. This story defines the function signature; Epic 10 will pass the provisioned user’s id and name from 8.4.

### AC4: pubKeyCredParams and authenticatorSelection
- Include `pubKeyCredParams` supporting EdDSA, ES256, RS256 (or the library’s sensible default). Align with `@simplewebauthn/server` recommendations.
- Include `authenticatorSelection`: prefer platform authenticator (e.g. Face ID / Touch ID), resident key (discoverable credential) where supported. Exact flags depend on library API; document choices (e.g. `residentKey: 'preferred'`, `authenticatorAttachment: 'platform'` if we want platform-first).

### AC5: Store Challenge in DB with 5-Minute TTL
- After generating options, store the challenge via existing `createChallenge({ userId, challenge: options.challenge, type: 'registration' })` from 9.1. Use the exact challenge string returned by the library (base64url or whatever format the lib uses) so 9.3 can look it up with `getChallengeByValue`.
- If the library returns the challenge in a different format (e.g. buffer), convert to the string form that we store and that the client will send back (typically base64url).

### AC6: Return Full Options to Caller
- Return the registration options object (challenge, rp, user, pubKeyCredParams, authenticatorSelection, timeout, etc.) so the caller (e.g. Epic 10 POST /apple-provision or POST /passkey-register) can send it to the client. No HTTP in this story — expose a function that takes (userId, optional name/displayName) and returns the options object.

### AC7: Dependency and Types
- Add dependency `@simplewebauthn/server` (and types if needed). Use current stable version; document in story.

---

## Tasks / Subtasks

- [x] **Task 1: Add @simplewebauthn/server** (AC: 1, 7)
  - [x] Add `@simplewebauthn/server` to package.json (bun add @simplewebauthn/server). Check for peer deps (e.g. @simplewebauthn/browser not needed for server-only).
  - [x] Confirm `generateRegistrationOptions` exists and signature (e.g. rp, user, challenge length, etc.). Use library types for options and response.

- [x] **Task 2: Relying party config** (AC: 2)
  - [x] Add `WEBAUTHN_RP_ID` (and optionally `WEBAUTHN_RP_NAME`) to `.env.example`. Default rpId for dev (e.g. `localhost`) if not set.
  - [x] Create a small config helper or pass rp into the generation function so rpId/rpName come from env.

- [x] **Task 3: Registration options function** (AC: 1, 3, 4, 5, 6)
  - [x] Create `src/lib/passkey/registration-options.ts` (or under `src/lib/server/passkey/`). Implement e.g. `generateRegistrationChallenge(params: { userId: string; userName?: string; displayName?: string })` or similar.
  - [x] Call `generateRegistrationOptions` with: rp (id from env, name from env), user (id = userId or encoded userId, name, displayName), and any library-required fields. Use 32-byte challenge if the lib allows configuring length.
  - [x] After getting options, call `createChallenge({ userId, challenge: options.challenge, type: 'registration' })`. Ensure stored challenge string matches what the client will receive (same encoding).
  - [x] Return the full options object. If the library returns challenge as Buffer, convert to base64url string for storage and for the client (the lib often returns options already with a string challenge).

- [x] **Task 4: pubKeyCredParams and authenticatorSelection** (AC: 4)
  - [x] Pass through or set `pubKeyCredParams` (EdDSA, ES256, RS256) and `authenticatorSelection` (platform, residentKey) per library API. Prefer platform and resident key for mobile-first flows; document in code or dev notes.

- [x] **Task 5: Barrel / exports** (AC: all)
  - [x] Export the generation function (and any types) from a passkey module (e.g. `src/lib/passkey/index.ts` or `src/lib/server/passkey/index.ts`). Do not add HTTP routes in this story.

- [x] **Task 6: Tests** (AC: all)
  - [x] Unit tests: mock or do not call real DB; test that returned options contain challenge, rp, user; test that createChallenge is called with the same challenge and type 'registration'. Optionally integration test with in-memory/test DB: generate options, then getChallengeByValue(returned challenge) returns the row with correct userId.

---

## Dev Notes

### Architecture Constraints
- **Passkeys in Keycloak:** Credentials are stored in Keycloak (9.3). This story only produces the registration **challenge** and stores it in PostgreSQL (9.1). No attestation verification or credential storage here.
- **Epic 10 consumption:** POST /apple-provision and POST /google-provision (or a shared passkey-register flow) will: verify token, provision user (8.4), then call this story’s function to get registration options and return them (e.g. webauthn_challenge, rp_id, user) to the client. This story is library-only.

### Previous Story (9.1) Intelligence
- **9.1 delivers:** `createChallenge({ userId, challenge, type }, db?)` in `src/lib/server/challenges.ts`. Challenge is stored as string; `getChallengeByValue(challenge)` used by 9.3. Use the exact challenge string from the WebAuthn options so 9.3 can look it up.
- **Challenge format:** SimpleWebAuthn typically uses base64url for the challenge in the JSON sent to the client. Store that same string so lookup by value works.

### @simplewebauthn/server
- **Docs:** Check package README or types for `generateRegistrationOptions({ rp, user, ... })`. `user.id` is often a Uint8Array or buffer; the library may expect a base64url string or buffer — ensure we pass a stable user id (e.g. Keycloak userId as string encoded to buffer, or as-is if the lib accepts string).
- **Challenge:** Options object returned usually has `challenge` as string (base64url). Use it for createChallenge and for the response.

### rpId and Security
- `rpId` must match the origin/host that the client uses. For local dev, `localhost`; for production, the app domain. No trailing slash; subdomains have specific rules (see WebAuthn spec). Document in .env.example.

### Project Structure Notes
- **New:** `src/lib/passkey/registration-options.ts` (or `src/lib/server/passkey/registration-options.ts`), and barrel if needed. Optional: `src/lib/passkey/index.ts`.
- **Modified:** `package.json` (dependency), `.env.example` (WEBAUTHN_RP_ID, WEBAUTHN_RP_NAME). No routes in this story.

### References
- [Source: _bmad-output/planning-artifacts/epics.md#9.2] — AC and technical notes (generateRegistrationOptions, 32 bytes, store in DB).
- [Source: _bmad-output/planning-artifacts/architecture.md] — Registration flow, POST /passkey-register, challenge in response.
- [Source: src/lib/server/challenges.ts] — createChallenge, getChallengeByValue.
- [Source: @simplewebauthn/server] — generateRegistrationOptions API.

### Developer Context (Guardrails)
- **Do not** verify attestation or store credentials in Keycloak (9.3). Only generate options and store the challenge.
- **Do not** add POST /passkey-register or any HTTP in this story. Epic 10 will wire the endpoint.
- **Do** store the same challenge string that is returned to the client so 9.3 can look it up.
- **Do** make rpId configurable via env for production.
- **Run tests with:** `bun vitest` (per CLAUDE.md).

### Testing Requirements
- Unit tests: options contain challenge, rp, user; createChallenge called with correct challenge and type. Optional: integration test with test DB to confirm challenge is retrievable by value.

### Story Completion Status
- **Status:** done
- **Completion note:** Registration challenge generation via @simplewebauthn/server; store challenge with 9.1; return full options for client; rp and user config; ready for 9.3 attestation verification and Epic 10 endpoints. Code review fixes applied: stable userID, error handling, test coverage, type safety.

---

## Dev Agent Record

### Agent Model Used

Claude claude-4.6-opus (via Cursor)

### Debug Log References

No debug issues encountered.

### Completion Notes List

- Added `@simplewebauthn/server@13.2.3` dependency — no peer deps needed for server-only usage.
- Created `getWebAuthnConfig()` helper reading `WEBAUTHN_RP_ID` and `WEBAUTHN_RP_NAME` from env with sensible defaults (`localhost` / `IdentiKey`).
- Implemented `generateRegistrationChallenge({ userId, userName?, displayName?, excludeCredentials? }, db?)` which:
  - Validates userId is non-empty.
  - Calls `@simplewebauthn/server`'s `generateRegistrationOptions` with RP config, stable userID (TextEncoder-encoded Keycloak ID as Uint8Array), user info, platform authenticator preference, discoverable credential preference, explicit `supportedAlgorithmIDs: [-8, -7, -257]` (EdDSA, ES256, RS256), and `attestationType: 'none'`.
  - Persists the challenge string (base64url from library) via `createChallenge` from 9.1, with error wrapping.
  - Returns the full `PublicKeyCredentialCreationOptionsJSON` for the client.
  - Accepts optional `db` parameter for testability (passed through to createChallenge).
- Uses library's `AuthenticatorTransportFuture` type instead of local redefinition.
- Barrel export at `src/lib/passkey/index.ts`.
- 15 unit tests (mocked DB) + 1 integration test (real generateRegistrationChallenge → DB round-trip). All 308 project tests pass, zero regressions.

### Change Log

- 2026-02-25: Story 9.2 implemented — registration challenge generation via @simplewebauthn/server with DB persistence and env-configurable RP.
- 2026-02-25: Code review fixes — C1: pass stable userID (Uint8Array-encoded Keycloak ID) to generateRegistrationOptions; H1: tests now verify user.id stability; H2: integration test calls actual generateRegistrationChallenge with test DB; M1: error handling for challenge persistence; M2: use library AuthenticatorTransportFuture type; L1: userId validation; L2: explicit supportedAlgorithmIDs; added optional db param for testability. 308 tests pass, zero regressions.

### File List

- `package.json` (modified — added @simplewebauthn/server dependency)
- `bun.lock` (modified — lockfile update)
- `.env.example` (modified — added WEBAUTHN_RP_ID, WEBAUTHN_RP_NAME)
- `src/lib/passkey/registration-options.ts` (new — core generation function + config helper)
- `src/lib/passkey/index.ts` (new — barrel exports)
- `src/lib/passkey/registration-options.spec.ts` (new — 15 unit tests)
- `src/lib/passkey/registration-options.integration.spec.ts` (new — 1 integration test)
