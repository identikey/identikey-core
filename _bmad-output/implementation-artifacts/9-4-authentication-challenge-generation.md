# Story 9.4: Authentication Challenge Generation

**Status:** done
**Epic:** 9 - Passkey Management
**FR Coverage:** FR110–118 (WebAuthn authentication flow)
**Story Key:** 9-4-authentication-challenge-generation

---

## Story

As a **returning user**,
I want **to receive an authentication challenge**,
So that **I can prove I own my passkey**.

---

## Acceptance Criteria

### AC1: Generate Authentication Options via @simplewebauthn/server
- Use `generateAuthenticationOptions()` from `@simplewebauthn/server` (already installed v13.2.3).
- Input: `rpID` (from env config), optional `allowCredentials`, optional `userVerification` preference.
- Return: `PublicKeyCredentialRequestOptionsJSON` containing `challenge`, `rpId`, `timeout`, `userVerification`, and optionally `allowCredentials`.

### AC2: Challenge Storage
- Store the generated challenge in DB via `createChallenge()` from 9.1 (`src/lib/server/challenges.ts`).
- Challenge type: `'authentication'`.
- `userId` on the challenge record: the provided userId if known, or `null` for discoverable credential flows (no userId known upfront).
- 5-minute TTL (handled by `createChallenge`).

### AC3: Allow Credentials (Known User)
- If `userId` is provided, look up the user's passkeys via `getPasskeysByUserId(userId)` from 9.3 (`src/lib/passkey/credential-store.ts`).
- Map stored passkeys to `allowCredentials` format: `{ id: credentialId, transports: parsedTransports }`.
- Parse the `transports` field from JSON string to `AuthenticatorTransportFuture[]`.
- If the user has no passkeys, return an error (cannot authenticate without credentials).

### AC4: Discoverable Credential Flow (No User)
- If no `userId` is provided, omit `allowCredentials` entirely — the client will prompt the user to select a discoverable credential.
- Store challenge with `userId: null`.
- This supports the "sign in with passkey" flow where the server doesn't know who the user is yet.

### AC5: Error Handling
- Typed errors for: user has no passkeys (when userId provided), challenge storage failure.
- Reuse `PasskeyError` and `PasskeyErrorCode` from 9.3 (`src/lib/passkey/errors.ts`) — add new error codes as needed.

### AC6: Function Signature (Library-Only, No HTTP)
- Expose a function like `generateAuthenticationChallenge(params?)` that returns `PublicKeyCredentialRequestOptionsJSON`.
- No HTTP routes in this story — Epic 10 will wire `POST /passkey-auth/start`.

---

## Tasks / Subtasks

- [x] **Task 1: Add error codes** (AC: 5)
  - [x] Add `NO_PASSKEYS_FOUND` to `PasskeyErrorCode` in `src/lib/passkey/errors.ts`.

- [x] **Task 2: Authentication challenge generation function** (AC: 1, 2, 3, 4, 5, 6)
  - [x] Create `src/lib/passkey/authentication-options.ts`.
  - [x] Implement `generateAuthenticationChallenge(params?: { userId?: string })` returning `Promise<PublicKeyCredentialRequestOptionsJSON>`.
  - [x] Use `getWebAuthnConfig()` from `registration-options.ts` for `rpID`.
  - [x] If `userId` provided: call `getPasskeysByUserId(userId)` from `credential-store.ts`. If no passkeys found, throw `PasskeyError` with `NO_PASSKEYS_FOUND`. Otherwise map to `allowCredentials` format (parse `transports` from JSON string).
  - [x] If no `userId`: omit `allowCredentials` (discoverable credential flow).
  - [x] Call `generateAuthenticationOptions({ rpID, allowCredentials?, userVerification: 'preferred' })`.
  - [x] Store challenge via `createChallenge({ userId: params?.userId ?? null, challenge: options.challenge, type: 'authentication' })`.
  - [x] Return the generated options.

- [x] **Task 3: Barrel exports** (AC: all)
  - [x] Export `generateAuthenticationChallenge` and any new types from `src/lib/passkey/index.ts`.

- [x] **Task 4: Tests** (AC: all)
  - [x] Unit tests (mock `getPasskeysByUserId`, mock `createChallenge`, mock `generateAuthenticationOptions`): happy path with known user + passkeys, discoverable credential flow (no userId), error case when user has no passkeys, challenge storage failure.
  - [x] Do NOT call real `generateAuthenticationOptions` in unit tests — mock it. Test orchestration logic.

---

## Dev Notes

### Architecture Constraints
- **ADR-007 deviation (9.3):** Passkeys are stored in PostgreSQL (`passkey_credentials` table), NOT Keycloak. The Keycloak Admin API lacks programmatic WebAuthn credential creation. Use `getPasskeysByUserId()` from `credential-store.ts` for credential lookups.
- **No HTTP routes:** This story is library-only. Epic 10 (`POST /passkey-auth/start`) will call `generateAuthenticationChallenge`.
- **Architecture flow:** See "Flow 2: Subsequent Logins" in architecture.md — `POST /passkey-auth/start` returns `{ challenge }`, then app triggers native passkey auth, then `POST /passkey-auth/finish` (story 9.5).

### Previous Story (9.3) Intelligence
- **9.3 delivers:** `verifyAndStorePasskey()`, `storePasskeyCredential()`, `getPasskeyByCredentialId()`, `getPasskeysByUserId()`, `updatePasskeyCounter()`, `deletePasskeyCredential()` in `src/lib/passkey/credential-store.ts`. `PasskeyError` and `PasskeyErrorCode` in `src/lib/passkey/errors.ts`. Passkey credentials stored in PostgreSQL `passkey_credentials` table.
- **Credential store schema:** `passkey_credentials` table: `id` (UUID), `userId` (text), `credentialId` (text, unique), `publicKey` (text, base64), `counter` (int), `transports` (text, JSON string or null), `deviceType` (text), `backedUp` (boolean), `createdAt`, `lastUsedAt`.
- **Pattern:** Tests mock `$lib/server/challenges` and `./credential-store` via `vi.mock()`. Follow same pattern.

### Previous Story (9.2) Intelligence
- **9.2 delivers:** `generateRegistrationChallenge()` and `getWebAuthnConfig()` in `src/lib/passkey/registration-options.ts`. Barrel at `src/lib/passkey/index.ts`.
- **Config helper:** `getWebAuthnConfig()` returns `{ rpId, rpName }` from env vars `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_NAME`. Defaults: `rpId='localhost'`, `rpName='IdentiKey'`.
- **Pattern:** This story (9.4) is structurally a mirror of 9.2, but for authentication instead of registration. Follow the same file/function naming pattern.

### Previous Story (9.1) Intelligence
- **9.1 delivers:** `createChallenge`, `getChallengeByValue`, `deleteChallenge`, `deleteChallengeByValue` in `src/lib/server/challenges.ts`.
- Challenge types: `'registration'` and `'authentication'` — 9.4 uses `'authentication'`.
- `createChallenge` accepts `{ userId: string | null, challenge: string, type: ChallengeType }`.

### @simplewebauthn/server v13.2.3 — generateAuthenticationOptions API
```typescript
import { generateAuthenticationOptions } from '@simplewebauthn/server';
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/server';

const options = await generateAuthenticationOptions({
  rpID: 'localhost',                   // required string
  allowCredentials: [{                 // optional — omit for discoverable
    id: 'credentialId-base64url',      // Base64URLString
    transports: ['internal', 'hybrid'] // AuthenticatorTransportFuture[]
  }],
  challenge: undefined,                // optional — auto-generated if omitted
  timeout: 60000,                      // optional — default 60000ms
  userVerification: 'preferred',       // optional — 'required' | 'preferred' | 'discouraged'
});

// options.challenge    — base64url string (auto-generated)
// options.rpId         — string
// options.timeout      — number
// options.allowCredentials — array or undefined
// options.userVerification — string
```

### Transport Parsing Note
- `passkey_credentials.transports` is stored as a JSON string (e.g., `'["internal","hybrid"]'`) or `null`.
- Must `JSON.parse()` it when mapping to `allowCredentials` format.
- Handle `null` transports gracefully — omit or pass `undefined`.

### Project Structure Notes
- **New:** `src/lib/passkey/authentication-options.ts` (authentication challenge generation function)
- **Modified:** `src/lib/passkey/errors.ts` (add `NO_PASSKEYS_FOUND` error code)
- **Modified:** `src/lib/passkey/index.ts` (barrel exports)
- **New:** `src/lib/passkey/authentication-options.spec.ts` (unit tests)

### References
- [Source: _bmad-output/planning-artifacts/epics.md#9.4] — AC and technical notes.
- [Source: _bmad-output/planning-artifacts/architecture.md#Flow-2] — Subsequent login flow: POST /passkey-auth/start.
- [Source: src/lib/server/challenges.ts] — createChallenge (type 'authentication').
- [Source: src/lib/passkey/credential-store.ts] — getPasskeysByUserId for allowCredentials.
- [Source: src/lib/passkey/registration-options.ts] — getWebAuthnConfig (reuse for rpID).
- [Source: @simplewebauthn/server] — generateAuthenticationOptions API.

### Developer Context (Guardrails)
- **Do not** verify assertions or issue tokens. Story 9.5 does assertion verification. Epic 10/12 handles tokens.
- **Do not** add HTTP routes. Epic 10 (`POST /passkey-auth/start`) will call this function.
- **Do** reuse `getWebAuthnConfig()` from `registration-options.ts` — don't recreate config loading.
- **Do** reuse `createChallenge` from `challenges.ts` with type `'authentication'`.
- **Do** look up passkeys from `credential-store.ts` (PostgreSQL), NOT Keycloak.
- **Do** support both known-user and discoverable-credential flows.
- **Do** parse `transports` JSON string from DB when building `allowCredentials`.
- **Run tests with:** `bun vitest` (per CLAUDE.md).

### Testing Requirements
- Unit tests: mock `generateAuthenticationOptions`, mock `createChallenge`, mock `getPasskeysByUserId`. Test: known user with passkeys (allowCredentials populated), discoverable credential flow (no userId, no allowCredentials), user with no passkeys throws error, challenge storage called correctly with type 'authentication', null userId for discoverable flow.
- Do NOT call real `generateAuthenticationOptions` — mock it. Test orchestration.

### Story Completion Status
- **Status:** review
- **Completion note:** Authentication challenge generation via @simplewebauthn/server; challenge storage from 9.1; credential lookup from 9.3; supports known-user and discoverable-credential flows; review hardening added typed input validation, guarded transport parsing, and consistent storage errors across registration/authentication helpers; ready for 9.5 assertion verification and Epic 10 endpoint wiring.

---

## Dev Agent Record

### Agent Model Used

Claude claude-4.6-opus (Cursor)

### Debug Log References

Senior review fixes applied for invalid input handling, malformed transport parsing, and consistent passkey challenge error semantics.

### Completion Notes List

- Added `NO_PASSKEYS_FOUND` error code to `PasskeyErrorCode` enum.
- Created `generateAuthenticationChallenge()` — mirrors the registration-options pattern for the authentication flow.
- Supports both known-user flow (looks up passkeys, populates `allowCredentials`) and discoverable credential flow (omits `allowCredentials`, stores challenge with `null` userId).
- Parses `transports` JSON string from DB when building `allowCredentials`, handles `null` transports gracefully.
- Throws `PasskeyError(NO_PASSKEYS_FOUND)` when a known user has no stored passkeys.
- Throws `PasskeyError(STORAGE_FAILED)` wrapping the cause when challenge persistence fails.
- Review hardening added typed invalid-input handling, guarded transport parsing with typed `INVALID_PASSKEY_DATA`, and removed userId leakage from auth errors.
- Review hardening aligned `generateRegistrationChallenge()` with `PasskeyError`/`STORAGE_FAILED` semantics used by authentication challenge generation.
- 13 authentication unit tests and 15 registration unit tests pass after the review fixes (28 targeted tests total).

### Change Log

- 2026-02-25: Implemented story 9-4 authentication challenge generation. Added `NO_PASSKEYS_FOUND` error code, created `authentication-options.ts`, updated barrel exports, authored 11 unit tests.
- 2026-02-25: Senior review fixes applied. Hardened `userId` validation, guarded stored transport parsing, removed userId leakage from auth errors, and aligned registration/authentication storage error handling. Expanded targeted passkey test coverage.

### File List

- `src/lib/passkey/errors.ts` (modified — added/expanded typed passkey error codes used by challenge generation hardening)
- `src/lib/passkey/authentication-options.ts` (new — `generateAuthenticationChallenge` function)
- `src/lib/passkey/index.ts` (modified — barrel exports for authentication-options)
- `src/lib/passkey/authentication-options.spec.ts` (new — expanded to cover invalid input, malformed transports, and typed error assertions)
- `src/lib/passkey/registration-options.ts` (modified during senior review — aligned typed input/storage error handling with authentication flow)
- `src/lib/passkey/registration-options.spec.ts` (modified during senior review — updated assertions for typed error handling)

## Senior Developer Review (AI)

### Reviewer

Master Dorje on 2026-02-25

### Outcome

Approved after fixes.

### Findings Fixed

- High: blank `userId` values no longer silently fall through to discoverable authentication; they now raise `PasskeyError(INVALID_INPUT)`.
- High: malformed stored `transports` JSON no longer explodes as a raw `SyntaxError`; it now raises `PasskeyError(INVALID_PASSKEY_DATA)`.
- Medium: auth error messages no longer embed raw `userId` values.
- Medium: authentication tests no longer double-invoke rejection paths just to inspect error metadata.
- Medium: malformed transport data now has direct unit coverage.
- Medium: registration challenge generation now uses the same typed storage/input error semantics as authentication challenge generation.

### Verification

- `bun vitest run src/lib/passkey/authentication-options.spec.ts src/lib/passkey/registration-options.spec.ts`
