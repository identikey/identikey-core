# Story 9.3: Attestation Validation & Storage

**Status:** done
**Epic:** 9 - Passkey Management
**FR Coverage:** FR110–118 (WebAuthn registration flow)
**Story Key:** 9-3-attestation-validation-storage

---

## Story

As the **auth system**,
I want **to validate passkey attestation and store the credential**,
So that **the passkey can be used for authentication** in 9.5 and via Epic 10 endpoints.

---

## Acceptance Criteria

### AC1: Verify Registration Response via @simplewebauthn/server
- Use `verifyRegistrationResponse()` from `@simplewebauthn/server` (already installed v13.2.3 in 9.2).
- Input: the attestation response from the client, the expected challenge, expected origin, and expected rpId.
- Return structured verification result on success; throw typed error on failure.

### AC2: Challenge Lookup and Deletion
- Before verification, look up the challenge in DB using `getChallengeByValue(challenge)` from 9.1 (`src/lib/server/challenges.ts`).
- If challenge not found or expired, reject with a clear error.
- After successful verification, delete the used challenge via `deleteChallengeByValue(challenge)` so it cannot be reused.

### AC3: Extract Credential Data
- On successful verification, extract from `registrationInfo`:
  - `credential.id` (credential ID string)
  - `credential.publicKey` (Uint8Array — the public key bytes)
  - `credential.counter` (sign count, number)
  - `credential.transports` (optional array of transport hints)
  - `credentialDeviceType` ("singleDevice" or "multiDevice")
  - `credentialBackedUp` (boolean)
- Return this data in a structured result type for the caller (Epic 10) to store and use.

### AC4: Store Credential in Keycloak via Admin API
- Store the verified passkey credential in Keycloak's user credential store using the Admin API.
- The Keycloak Admin REST API path for creating credentials is: `PUT /admin/realms/{realm}/users/{id}/credentials/{credentialId}` or raw creation. **Investigation required** — the Keycloak Admin Client doesn't expose a direct "create WebAuthn credential" method. Options:
  - A) Use `client.users.updateCredential` or raw REST call to store credential data as a Keycloak `CredentialRepresentation` with type `webauthn`.
  - B) If Keycloak Admin API doesn't support programmatic WebAuthn credential creation (likely), store in IdentiKey's own PostgreSQL DB instead and document the deviation from ADR-007.
- Support multiple passkeys per user (different credential IDs).
- If Keycloak storage isn't feasible, add a `passkey_credentials` table to Drizzle schema as fallback.

### AC5: Attestation Format Support
- Support attestation formats: `none` (most common from platform authenticators), `packed`, `fido-u2f`.
- Be permissive — `attestationType: 'none'` was set in 9.2's `generateRegistrationOptions`, so most responses will have `none` format.
- The `verifyRegistrationResponse` library handles format parsing; just ensure we don't reject valid formats.

### AC6: Error Handling
- Typed errors for: invalid attestation, challenge not found, challenge expired, verification failure, Keycloak/DB storage failure.
- Error messages should be diagnostic enough for debugging without leaking internals to clients.

### AC7: Function Signature (Library-Only, No HTTP)
- Expose a function like `verifyAndStorePasskey(params)` that takes the attestation response, challenge string, userId, and returns the stored credential info.
- No HTTP routes in this story — Epic 10 will wire the endpoint.

---

## Tasks / Subtasks

- [x] **Task 1: Investigate Keycloak credential storage** (AC: 4)
  - [x] Research Keycloak Admin REST API for creating WebAuthn credentials programmatically. Check if `CredentialRepresentation` with type `webauthn` can be POSTed/PUTed via the admin client. Check the `@keycloak/keycloak-admin-client` source for credential creation methods beyond `getCredentials` and `deleteCredential`.
  - [x] If Keycloak supports it: document the API call and credential format. If not: design a `passkey_credentials` table in Drizzle (credentialId, userId, publicKey as base64, counter, transports as JSON, deviceType, backedUp, createdAt, lastUsedAt) and document the ADR-007 deviation.

- [x] **Task 2: Credential storage implementation** (AC: 4)
  - [x] Based on Task 1 findings: implement either Keycloak Admin API credential creation OR Drizzle-based `passkey_credentials` table with migration.
  - [x] Implement `storePasskeyCredential({ userId, credentialId, publicKey, counter, transports, deviceType, backedUp })` function.
  - [x] Implement `getPasskeyByCredentialId(credentialId)` for later use by 9.5 (assertion verification).
  - [x] Ensure multiple passkeys per user are supported.

- [x] **Task 3: Attestation verification function** (AC: 1, 2, 3, 5, 6, 7)
  - [x] Create `src/lib/passkey/verify-registration.ts`. Implement `verifyAndStorePasskey(params: { attestationResponse, challenge, userId })`.
  - [x] Look up challenge via `getChallengeByValue(challenge)`. If not found, throw typed error.
  - [x] Validate `challenge.userId === userId` — the challenge must belong to this user.
  - [x] Call `verifyRegistrationResponse({ response: attestationResponse, expectedChallenge: challenge, expectedOrigin, expectedRPID })`. Use `getWebAuthnConfig()` from 9.2 for rpId. Origin must be configurable (env var `WEBAUTHN_EXPECTED_ORIGIN` or derived from rpId).
  - [x] On success, extract credential data from `registrationInfo` (credential.id, credential.publicKey, credential.counter, credential.transports, credentialDeviceType, credentialBackedUp).
  - [x] Store credential via Task 2's storage function.
  - [x] Delete used challenge via `deleteChallengeByValue(challenge)`.
  - [x] Return structured result: `{ credentialId, publicKey, counter, transports, deviceType, backedUp, userId }`.

- [x] **Task 4: Origin configuration** (AC: 1)
  - [x] Add `WEBAUTHN_EXPECTED_ORIGIN` to `.env.example`. For dev: `http://localhost:5173` or similar. For production: `https://connect.identikey.io`. The origin must match what the client's browser/app sends. For native mobile apps, this may be the app's origin or `android:apk-key-hash:...` / iOS equivalent.
  - [x] `verifyRegistrationResponse` accepts `expectedOrigin` as string or string[]. Support array for multiple origins.

- [x] **Task 5: Barrel exports** (AC: all)
  - [x] Export `verifyAndStorePasskey` and result types from `src/lib/passkey/index.ts`. Also export credential storage functions if they're in a separate module.

- [x] **Task 6: Tests** (AC: all)
  - [x] Unit tests (mock DB + mock `verifyRegistrationResponse`): test that challenge is looked up, verified, credential is stored, challenge is deleted. Test error cases: challenge not found, challenge userId mismatch, verification failure, storage failure.
  - [x] Do NOT call real `verifyRegistrationResponse` with actual WebAuthn data in unit tests — mock it. The library is well-tested; we test our orchestration.

---

## Dev Notes

### Architecture Constraints
- **ADR-007 (Passkeys in Keycloak):** The architecture states passkeys should be stored in Keycloak's credential store. However, the Keycloak Admin API may not support programmatic WebAuthn credential creation — this is the key risk. If Keycloak doesn't support it, store in PostgreSQL and document the deviation. The existing `UserService.getCredentials()` and `UserService.deleteCredential()` in `src/lib/keycloak/services/users.ts` work for listing/deleting but use Keycloak's `CredentialRepresentation` which may not support creating WebAuthn credentials.
- **No HTTP routes:** This story is library-only. Epic 10 (`POST /passkey-register`) will call `verifyAndStorePasskey`.

### Previous Story (9.2) Intelligence
- **9.2 delivers:** `generateRegistrationChallenge({ userId, userName?, displayName? })` in `src/lib/passkey/registration-options.ts`. Returns `PublicKeyCredentialCreationOptionsJSON` with challenge stored in DB. The challenge string is base64url (from `@simplewebauthn/server`).
- **Config helper:** `getWebAuthnConfig()` returns `{ rpId, rpName }` from env vars `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_NAME`.
- **Barrel:** `src/lib/passkey/index.ts` exports everything.
- **Dependency:** `@simplewebauthn/server@13.2.3` already installed.
- **Pattern:** Tests mock `$lib/server/challenges` via `vi.mock()`. Follow same pattern.

### Previous Story (9.1) Intelligence
- **9.1 delivers:** `createChallenge`, `getChallengeByValue`, `deleteChallenge`, `deleteChallengeByValue` in `src/lib/server/challenges.ts`. Challenge rows have: `id`, `userId`, `challenge` (string), `type`, `expiresAt`, `createdAt`.
- **Test utils:** `withTestDb` in `src/lib/server/db/test-utils.ts` wraps tests in a rollback transaction. Use for integration tests.

### @simplewebauthn/server v13.2.3 — verifyRegistrationResponse API
```typescript
import { verifyRegistrationResponse } from '@simplewebauthn/server';

const verification = await verifyRegistrationResponse({
  response: body,                    // RegistrationResponseJSON from client
  expectedChallenge: challenge,      // base64url string from DB
  expectedOrigin: origin,            // string or string[]
  expectedRPID: rpID,                // string or string[]
});

const { verified, registrationInfo } = verification;
// registrationInfo.credential.id         — string (credential ID)
// registrationInfo.credential.publicKey  — Uint8Array
// registrationInfo.credential.counter    — number
// registrationInfo.credential.transports — AuthenticatorTransportFuture[] | undefined
// registrationInfo.credentialDeviceType  — "singleDevice" | "multiDevice"
// registrationInfo.credentialBackedUp    — boolean
```

### Keycloak Credential API Surface
- `UserService.getCredentials(userId)` → `Credential[]` (id, type, userLabel, createdDate)
- `UserService.deleteCredential(userId, credentialId)` → void
- `mapKeycloakCredential` maps `CredentialRepresentation` → `Credential`
- The `@keycloak/keycloak-admin-client` `users.getCredentials` and `users.deleteCredential` are available. **No `users.createCredential` for WebAuthn type.** Keycloak normally creates WebAuthn credentials through its own authentication flow, not via Admin API.
- **Likely outcome:** Store passkeys in PostgreSQL (IdentiKey DB) rather than Keycloak. This is fine — the architecture doc's "Passkeys in Keycloak" decision was aspirational and noted "Investigate" as a risk.

### Fallback Schema (if Keycloak storage isn't feasible)
```sql
CREATE TABLE passkey_credentials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT NOT NULL,                -- Keycloak user ID
  credential_id TEXT NOT NULL UNIQUE,   -- WebAuthn credential ID (base64url)
  public_key TEXT NOT NULL,             -- Public key bytes as base64
  counter INTEGER NOT NULL DEFAULT 0,   -- Sign count for replay protection
  transports TEXT,                      -- JSON array of transport hints
  device_type TEXT NOT NULL,            -- "singleDevice" or "multiDevice"
  backed_up BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_passkey_credentials_user_id ON passkey_credentials(user_id);
```

### Project Structure Notes
- **New:** `src/lib/passkey/verify-registration.ts` (attestation verification + storage orchestration)
- **New (likely):** `src/lib/passkey/credential-store.ts` (credential CRUD — either Keycloak or Drizzle-backed)
- **New (if DB fallback):** Drizzle schema addition in `src/lib/server/db/schema.ts` for `passkey_credentials`, plus migration
- **Modified:** `src/lib/passkey/index.ts` (barrel exports)
- **Modified:** `.env.example` (WEBAUTHN_EXPECTED_ORIGIN)

### References
- [Source: _bmad-output/planning-artifacts/epics.md#9.3] — AC and technical notes.
- [Source: _bmad-output/planning-artifacts/architecture.md#ADR-007] — Passkeys in Keycloak decision.
- [Source: src/lib/server/challenges.ts] — getChallengeByValue, deleteChallengeByValue.
- [Source: src/lib/passkey/registration-options.ts] — getWebAuthnConfig, 9.2 implementation.
- [Source: src/lib/keycloak/services/users.ts] — getCredentials, deleteCredential (existing API).
- [Source: @simplewebauthn/server docs] — verifyRegistrationResponse API.

### Developer Context (Guardrails)
- **Do not** add HTTP routes. Epic 10 wires the endpoint.
- **Do not** issue tokens. Epic 10/12 handles token issuance.
- **Do** delete the used challenge after successful verification (replay protection).
- **Do** validate that the challenge's userId matches the provided userId.
- **Do** investigate Keycloak Admin API first (Task 1) before falling back to Drizzle.
- **Do** store publicKey as base64 string (not raw bytes) for portability.
- **Do** support multiple passkeys per user.
- **Run tests with:** `bun vitest` (per CLAUDE.md).

### Testing Requirements
- Unit tests: mock `verifyRegistrationResponse`, mock `getChallengeByValue` and `deleteChallengeByValue`. Test happy path (challenge found → verification passes → credential stored → challenge deleted → result returned). Test errors: challenge not found, userId mismatch, verification failure, storage failure.
- Optional integration test: use `withTestDb` to test credential storage round-trip if using Drizzle fallback.

### Story Completion Status
- **Status:** done
- **Completion note:** Attestation verification via @simplewebauthn/server; challenge lookup and deletion from 9.1; credential storage in PostgreSQL (Drizzle fallback — Keycloak Admin API lacks WebAuthn credential creation). Ready for 9.5 auth verification and Epic 10 endpoint wiring.

---

## Change Log

- **2026-02-25:** Story implemented — attestation verification via `@simplewebauthn/server`, credential storage in PostgreSQL (ADR-007 deviation: Keycloak Admin API lacks WebAuthn credential creation), challenge lifecycle management, typed error handling. 37 passkey tests, 329 total tests pass.
- **2026-02-25:** Code review fixes — wrapped challenge deletion in try/catch (H2), removed dead `CHALLENGE_EXPIRED` error code (M1), added defensive check for `storePasskeyCredential` return (M2), amended ADR-007 in architecture.md (H1), updated File List with drizzle meta files (M3).

---

## Dev Agent Record

### Agent Model Used

Claude claude-4.6-opus (Cursor)

### Code Review Notes

- **C1 (git history):** Story 9.3 implementation files were committed inside the 9-2 commit (`9a7593d`). Schema changes (`schema.ts`, migration) left uncommitted, meaning HEAD was temporarily broken. Cannot fix without history rewrite — documented here for awareness.
- **M4 (git history):** Same root cause as C1. Git log attributes 9.3 files to story 9-2.
- **H1 (architecture):** ADR-007 amended in `architecture.md` to reflect PostgreSQL storage deviation.
- **H2 (error handling):** `deleteChallengeByValue` now wrapped in try/catch — credential is already stored, so deletion failure is swallowed.
- **M1 (dead code):** Removed `CHALLENGE_EXPIRED` from `PasskeyErrorCode` — `getChallengeByValue` auto-deletes expired challenges and returns null, making the distinction impossible at this API level.
- **M2 (defensive check):** `storePasskeyCredential` now throws `PasskeyError(STORAGE_FAILED)` instead of `!` assertion on empty return.
- **L1/L2 (low):** Noted for future stories. Origin config consolidation and base64 vs base64url encoding are downstream concerns for 9.5/Epic 10.

### Debug Log References

- Task 1 investigation confirmed: `@keycloak/keycloak-admin-client` has no `createCredential` or equivalent for WebAuthn type. Keycloak creates WebAuthn creds through its own auth flow only. Drizzle/PostgreSQL fallback used per ADR-007 risk note.
- vi.mock hoisting issue: `mockPublicKey` referenced in factory was in TDZ. Fixed by inlining the base64 string literal.

### Completion Notes List

- ✅ Keycloak Admin API investigated — no programmatic WebAuthn credential creation; storing in PostgreSQL via Drizzle (ADR-007 deviation documented)
- ✅ `passkey_credentials` table added to Drizzle schema with migration applied to dev + test DBs
- ✅ `credential-store.ts` — full CRUD: store, getByCredentialId, getByUserId, updateCounter, delete
- ✅ `verify-registration.ts` — `verifyAndStorePasskey()` orchestrates: challenge lookup → userId validation → attestation verification → credential storage → challenge deletion
- ✅ `errors.ts` — `PasskeyError` with typed codes: CHALLENGE_NOT_FOUND, CHALLENGE_USER_MISMATCH, ATTESTATION_INVALID, VERIFICATION_FAILED, STORAGE_FAILED
- ✅ Origin config via `WEBAUTHN_EXPECTED_ORIGIN` env var (comma-separated, defaults to localhost:5173)
- ✅ Barrel exports updated in `src/lib/passkey/index.ts`
- ✅ 10 unit tests for verify-registration (mocked), 11 integration tests for credential-store (withTestDb)
- ✅ 329 total tests pass, 0 regressions

### File List

- `src/lib/server/db/schema.ts` — Modified: added `passkeyCredentials` table and `PasskeyCredential` type
- `src/lib/passkey/errors.ts` — New: `PasskeyError` class and `PasskeyErrorCode` enum
- `src/lib/passkey/credential-store.ts` — New: CRUD operations for passkey credentials in PostgreSQL
- `src/lib/passkey/verify-registration.ts` — New: `verifyAndStorePasskey()` attestation verification + storage orchestration
- `src/lib/passkey/index.ts` — Modified: barrel exports for all new modules
- `src/lib/passkey/verify-registration.spec.ts` — New: 10 unit tests (mocked)
- `src/lib/passkey/credential-store.spec.ts` — New: 11 integration tests (withTestDb)
- `.env.example` — Modified: added `WEBAUTHN_EXPECTED_ORIGIN`
- `drizzle/0001_freezing_liz_osborn.sql` — New: migration for `passkey_credentials` table
- `drizzle/meta/_journal.json` — Modified: migration journal entry for 0001
- `drizzle/meta/0001_snapshot.json` — New: migration snapshot
- `_bmad-output/planning-artifacts/architecture.md` — Modified: ADR-007 amendment (Keycloak → PostgreSQL)
