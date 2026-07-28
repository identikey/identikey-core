# Story 9.5: Assertion Verification

**Status:** ready-for-dev
**Epic:** 9 - Passkey Management
**FR Coverage:** FR114–115 (WebAuthn authentication flow — assertion verification, counter update)
**Story Key:** 9-5-assertion-verification

---

## Story

As the **auth system**,
I want **to verify passkey assertions**,
So that **I can authenticate users via their registered passkeys**.

---

## Acceptance Criteria

### AC1: Verify Authentication Response via @simplewebauthn/server
- Use `verifyAuthenticationResponse()` from `@simplewebauthn/server` (already installed v13.2.3).
- Input: the authentication response from the client, the expected challenge, expected origin, expected rpId, and the stored credential data.
- The `credential` param requires: `{ id, publicKey (Uint8Array), counter, transports }`.
- Return structured result on success; throw typed error on failure.

### AC2: Challenge Lookup and Deletion
- Before verification, look up the challenge in DB using `getChallengeByValue(challenge)` from 9.1 (`src/lib/server/challenges.ts`).
- If challenge not found or expired, reject with `CHALLENGE_NOT_FOUND` error.
- After successful verification, delete the used challenge via `deleteChallengeByValue(challenge)`.

### AC3: Credential Lookup by ID
- Look up the passkey credential by the credential ID from the assertion response (`response.id`).
- Use `getPasskeyByCredentialId(credentialId)` from 9.3 (`src/lib/passkey/credential-store.ts`).
- If credential not found, throw `CREDENTIAL_NOT_FOUND` error.
- Convert stored `publicKey` from base64 string back to `Uint8Array` for verification: `Buffer.from(storedPublicKey, 'base64')`.
- Parse stored `transports` from JSON string to `AuthenticatorTransportFuture[]` (handle `null` gracefully).

### AC4: Challenge-User Validation
- **Known-user flow (challenge.userId is not null):** Validate that `credential.userId === challenge.userId`. If mismatch, throw `CHALLENGE_USER_MISMATCH`.
- **Discoverable credential flow (challenge.userId is null):** No userId validation needed — the user is identified by the credential record itself.

### AC5: Counter Update (Replay Protection)
- On successful verification, extract `authenticationInfo.newCounter` from the verification result.
- Update the stored counter via `updatePasskeyCounter(credentialId, newCounter)` from 9.3 (`src/lib/passkey/credential-store.ts`).
- This also updates `lastUsedAt` timestamp on the credential.

### AC6: Error Handling
- Typed errors for: challenge not found, credential not found, challenge-user mismatch, assertion verification failure, verification not confirmed.
- Reuse existing `PasskeyErrorCode` values where applicable; add `CREDENTIAL_NOT_FOUND` and `ASSERTION_INVALID`.
- Error messages should be diagnostic without leaking internals to clients.

### AC7: Function Signature (Library-Only, No HTTP)
- Expose a function like `verifyAuthenticationAssertion(params)` that takes the assertion response + challenge string and returns `{ userId, credentialId, newCounter }`.
- No HTTP routes in this story — Epic 10 (`POST /passkey-auth/finish`) will call this function.

---

## Tasks / Subtasks

- [ ] **Task 1: Add error codes** (AC: 6)
  - [ ] Add `CREDENTIAL_NOT_FOUND` and `ASSERTION_INVALID` to `PasskeyErrorCode` in `src/lib/passkey/errors.ts`.

- [ ] **Task 2: Assertion verification function** (AC: 1, 2, 3, 4, 5, 6, 7)
  - [ ] Create `src/lib/passkey/verify-authentication.ts`.
  - [ ] Implement `verifyAuthenticationAssertion(params: { assertionResponse, challenge })` returning `Promise<AuthenticationResult>`.
  - [ ] Look up challenge via `getChallengeByValue(challenge)`. If not found, throw `PasskeyError(CHALLENGE_NOT_FOUND)`.
  - [ ] Extract credential ID from `assertionResponse.id`. Look up credential via `getPasskeyByCredentialId(credentialId)`. If not found, throw `PasskeyError(CREDENTIAL_NOT_FOUND)`.
  - [ ] If `challenge.userId` is not null, validate `credential.userId === challenge.userId`. If mismatch, throw `PasskeyError(CHALLENGE_USER_MISMATCH)`.
  - [ ] Convert `credential.publicKey` from base64 to `Uint8Array` via `Buffer.from(publicKey, 'base64')`.
  - [ ] Parse `credential.transports` from JSON string (or `undefined` if null).
  - [ ] Use `getWebAuthnConfig()` from `registration-options.ts` for `rpId`. Use `getExpectedOrigins()` (same pattern as `verify-registration.ts`).
  - [ ] Call `verifyAuthenticationResponse({ response, expectedChallenge, expectedOrigin, expectedRPID, credential: { id, publicKey, counter, transports } })`.
  - [ ] If verification throws, wrap in `PasskeyError(ASSERTION_INVALID)`.
  - [ ] If `verified === false`, throw `PasskeyError(VERIFICATION_FAILED)`.
  - [ ] On success: extract `authenticationInfo.newCounter`. Call `updatePasskeyCounter(credentialId, newCounter)`.
  - [ ] Delete used challenge via `deleteChallengeByValue(challenge)` (swallow errors — credential is already verified).
  - [ ] Return `{ userId: credential.userId, credentialId, newCounter }`.

- [ ] **Task 3: Barrel exports** (AC: all)
  - [ ] Export `verifyAuthenticationAssertion`, `AuthenticationResult`, and `VerifyAuthenticationParams` from `src/lib/passkey/index.ts`.

- [ ] **Task 4: Tests** (AC: all)
  - [ ] Unit tests (mock `verifyAuthenticationResponse`, mock `getChallengeByValue`, mock `deleteChallengeByValue`, mock `getPasskeyByCredentialId`, mock `updatePasskeyCounter`).
  - [ ] Test cases: happy path (known user — challenge lookup → credential lookup → userId match → verification → counter update → challenge delete → result); discoverable credential flow (challenge.userId is null, no mismatch check); challenge not found; credential not found; userId mismatch; assertion verification throws; verified=false; counter update called with newCounter.
  - [ ] Do NOT call real `verifyAuthenticationResponse` in unit tests — mock it. Test orchestration logic.

---

## Dev Notes

### Architecture Constraints
- **ADR-007 deviation (9.3):** Passkeys are stored in PostgreSQL (`passkey_credentials` table), NOT Keycloak. The Keycloak Admin API lacks programmatic WebAuthn credential creation. Use `getPasskeyByCredentialId()` and `updatePasskeyCounter()` from `credential-store.ts` for credential lookups and counter updates.
- **No HTTP routes:** This story is library-only. Epic 10 (`POST /passkey-auth/finish`) will call `verifyAuthenticationAssertion`.
- **Architecture flow:** See "Flow 2: Subsequent Logins" in architecture.md — `POST /passkey-auth/start` (9.4) returns `{ challenge }`, then app triggers native passkey auth, then `POST /passkey-auth/finish` calls this 9.5 function.
- **No token issuance:** This story only verifies the assertion and returns `{ userId, credentialId, newCounter }`. Token issuance is Epic 10/12's responsibility.

### Previous Story (9.4) Intelligence
- **9.4 delivers:** `generateAuthenticationChallenge(params?)` in `src/lib/passkey/authentication-options.ts`. Returns `PublicKeyCredentialRequestOptionsJSON` with challenge stored in DB.
- **Challenge storage:** `createChallenge({ userId: string | null, challenge, type: 'authentication' })`. For known user, `userId` is set. For discoverable credential flow, `userId` is `null`.
- **Error codes added:** `NO_PASSKEYS_FOUND` in `PasskeyErrorCode`.
- **Pattern:** Tests mock `$lib/server/challenges`, `./credential-store`, and `@simplewebauthn/server` via `vi.mock()`. Follow same pattern.

### Previous Story (9.3) Intelligence
- **9.3 delivers:** `verifyAndStorePasskey()` in `src/lib/passkey/verify-registration.ts`. This is the structural mirror — 9.5 is the authentication counterpart. Follow the same file/function naming pattern.
- **Credential store:** `getPasskeyByCredentialId(credentialId)` returns `PasskeyCredential | null`. `updatePasskeyCounter(credentialId, counter)` updates counter and `lastUsedAt`.
- **Credential schema:** `passkey_credentials` table: `id` (UUID), `userId` (text), `credentialId` (text, unique), `publicKey` (text, base64), `counter` (int), `transports` (text, JSON string or null), `deviceType` (text), `backedUp` (boolean), `createdAt`, `lastUsedAt`.
- **Error codes available:** `CHALLENGE_NOT_FOUND`, `CHALLENGE_USER_MISMATCH`, `ATTESTATION_INVALID`, `VERIFICATION_FAILED`, `STORAGE_FAILED`, `NO_PASSKEYS_FOUND`.
- **Origin config:** `WEBAUTHN_EXPECTED_ORIGIN` env var (comma-separated, defaults to `http://localhost:5173`). Reuse the `getExpectedOrigins()` helper from `verify-registration.ts` — consider extracting to a shared location or just duplicating the small helper.
- **Code review learning (9.3):** Challenge deletion is wrapped in try/catch — credential is already verified, so deletion failure is swallowed. Apply same pattern here.
- **Code review learning (9.3):** base64 vs base64url — the stored publicKey is standard base64 (from `Buffer.from(publicKey).toString('base64')` in 9.3). When converting back, use `Buffer.from(stored, 'base64')`.

### Previous Story (9.1) Intelligence
- **9.1 delivers:** `getChallengeByValue`, `deleteChallengeByValue` in `src/lib/server/challenges.ts`. Challenge types: `'registration'` and `'authentication'`. `getChallengeByValue` auto-deletes expired challenges and returns `null` if expired or not found.

### @simplewebauthn/server v13.2.3 — verifyAuthenticationResponse API
```typescript
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';

const verification = await verifyAuthenticationResponse({
  response: body,                    // AuthenticationResponseJSON from client
  expectedChallenge: challenge,      // base64url string from DB
  expectedOrigin: origin,            // string or string[]
  expectedRPID: rpID,                // string or string[]
  credential: {
    id: passkey.id,                  // string (credential ID)
    publicKey: passkey.publicKey,    // Uint8Array (NOT base64 string)
    counter: passkey.counter,        // number
    transports: passkey.transports,  // AuthenticatorTransportFuture[] | undefined
  },
});

const { verified, authenticationInfo } = verification;
// verified          — boolean
// authenticationInfo.newCounter  — number (updated sign count)

// After success: update counter in DB
await updatePasskeyCounter(credentialId, authenticationInfo.newCounter);
```

### Public Key Conversion Note
- `passkey_credentials.publicKey` is stored as **base64 string** (standard base64, from `Buffer.from(uint8array).toString('base64')` in 9.3).
- `verifyAuthenticationResponse` expects `credential.publicKey` as `Uint8Array`.
- Convert back: `Buffer.from(storedPublicKey, 'base64')` — `Buffer` is a `Uint8Array` subclass in Node.js, so this works directly.

### Transport Parsing Note
- `passkey_credentials.transports` is stored as a JSON string (e.g., `'["internal","hybrid"]'`) or `null`.
- Must `JSON.parse()` it when building the `credential` object for verification.
- Handle `null` transports gracefully — pass `undefined`.

### Discoverable Credential Flow
- In discoverable credential flow, the challenge was stored with `userId: null` (from 9.4).
- The assertion response contains the credential ID (`response.id`), which we use to look up the credential and find the associated userId.
- No userId validation needed against the challenge — the credential itself proves identity.
- The returned `userId` from this function is how the caller (Epic 10) knows who authenticated.

### Project Structure Notes
- **New:** `src/lib/passkey/verify-authentication.ts` (assertion verification + counter update orchestration)
- **Modified:** `src/lib/passkey/errors.ts` (add `CREDENTIAL_NOT_FOUND`, `ASSERTION_INVALID` error codes)
- **Modified:** `src/lib/passkey/index.ts` (barrel exports)
- **New:** `src/lib/passkey/verify-authentication.spec.ts` (unit tests)

### References
- [Source: _bmad-output/planning-artifacts/epics.md#9.5] — AC and technical notes.
- [Source: _bmad-output/planning-artifacts/architecture.md#Flow-2] — Subsequent login flow: POST /passkey-auth/finish.
- [Source: src/lib/server/challenges.ts] — getChallengeByValue, deleteChallengeByValue.
- [Source: src/lib/passkey/credential-store.ts] — getPasskeyByCredentialId, updatePasskeyCounter.
- [Source: src/lib/passkey/verify-registration.ts] — 9.3 implementation (structural mirror for registration side).
- [Source: src/lib/passkey/authentication-options.ts] — 9.4 implementation (challenge generation).
- [Source: src/lib/passkey/registration-options.ts] — getWebAuthnConfig (reuse for rpID).
- [Source: @simplewebauthn/server docs] — verifyAuthenticationResponse API.

### Developer Context (Guardrails)
- **Do not** add HTTP routes. Epic 10 (`POST /passkey-auth/finish`) wires the endpoint.
- **Do not** issue tokens. Epic 10/12 handles token issuance after receiving userId from this function.
- **Do not** look up credentials in Keycloak — use PostgreSQL via `credential-store.ts` (ADR-007 deviation).
- **Do** delete the used challenge after successful verification (replay protection). Swallow deletion errors (credential is already verified).
- **Do** validate `challenge.userId === credential.userId` for known-user flow. Skip for discoverable (challenge.userId is null).
- **Do** convert publicKey from base64 string to Uint8Array before passing to verifyAuthenticationResponse.
- **Do** parse transports from JSON string before passing to verifyAuthenticationResponse.
- **Do** update counter via `updatePasskeyCounter` after successful verification (replay protection + lastUsedAt update).
- **Do** reuse `getWebAuthnConfig()` from `registration-options.ts` for rpId.
- **Do** reuse the origin config pattern from `verify-registration.ts` (`WEBAUTHN_EXPECTED_ORIGIN` env var).
- **Run tests with:** `bun vitest` (per CLAUDE.md).

### Testing Requirements
- Unit tests: mock `verifyAuthenticationResponse`, mock `getChallengeByValue`, mock `deleteChallengeByValue`, mock `getPasskeyByCredentialId`, mock `updatePasskeyCounter`. Test: happy path with known user (challenge → credential → userId match → verify → counter update → challenge delete → result returned), discoverable credential flow (challenge.userId is null, credential lookup by response.id), challenge not found, credential not found, userId mismatch, assertion throws error, verified=false, counter update called with newCounter from authenticationInfo, challenge deletion failure swallowed.
- Do NOT call real `verifyAuthenticationResponse` — mock it. Test orchestration.

### Story Completion Status
- **Status:** ready-for-dev
- **Completion note:** Assertion verification via @simplewebauthn/server; challenge lookup from 9.1; credential lookup and counter update from 9.3; supports known-user and discoverable-credential flows; ready for Epic 10 endpoint wiring (POST /passkey-auth/finish).

---

## Dev Agent Record

### Agent Model Used

{{agent_model_name_version}}

### Debug Log References

### Completion Notes List

### File List
