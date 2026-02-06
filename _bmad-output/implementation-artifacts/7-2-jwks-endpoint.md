# Story 7.2: JWKS Endpoint

**Status:** done
**Epic:** 7 - JWT Infrastructure  
**FR Coverage:** FR122  
**Story Key:** 7-2-jwks-endpoint

---

## Story

As a **resource server**,  
I want **to fetch IdentiKey's public keys** via a well-known URL,  
So that **I can validate access tokens** issued by IdentiKey.

---

## Acceptance Criteria

### AC1: GET /.well-known/jwks.json Returns JWKS
- [x] `GET /.well-known/jwks.json` returns HTTP 200 with a JSON body conforming to JWKS (RFC 7517)
- [x] Body is `{ "keys": [ ... ] }` where each key is a JWK with: `kid`, `kty: "OKP"`, `crv: "Ed25519"`, `x`, `use: "sig"`, `alg: "EdDSA"`
- [x] No private key material (`d`) or other sensitive data in the response
- [x] Content-Type: `application/json`

### AC2: Response is Cacheable
- [x] Response includes cache-friendly headers (e.g. `Cache-Control` with `max-age`; 5–60 minutes is acceptable; keys rotate rarely in Phase 1)
- [x] Optional: `Vary` or other headers per SvelteKit/convention; no requirement for ETag/Last-Modified unless we add them later

### AC3: Unavailable When Key Not Loaded
- [x] If the signing key has not been initialized (e.g. startup failed or env missing), respond with 503 Service Unavailable and a minimal body or no body — do not expose key material or stack traces

---

## Tasks / Subtasks

- [x] **Task 1: SvelteKit route for JWKS** (AC: 1, 2)
  - [x] Create `src/routes/.well-known/jwks.json/+server.ts`
  - [x] In GET handler: obtain current key via `getSigningKey()` (returns `SigningKeyPair`), then `getPublicKeyJwk(keyPair)` to get the public JWK
  - [x] Return `{ keys: [ publicKeyJwk ] }` (single key in Phase 1; structure supports multiple keys for future rotation)
  - [x] Set `Cache-Control: public, max-age=<value>` (e.g. 300 or 3600)
  - [x] Set `Content-Type: application/json`

- [x] **Task 2: Handle uninitialized key** (AC: 3)
  - [x] If signing key is not available (e.g. `getSigningKey()` returns null or throws), return 503 with empty or minimal JSON body
  - [x] Do not log private key material; log only that JWKS is unavailable (e.g. debug level)

- [x] **Task 3: Tests** (AC: all)
  - [x] Unit or route test: GET returns 200, body has `keys` array with one JWK containing required fields
  - [x] Test: when key not initialized, GET returns 503
  - [x] Test: response has Cache-Control header

---

## Dev Notes

### Architecture Constraints
- **Route location:** Architecture specifies `src/routes/.well-known/jwks.json/+server.ts` — use exactly this path.
- **Single key:** Phase 1 has one signing key; JWKS returns one key. Structure `{ keys: [ ... ] }` allows adding more keys in key-rotation story (Epic 13).
- **No new libraries:** Use existing `jose` and `src/lib/auth/jwt` (getPublicKeyJwk, getSigningKey). Do not add a separate JWKS library.

### Previous Story (7.1) Intelligence
- **7.1 delivered:** `getPublicKeyJwk()` in `src/lib/auth/jwt/keys.ts` returns the public key JWK with `kty`, `crv`, `x`, `kid`, `use`, `alg`. It requires the key to be loaded (via `loadSigningKey()` / `initializeSigningKey()`).
- **Initialization:** `getSigningKey()` in `src/lib/auth/jwt/init.ts` returns the singleton signing key or throws if not initialized. Use this to obtain the key pair; then call `getPublicKeyJwk(keyPair)` (takes `SigningKeyPair`, returns `SigningKeyJwk`) for the response.
- **Ed25519 JWK:** No `y` field (that's for EC). Only `x` is required for OKP Ed25519.
- **Files to reuse:** `src/lib/auth/jwt/index.ts` exports `getPublicKeyJwk`, `getSigningKey`. Do not duplicate key-loading or JWK export logic in the route.

### Keycloak / OIDC Notes
- Resource servers and OIDC clients will use this URL to validate tokens (e.g. `jose.createRemoteJWKSet(new URL('https://.../.well-known/jwks.json'))`). Standard path is `/.well-known/jwks.json`; do not change.

### Security
- Never return or log private key (`d`) or any secret. JWKS must contain only public key material.
- 503 when key unavailable is correct — do not return 200 with empty keys (clients might treat that as "no keys" and fail validation incorrectly).

### References
- [Source: _bmad-output/planning-artifacts/epics.md#7.2] — AC and technical notes
- [Source: _bmad-output/planning-artifacts/architecture.md#Project Structure] — route path
- [Source: _bmad-output/implementation-artifacts/7-1-key-generation-storage.md] — getPublicKeyJwk, getSigningKey, init
- [Source: src/lib/auth/jwt/keys.ts] — getPublicKeyJwk signature and return type
- [Source: src/lib/auth/jwt/init.ts] — getSigningKey

### Developer Context (Guardrails)
- **Do not** add token signing or verification in this story; those are 7.3 and 7.4. This story is only the HTTP endpoint that serves the public key(s).
- **Do not** create a new JWKS builder in the route; use `getSigningKey()` then `getPublicKeyJwk(keyPair)` from 7.1 and wrap the result in `{ keys: [ jwk ] }`.
- **Do not** add auth (e.g. API key) to this endpoint; JWKS is public by design so resource servers can validate tokens.

### Testing Requirements
- SvelteKit route can be tested via `GET /.well-known/jwks.json` (e.g. `fetch` in test or SvelteKit's load/invoke). Mock or initialize the signing key in test so 200 path is covered; test 503 by not initializing key or mocking getSigningKey to throw/return null.
- Validate response body shape: `keys` is an array, first element has `kid`, `kty`, `crv`, `x`, `use`, `alg`.

### Story Completion Status
- **Status:** done
- **Completion note:** All tasks complete. Route-only change using existing jwt module exports. 7 tests covering all 3 ACs.

---

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6

### Debug Log References

None — clean implementation, no issues encountered.

### Completion Notes List

- Created `src/routes/.well-known/jwks.json/+server.ts` — GET handler that returns JWKS via `getSigningKey()` + `getPublicKeyJwk()` from `$lib/auth/jwt`
- Route returns `{ keys: [jwk] }` with `Cache-Control: public, max-age=3600` and `Content-Type: application/json`
- On key unavailable (throws), returns 503 with `{ error: "Service Unavailable" }` — no private material leaked
- 7 tests in `server.spec.ts` covering: 200 response shape, JWK required fields, no `d` field, Content-Type, Cache-Control, 503 on uninitialized key, 503 body shape
- Full suite: 166 tests across 14 files, all passing, zero regressions

### Change Log

- 2026-02-05: Implemented JWKS endpoint (Story 7.2) — route + tests

### File List

- `src/routes/.well-known/jwks.json/+server.ts` (new)
- `src/routes/.well-known/jwks.json/server.spec.ts` (new)
- `_bmad-output/implementation-artifacts/7-2-jwks-endpoint.md` (modified)
- `_bmad-output/implementation-artifacts/sprint-status.yaml` (modified)
