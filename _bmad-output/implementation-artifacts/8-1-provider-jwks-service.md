# Story 8.1: Provider JWKS Service

**Status:** done
**Epic:** 8 - Bootstrap Verification
**FR Coverage:** FR100 (Apple), FR105 (Google) — JWKS fetch and cache  
**Story Key:** 8-1-provider-jwks-service

---

## Story

As the **auth system**,  
I want **to fetch and cache provider public keys** (Apple, Google),  
So that **I can verify identity tokens from Apple and Google** in later stories.

---

## Acceptance Criteria

### AC1: Fetch Apple JWKS
- [x] Apple JWKS is fetched from `https://appleid.apple.com/auth/keys`
- [x] Expose a way to obtain a key-resolution function (e.g. for use with `jose.jwtVerify`) that uses Apple's keys. Recommended: `jose.createRemoteJWKSet(new URL('https://appleid.apple.com/auth/keys'))` which returns a `GetKeyFunction` with built-in caching.
- [x] No hardcoded keys; always resolve via the provider URL.

### AC2: Fetch Google JWKS
- [x] Google JWKS is fetched from `https://www.googleapis.com/oauth2/v3/certs`
- [x] Same pattern: expose key-resolution for Google (e.g. `createRemoteJWKSet` for Google URL) so 8.3 can verify Google tokens.

### AC3: Caching and Refresh
- [x] Keys are cached with a reasonable TTL (1 hour recommended per epics). `jose.createRemoteJWKSet` handles caching internally; document or configure if the library allows (e.g. cache size, TTL).
- [x] On cache miss or expiry, keys are refreshed (automatic with remote JWK set). No requirement to implement custom cache if jose satisfies "cache with TTL" and "refresh on miss/expiry".

### AC4: Handle Fetch Failures Gracefully
- [x] If the provider URL is unreachable or returns an error, the key-resolution function (or wrapper) should throw a clear, typed error (e.g. `ProviderJwksError` or `JwksFetchError`) so callers (8.2, 8.3) can handle network/provider failures without exposing raw fetch errors.
- [x] Optional: retry with backoff for transient failures; document behaviour.

### AC5: Abstract Provider Logic
- [x] Structure the code so adding another provider (e.g. future OIDC provider) is straightforward: e.g. a small config or registry of (providerId, jwksUri) and a function like `getProviderJwkSet(providerId)` or separate `getAppleJwkSet()` / `getGoogleJwkSet()` that share common logic.
- [x] Document the pattern for adding a new provider.

---

## Tasks / Subtasks

- [x] **Task 1: Provider JWKS module** (AC: 1, 2, 3)
  - [x] Create module under `src/lib/auth/` for provider JWKS. Architecture suggests `src/lib/auth/apple/` (jwks-cache) and similar; for "abstract provider logic" consider `src/lib/auth/bootstrap/` or `src/lib/auth/provider-jwks/` with Apple and Google, or separate `apple/` and `google/` subdirs that both use a shared helper.
  - [x] Use `jose.createRemoteJWKSet(url)` for Apple and Google URLs. Export a getter or factory that returns the key function (e.g. `getAppleJwkSet(): GetKeyFunction`, `getGoogleJwkSet(): GetKeyFunction`) so 8.2 and 8.3 can pass it to `jose.jwtVerify(token, getKeyFunction, options)`.
  - [x] Ensure jose version supports createRemoteJWKSet and document caching behaviour (built-in or custom).

- [x] **Task 2: Error handling** (AC: 4)
  - [x] Define a typed error (e.g. `ProviderJwksError` in `src/lib/auth/errors.ts`) for fetch/parse failures. Wrap or map jose/fetch errors when key resolution fails so callers get a stable error type.
  - [x] Document when this error is thrown (e.g. network error, non-2xx response, invalid JWKS JSON).

- [x] **Task 3: Abstraction and docs** (AC: 5)
  - [x] Implement provider abstraction: either a map of providerId → JWKS URL and `getProviderJwkSet(providerId)`, or explicit `getAppleJwkSet` / `getGoogleJwkSet` with shared code and a short comment on adding providers.
  - [x] Add brief README or inline comment on how to add another provider (URL + export).

- [x] **Task 4: Exports and tests** (AC: all)
  - [x] Export public API from `src/lib/auth/index.ts` (e.g. `getAppleJwkSet`, `getGoogleJwkSet`, error type).
  - [x] Unit tests: mock fetch or use jose behaviour; test that getter returns a function, and that calling it with a valid token (or invalid) behaves as expected. Test error path when fetch fails (e.g. mock fetch to 500 or network error).

---

## Dev Notes

### Architecture Constraints
- **URLs (non-negotiable):** Apple `https://appleid.apple.com/auth/keys`, Google `https://www.googleapis.com/oauth2/v3/certs` (architecture + epics).
- **Bootstrap only:** Apple/Google are not Keycloak IDPs; we verify tokens server-side via JWKS (ADR-008).
- **File location:** Architecture mentions `src/lib/auth/apple/verify.ts` and `jwks-cache.ts`; 8.1 is the JWKS/cache layer. 8.2 will add verify. So 8.1 can live under `auth/apple/` and `auth/google/` or a single `auth/provider-jwks/` (or `auth/bootstrap/`) — choose one and stay consistent.

### Previous Stories
- **Epic 7:** We have `jose` in use (JWT signing/verification). Same `jose` for `createRemoteJWKSet`. No new libs required.
- **7.4:** We use local key for our own tokens; here we use remote JWKS for third-party (Apple/Google) tokens.

### jose createRemoteJWKSet
- Returns a function suitable for use as the key resolver in `jwtVerify(token, keyResolver, options)`. Handles HTTP fetch and key selection by `kid`/alg. Check jose docs for cache behaviour (some versions cache in-memory by default).
- If custom TTL is required and jose doesn't support it, consider a thin wrapper that recreates the remote JWK set after TTL (or document "jose default caching" as sufficient for 1h).

### Security
- Only fetch over HTTPS. Validate that URLs are HTTPS when configuring.
- Do not log or expose raw JWKS responses in error messages; log only "Provider JWKS fetch failed" or similar.

### References
- [Source: _bmad-output/planning-artifacts/epics.md#8.1] — AC and technical notes
- [Source: _bmad-output/planning-artifacts/architecture.md#Apple Identity Services] — Apple JWKS URL
- [Source: _bmad-output/planning-artifacts/architecture.md#Google Identity Services] — Google JWKS URL
- [Source: _bmad-output/planning-artifacts/architecture.md#Project Structure] — auth/apple, auth layout
- [Source: src/lib/auth/errors.ts] — add ProviderJwksError

### Developer Context (Guardrails)
- **Do not** implement Apple or Google token verification (claim validation, iss/aud) in this story; that is 8.2 and 8.3. This story is only "fetch and expose JWKS for providers."
- **Do not** add Keycloak or UserService calls; no user provisioning. That is 8.4.
- **Do not** add HTTP endpoints or routes; this is a library used by future API routes.

### Testing Requirements
- Unit tests: either (1) test that getAppleJwkSet/getGoogleJwkSet return a function and that function can be called (e.g. with a mock token or expect it to throw on invalid token), or (2) mock global fetch and assert correct URL is requested and response is used. Test error path: fetch fails → typed error thrown.

### Story Completion Status
- **Status:** done
- **Completion note:** All tasks and ACs complete. Foundation for 8.2 (Apple verify) and 8.3 (Google verify).

---

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6

### Debug Log References

None.

### Completion Notes List

- Created `src/lib/auth/provider-jwks/provider-jwks.ts` with `createRemoteJWKSet` for Apple and Google JWKS URIs.
- Used `PROVIDER_JWKS_URIS` registry pattern with `getProviderJwkSet(providerId)` generic function and `getAppleJwkSet()` / `getGoogleJwkSet()` convenience getters.
- Key functions are cached per provider; `createRemoteJWKSet` handles HTTP caching and key selection by kid/alg internally (jose v6).
- Added `ProviderJwksError` to `src/lib/auth/errors.ts` with `cause` field for original error propagation.
- Key function wrapper catches fetch/parse errors from jose and re-throws as `ProviderJwksError` with provider name in message.
- Inline documentation describes how to add a new provider (4-step process in code comments).
- Retry with backoff not implemented (AC4 optional); jose handles standard HTTP retry semantics. Documented as relying on jose defaults.
- 14 unit tests covering: URI constants, Apple/Google key function creation, caching, error wrapping (typed error, cause preservation, provider name in message), generic provider lookup, unknown provider rejection.
- All 226 tests pass with zero regressions.

### File List

- `src/lib/auth/provider-jwks/provider-jwks.ts` (new) — Provider JWKS module
- `src/lib/auth/provider-jwks/provider-jwks.spec.ts` (new) — 14 unit tests
- `src/lib/auth/provider-jwks/index.ts` (new) — Barrel exports
- `src/lib/auth/errors.ts` (modified) — Added ProviderJwksError class
- `src/lib/auth/index.ts` (modified) — Re-exported provider-jwks public API
