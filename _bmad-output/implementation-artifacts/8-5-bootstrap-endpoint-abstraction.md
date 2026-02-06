# Story 8.5: Bootstrap Endpoint Abstraction

**Status:** done
**Epic:** 8 - Bootstrap Verification
**FR Coverage:** FR100–109 (bootstrap flow consistency); prepares Epic 10 provision endpoints and Epic 13 expansion
**Story Key:** 8-5-bootstrap-endpoint-abstraction

---

## Story

As a **developer**,
I want **a consistent pattern for bootstrap endpoints**,
So that **adding new providers (e.g. email/SMS in Epic 13) is straightforward** and Epic 10 provision routes stay thin and uniform.

---

## Acceptance Criteria

### AC1: Common Interface for Verify + Provision
- Define a single interface that represents “verify identity token and provision user.”
- Contract: given a **raw identity token string**, return `ProvisionResult` (userId, isNewUser, email?, provider) or throw.
- Implementations perform: verify token (provider-specific) → then call existing `provisionUser(provider, payload)` from 8.4. No duplication of provisioning logic.

### AC2: Provider-Specific Implementations (Apple, Google)
- **Apple:** Implementation verifies via `verifyAppleToken(token)`, then `provisionUser('apple', payload)`. Propagates `TokenVerificationError` and `BootstrapProvisionError` (and IdentiKeyError) without wrapping in a new abstraction-specific error type unless needed for parity.
- **Google:** Implementation verifies via `verifyGoogleToken(token)`, then `provisionUser('google', payload)`. Same error propagation policy.
- Both implementations are stateless and use existing 8.2, 8.3, 8.4 APIs only.

### AC3: Shared User Provisioning Logic
- Provisioning is **not** reimplemented. All provisioning goes through `provisionUser()` from `src/lib/auth/bootstrap`. The abstraction layer only composes “verify token” + “provision user” in one call.

### AC4: Easy to Add New Providers Later
- New providers (e.g. email, SMS in Epic 13) can be added by: (1) implementing the same interface (verify step may be “validate magic link” or “validate OTP” instead of JWT), (2) returning a result compatible with `ProvisionResult` (or an extended type), (3) registering in a factory/registry.
- Document the extension point (e.g. provider registry or `getBootstrapHandler(id)` that can later accept `'email' | 'sms'`). This story does **not** implement email/SMS — it only establishes the pattern and leaves a clear extension point.

### AC5: Factory or Registry for Provider Lookup
- Callers (e.g. Epic 10 `POST /apple-provision`, `POST /google-provision`) obtain the handler by provider id (e.g. `'apple' | 'google'`), then call the single method (e.g. `verifyAndProvision(token)`). No switch-on-provider in endpoint code.
- Typed provider id: at least `'apple' | 'google'`; document that future values will be added for Epic 13.

### AC6: No HTTP or SvelteKit Coupling
- This story is library-only. No SvelteKit routes, no request/response types. Epic 10 will add `src/routes/api/apple-provision/+server.ts` and `google-provision` that consume this abstraction.

---

## Tasks / Subtasks

- [x] **Task 1: Define bootstrap handler interface** (AC: 1, 4)
  - [x] Create `src/lib/auth/bootstrap/handler.ts` (or under `src/lib/auth/bootstrap/` in a file that holds interface + factory).
  - [x] Define interface, e.g. `BootstrapHandler`: single method `verifyAndProvision(token: string): Promise<ProvisionResult>`.
  - [x] Document that new providers (email/SMS) will implement this interface and register; verify step may differ (e.g. magic link), but result shape stays compatible.

- [x] **Task 2: Apple handler** (AC: 2, 3)
  - [x] Implement Apple handler: verify with `verifyAppleToken(token)`, then `provisionUser('apple', payload)`. Return `ProvisionResult` (already has `provider: 'apple'`).
  - [x] Do not catch and rewrap token or provision errors unless needed for a unified error type; prefer propagating `TokenVerificationError` and `BootstrapProvisionError` so callers can map to 401/400.

- [x] **Task 3: Google handler** (AC: 2, 3)
  - [x] Implement Google handler: verify with `verifyGoogleToken(token)`, then `provisionUser('google', payload)`. Same error propagation as Apple.

- [x] **Task 4: Factory / registry** (AC: 5)
  - [x] Export `getBootstrapHandler(provider: 'apple' | 'google'): BootstrapHandler`. Return the appropriate implementation. Document extension: future `provider` values (e.g. `'email' | 'sms'`) to be added in Epic 13.
  - [x] Keep provider set as a type alias, e.g. `BootstrapProviderId = 'apple' | 'google'`, so adding new ids later is a single change.

- [x] **Task 5: Barrel and auth index** (AC: all)
  - [x] Export from `src/lib/auth/bootstrap/index.ts`: `BootstrapHandler` (type/interface), `getBootstrapHandler`, and any new types (e.g. `BootstrapProviderId`).
  - [x] Update `src/lib/auth/index.ts` to re-export the new public API (getBootstrapHandler, BootstrapHandler, BootstrapProviderId).

- [x] **Task 6: Tests** (AC: all)
  - [x] Create `src/lib/auth/bootstrap/handler.spec.ts` (or equivalent). Mock `verifyAppleToken`, `verifyGoogleToken`, `provisionUser`.
  - [x] **Apple path:** Token valid → verifyAppleToken and provisionUser called in order; result matches ProvisionResult with provider 'apple'. Invalid token → verifyAppleToken throws → no provisionUser call.
  - [x] **Google path:** Same for Google. Verify factory returns correct handler for 'apple' and 'google'.
  - [x] **Error propagation:** Provision failure (provisionUser throws) propagates to caller; no swallowing of errors.

---

## Dev Notes

### Architecture Constraints
- **Bootstrap only:** Same as 8.1–8.4: social (and future email/SMS) are bootstrap mechanisms only (ADR-008). This story only adds an abstraction layer on top of existing verify + provision; it does not add endpoints or new verification logic.
- **Single provisioning path:** All “create/find user in Keycloak” flows go through `provisionUser()`. 8.5 must not duplicate or bypass it.
- **Epic 10 consumption:** Epic 10 will implement `POST /api/apple-provision` and `POST /api/google-provision`; each will call `getBootstrapHandler('apple'|'google').verifyAndProvision(body.token)` then use `userId` (e.g. for WebAuthn challenge). This story makes that call site identical for both providers.

### Previous Story (8.4) Intelligence
- **8.4 delivers:** `provisionUser(provider, payload)`, `ProvisionResult`, `BootstrapProvisionError`, in `src/lib/auth/bootstrap/provision.ts`. Already used with Apple/Google payloads from 8.2/8.3.
- **Pattern:** 8.5 handlers should be thin: verify (8.2/8.3) → provision (8.4). No new Keycloak or JWKS logic.

### Previous Stories (8.2, 8.3) Intelligence
- **8.2:** `verifyAppleToken(token[, options])` → `AppleTokenPayload`. Throws `TokenVerificationError`.
- **8.3:** `verifyGoogleToken(token[, options])` → `GoogleTokenPayload`. Throws `TokenVerificationError`.
- Audience/config: Apple uses `APPLE_SERVICES_ID` or options; Google uses `GOOGLE_CLIENT_ID` or options. Handlers can call verify with no options (env used) or pass through options if we add them later; for 8.5, env-based is enough.

### Extensibility (Epic 13)
- Epic 13 will add email magic link and SMS OTP bootstrap. Those “verify” steps are not JWT; they might return a synthetic payload with `sub` (e.g. email or phone id) and optional email. The same `BootstrapHandler` interface can be used: “verify” = validate link/OTP and return a payload compatible with what `provisionUser` expects (or extend ProvisionResult with `provider: 'email' | 'sms'` and add provisioning branches). This story only documents the extension point; no email/SMS code.

### Project Structure Notes
- **New files:** `src/lib/auth/bootstrap/handler.ts` (interface + Apple/Google impls + factory), `src/lib/auth/bootstrap/handler.spec.ts`.
- **Modified:** `src/lib/auth/bootstrap/index.ts`, `src/lib/auth/index.ts`. No new routes.

### References
- [Source: _bmad-output/planning-artifacts/epics.md#8.5] — AC and technical notes (strategy pattern, prep for Epic 13).
- [Source: _bmad-output/planning-artifacts/architecture.md] — Bootstrap flow (verify → create/find user), POST /apple-provision, POST /google-provision, future POST /email-provision.
- [Source: src/lib/auth/bootstrap/provision.ts] — provisionUser, ProvisionResult.
- [Source: src/lib/auth/apple/verify.ts] — verifyAppleToken, AppleTokenPayload.
- [Source: src/lib/auth/google/verify.ts] — verifyGoogleToken, GoogleTokenPayload.
- [Source: src/lib/auth/errors.ts] — TokenVerificationError (if used by endpoints for 401/400).

### Developer Context (Guardrails)
- **Do not** reimplement verification or provisioning. Compose 8.2, 8.3, 8.4 only.
- **Do not** add SvelteKit routes or HTTP in this story. Epic 10 adds the endpoints.
- **Do not** implement email or SMS bootstrap here; only document how they would plug in.
- **Do** keep the handler interface minimal: one method (e.g. `verifyAndProvision(token)`) so Epic 10 stays a one-liner per provider.
- **Do** propagate token and provision errors so callers can map to appropriate HTTP status codes.
- **Run tests with:** `bun vitest` (per CLAUDE.md).

### Testing Requirements
- Unit tests with mocks for verifyAppleToken, verifyGoogleToken, provisionUser. Assert call order (verify then provision), result shape, and error propagation. Factory returns correct handler for 'apple' and 'google'. No integration with real Keycloak or JWKS.

### Story Completion Status
- **Status:** ready-for-dev
- **Completion note:** Ultimate context engine analysis completed. Abstraction layer for bootstrap: common interface, Apple/Google handlers composing 8.2+8.3+8.4, factory for provider lookup, extension point documented for Epic 13.

---

## Dev Agent Record

### Agent Model Used

{{agent_model_name_version}}

### Debug Log References

### Completion Notes List

- Added `BootstrapHandler` interface (verifyAndProvision(token) → Promise<ProvisionResult>) and `getBootstrapHandler(provider)` in `src/lib/auth/bootstrap/handler.ts`. Apple/Google handlers compose verifyAppleToken/verifyGoogleToken + provisionUser; errors propagated. `BootstrapProviderId = 'apple' | 'google'` with JSDoc for Epic 13 extension. Barrel and auth index re-exports. 10 tests in handler.spec.ts (factory, Apple/Google paths, call order, no provision on verify throw, error propagation). 30 bootstrap tests pass.

### File List

- `src/lib/auth/bootstrap/handler.ts` (new)
- `src/lib/auth/bootstrap/handler.spec.ts` (new)
- `src/lib/auth/bootstrap/index.ts` (modified)
- `src/lib/auth/index.ts` (modified)
