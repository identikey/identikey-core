# Story 1.3: Keycloak Client Wrapper

Status: done

## Story

As a **developer**,  
I want **a wrapper around @keycloak/keycloak-admin-client**,  
so that **services can get an authenticated client instance**.

## Acceptance Criteria

1. **Authenticated client from env configuration**
   - Given valid Keycloak credentials are available in environment variables (loaded via `loadConfig()` from Story 1.2)  
     When I call `getKeycloakClient()`  
     Then I receive an authenticated `KcAdminClient` instance configured for the correct `KEYCLOAK_URL` and `KEYCLOAK_REALM`.

2. **Password grant support (FR2)**
   - And the client is authenticated using password grant with `KEYCLOAK_USERNAME`, `KEYCLOAK_PASSWORD`, and `KEYCLOAK_CLIENT_ID` (`admin-cli` by default).

3. **Service account extensibility (FR1)**
   - And the wrapper is structured so that service-account based authentication can be added later without breaking callers (e.g. by allowing an alternate auth strategy or config extension).

4. **Singleton client instance**
   - And the client is cached as a singleton per process so that repeated calls to `getKeycloakClient()` reuse the same underlying `KcAdminClient` instance.

5. **Token refresh behavior**
   - And re-authentication or token refresh happens automatically (leveraging the underlying client’s behavior) so that services can make multiple calls without manually reauthenticating.

## Tasks / Subtasks

- [x] **T1 – Implement client wrapper**
  - [x] Create `src/lib/keycloak/client.ts` that: - Imports `loadConfig()` from `src/lib/keycloak/config.ts`. - Constructs a `KcAdminClient` with `baseUrl` and `realmName` derived from config. - Performs password-grant authentication using config credentials.
  - [x] Export a `getKeycloakClient()` function that returns a cached instance (singleton) and performs lazy authentication on first use.

- [x] **T2 – Handle auth errors cleanly**
  - [x] Ensure authentication errors are thrown in a way that later stories (error/logging) can wrap into `IdentiKeyError` without double-logging or losing stack traces.
  - [x] Avoid logging secrets or full URLs with embedded credentials.

- [x] **T3 – Unit tests / integration shim**
  - [x] Add tests (or a test harness) that: - Verify `getKeycloakClient()` calls `loadConfig()` and constructs the admin client with correct base URL and realm. - Verify singleton behavior (same instance returned on multiple calls). - Are structured so they can be wired to a real Keycloak instance later, but do not require one in this repo yet (e.g. by mocking `@keycloak/keycloak-admin-client`).

- [x] **T4 – Prepare for connection validation**
  - [x] Sketch (but do not fully implement) a `validateConnection()` helper or hook location aligned with `tech-spec-epic-1.md` so that Story 1.5 can plug in the actual validation logic without refactoring the wrapper.

## Dev Notes

- **Architecture alignment**
  - This story realizes the `client.ts` module described in `docs/architecture.md` under **Project Structure** and the Keycloak Admin Client section, using the `loadConfig()` API defined by Story 1.2.
  - It is the primary consumer of the configuration layer and will be the entry point for all domain services (users, apps, guilds, etc.) in later stories.

- **Source tree components to touch**
  - `src/lib/keycloak/client.ts` – new wrapper and singleton entrypoint.
  - Test files under `src/lib/keycloak/` (e.g. `client.spec.ts`) to exercise the wrapper behavior (likely with mocks).

- **Testing standards summary**
  - Focus on **unit-level** behavior (config usage + singleton semantics), not real Keycloak I/O.
  - Actual end-to-end auth against a Keycloak instance can be added later once environment and test infrastructure are available.

### Project Structure Notes

- `client.ts` must depend on `config.ts` (Story 1.2) rather than re-reading env vars directly.
- Keep responsibilities clean: authentication and client lifecycle live here; higher-level services should not be instantiating `KcAdminClient` on their own.

### References

- [Source: `docs/epics.md` – Epic 1 / Story 1.3](../epics.md#story-13-keycloak-client-wrapper)
- [Source: `docs/architecture.md` – Keycloak Admin Client and `client.ts` sections](../architecture.md)
- [Source: `docs/sprint-artifacts/tech-spec-epic-1.md` – Keycloak Client API & connection strategy](./tech-spec-epic-1.md)

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/1-3-keycloak-client-wrapper.context.xml

### Agent Model Used

Cursor AI – keycloak-commander / Story 1.3

### Debug Log References

### Completion Notes List

- Implemented `getKeycloakClient()` as a singleton wrapper around `@keycloak/keycloak-admin-client` using configuration from `loadConfig()`, with lazy password-grant authentication and no logging of secrets.
- Added a minimal `validateConnection()` hook that reuses the singleton client and will be extended in Story 1.5 for richer connection diagnostics.

### File List

- src/lib/keycloak/client.ts
- src/lib/keycloak/client.spec.ts
