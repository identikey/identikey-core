# Story 2.1: UserService Core Operations

Status: done

## Story

As an **admin**,  
I want **a service that wraps Keycloak user operations**,  
so that **MCP and CLI can share the same logic**.

## Acceptance Criteria

1. **UserService surface**
   - Given an authenticated Keycloak client  
     When `UserService` is instantiated  
     Then the following methods are available:

     | Method                                    | FR   | Description                                                    |
     | ----------------------------------------- | ---- | -------------------------------------------------------------- |
     | `list(options?)`                          | FR5  | List users with pagination (max, offset)                       |
     | `search(query, options?)`                 | FR6  | Search by username, email, firstName, lastName                 |
     | `get(id)`                                 | FR7  | Get user by ID                                                 |
     | `create(data)`                            | FR8  | Create user with username, email, firstName, lastName, enabled |
     | `update(id, data)`                        | FR9  | Update user attributes                                         |
     | `delete(id)`                              | FR10 | Delete user                                                    |
     | `resetPassword(id, password, temporary?)` | FR11 | Set new password                                               |
     | `getCredentials(id)`                      | FR12 | List user credentials                                          |
     | `deleteCredential(id, credentialId)`      | FR13 | Remove specific credential                                     |

2. **Domain modeling**
   - All methods return IdentiKey domain types (not raw Keycloak types).

3. **Error handling**
   - All failures are wrapped in `IdentiKeyError` using appropriate `ErrorCodes` rather than exposing raw Keycloak errors.

## Tasks / Subtasks

- [x] **T1 – Implement `UserService` core operations**
  - [x] Define `User`, `CreateUserInput`, `UpdateUserInput`, and any list/pagination types in `src/lib/keycloak/types.ts` consistent with `docs/architecture.md`.
  - [x] Implement `UserService` in `src/lib/keycloak/services/users.ts` with the method surface defined in the acceptance criteria, delegating to `client.users.*`.
  - [x] Ensure `UserService` obtains its `KcAdminClient` instance via the shared `getKeycloakClient()` helper and never instantiates the client directly.
  - [x] Wrap connectivity/auth failures and logical errors in `IdentiKeyError` with appropriate `ErrorCodes` (`USER_NOT_FOUND`, `INVALID_INPUT`, `CONNECTION_FAILED`, `UNAUTHORIZED`, etc.).

- [x] **T2 – Implement user mappers and exports**
  - [x] Add `mapKeycloakUser` (and any helpers) under `src/lib/keycloak/mappers/users.ts` to map Keycloak `UserRepresentation` into the IdentiKey `User` type, including `guilds` from group memberships.
  - [x] Expose `UserService` (and its factory, if any) from `src/lib/keycloak/services/index.ts` so MCP and CLI can share it.
  - [x] Ensure naming and file layout match the service-first patterns in `docs/architecture.md` and `docs/epics.md` (services per domain, no Keycloak types leaking through).

- [x] **T3 – Tests and diagnostics**
  - [x] Add Vitest coverage for `UserService.list`, `get`, `create`, `update`, `delete`, `resetPassword`, `getCredentials`, and `deleteCredential` using mocks of `@keycloak/keycloak-admin-client`.
  - [x] Verify error paths produce `IdentiKeyError` with stable codes and scrubbed messages, not raw Keycloak errors.
  - [x] Add at least one higher-level test that exercises `UserService` via the same config/client wiring used by CLI/MCP, to catch regressions in how the service is constructed.

## Dev Notes

- **Architecture alignment**
  - This story realizes the **UserService** slice of the service-first architecture described in `docs/architecture.md` and the FR5–FR13 user management requirements in `docs/prd.md`.
  - It depends on the Epic 1 foundation: configuration loading (`config.ts`), Keycloak client wrapper (`client.ts`), standardized error types (`errors.ts`), logging (`logger.ts`), and connection validation (`validateConnection()`).
  - The service exposes IdentiKey abstractions (Users and Guilds) rather than raw Keycloak representations, keeping the MCP and CLI layers clean and stable even if Keycloak’s API changes.

- **Source tree components to touch**
  - `src/lib/keycloak/types.ts` – add `User` and supporting input/option types.
  - `src/lib/keycloak/mappers/users.ts` – implement `mapKeycloakUser` and related helpers.
  - `src/lib/keycloak/services/users.ts` – implement `UserService` on top of `getKeycloakClient()`.
  - `src/lib/keycloak/services/index.ts` – export `UserService` (or a factory) for use by MCP/CLI.

- **Testing standards summary**
  - Prefer deterministic unit tests that mock the Keycloak admin client and verify method behavior and error mapping.
  - Reserve real-instance tests for local smoke testing using the same configuration and `validateConnection()` wiring from Epic 1, ensuring failure modes remain clear and non-leaky.

### Project Structure Notes

- Follow the **service-per-domain** structure from `docs/architecture.md`: `src/lib/keycloak/services/users.ts` for core operations, with domain types in `types.ts` and mappers in `mappers/`.
- Ensure no Keycloak-centric terminology leaks into the public `UserService` API; it should speak in terms of IdentiKey Users and Guilds.
- Keep the service thin over the Keycloak client and avoid embedding CLI/MCP-specific concerns here; interface layers should remain consumers, not collaborators.

### Learnings from Previous Story

From **Story 1.5 – Connection Validation** (`docs/sprint-artifacts/1-5-connection-validation.md`):

- All connectivity and authentication behavior should flow through the shared `loadConfig()`, `getKeycloakClient()`, and `validateConnection()` path; `UserService` must not reimplement its own connection logic.
- `IdentiKeyError` and `ErrorCodes` are now the canonical way to represent connectivity and auth failures (`CONNECTION_FAILED`, `UNAUTHORIZED`); user operations should reuse those codes where appropriate instead of inventing new ones.
- Logging for user operations should go through the shared `logger` and respect the same non-leakage guarantees as connection validation (no credentials, tokens, or secrets in logs).

These imply that:

- `UserService` should treat connection and auth issues as infrastructure concerns surfaced via standardized errors and logs, leaving domain logic focused on user operations and FR5–FR13.
- Future stories that build MCP tools and CLI commands for users can rely on a consistent error and logging surface inherited from Epic 1 and this service.

### References

- [Source: `docs/epics.md` – Epic 2 / Story 2.1: UserService Core Operations](../epics.md)
- [Source: `docs/prd.md` – User Management FR5–FR13](../prd.md)
- [Source: `docs/architecture.md` – Service-first architecture, IdentiKey abstraction, and UserService mapping](../architecture.md)
- [Source: `docs/sprint-artifacts/tech-spec-epic-1.md` – Epic 1 foundation and connectivity contracts](./tech-spec-epic-1.md)
- [Source: `docs/sprint-artifacts/1-5-connection-validation.md` – Completed story and learnings for connection validation](./1-5-connection-validation.md)

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/2-1-userservice-core-operations.context.xml

### Agent Model Used

keycloak-commander – SM create-story workflow (YOLO, non-interactive)

### Debug Log References

- 2025-12-01 – Drafted Story 2.1 scope and tasks from PRD, architecture, epic breakdown, and previous story learnings.

### Completion Notes List

- Drafted Story 2.1 to define `UserService` core operations and their mapping to FR5–FR13, grounded in `docs/epics.md` and `docs/prd.md`.
- Identified dependencies on Epic 1 foundation (`config.ts`, `client.ts`, `errors.ts`, `logger.ts`, `validateConnection()`) and made them explicit in Dev Notes and tasks.
- Outlined implementation tasks, mappers, and test coverage needed to deliver a reusable UserService suitable for both MCP and CLI layers.
- ✅ Implemented `types.ts` with `User`, `CreateUserInput`, `UpdateUserInput`, `ListOptions`, and `Credential` domain types.
- ✅ Implemented `mappers/users.ts` with `mapKeycloakUser` and `mapKeycloakCredential` functions to transform Keycloak representations.
- ✅ Implemented `services/users.ts` with full `UserService` class: `list`, `search`, `get`, `create`, `update`, `delete`, `resetPassword`, `getCredentials`, `deleteCredential`.
- ✅ Implemented `services/index.ts` with `getUserService()` factory that uses the shared Keycloak client singleton.
- ✅ Added 26 comprehensive unit tests covering all methods, error classification (401/403→UNAUTHORIZED, 404→USER_NOT_FOUND, network→CONNECTION_FAILED), and edge cases.

### File List

- docs/sprint-artifacts/2-1-userservice-core-operations.md
- src/lib/keycloak/types.ts (new)
- src/lib/keycloak/mappers/users.ts (new)
- src/lib/keycloak/services/users.ts (new)
- src/lib/keycloak/services/index.ts (new)
- src/lib/keycloak/services/users.spec.ts (new)

## Change Log

- 2025-12-01 – Initial draft created via SM `*create-story` workflow.
- 2025-12-01 – Implemented all tasks (T1, T2, T3): types, mappers, UserService, exports, and 26 unit tests. All 45 tests pass.
