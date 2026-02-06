# Story 1.4: Error Types & Logging Setup

Status: done

## Story

As a **developer**,  
I want **standardized error types and structured logging**,  
so that **errors are consistent and debuggable across all services**.

## Acceptance Criteria

1. **IdentiKey error type and codes**
   - Given a Keycloak or network error occurs in a connectivity path (e.g. during configuration loading or Keycloak client initialization)  
     When it is handled in the core layer  
     Then it is wrapped in an `IdentiKeyError` instance with:
     - a specific, non-generic `code` drawn from a constrained `ErrorCodes` set, and
     - an optional `cause` preserving the original error for debugging.

2. **Structured logging with Pino**
   - Given the application is running in any environment  
     When the logger is used from core modules (`config.ts`, `client.ts`, future services)  
     Then logs are emitted via a shared `logger` built on `pino`, with:
     - JSON output by default in non-development environments, and
     - pretty-printed, human-readable output in development.

3. **Environment-driven log level**
   - Given `LOG_LEVEL` is set in the environment  
     When the logger is created  
     Then the effective log level honors `LOG_LEVEL`, defaulting to `info` when unset.

4. **No secret leakage**
   - Given errors are wrapped and logs are written  
     When sensitive values such as passwords, tokens, client secrets, or full credential objects are involved  
     Then those values are never logged (neither in messages nor in structured fields), and error messages remain high-level and non-leaky.

5. **Ready for Epic 1 consumers**
   - Given later epics introduce domain services (users, apps, guilds, roles, flows, sessions, events)  
     When those services depend on the error and logging primitives from this story  
     Then they can:
     - throw `IdentiKeyError` with appropriate codes without redesigning the base types, and
     - use the shared `logger` directly without additional per-service configuration.

## Tasks / Subtasks

- [x] **T1 – Implement IdentiKey error type**
  - [x] Create `src/lib/keycloak/errors.ts` exporting:
    - [x] `class IdentiKeyError extends Error` with `message`, `code`, and optional `cause`.
    - [x] A frozen `ErrorCodes` object enumerating at least:
          `USER_NOT_FOUND`, `APP_NOT_FOUND`, `GUILD_NOT_FOUND`, `AUTH_FLOW_NOT_FOUND`,
          `UNAUTHORIZED`, `CONNECTION_FAILED`, `INVALID_INPUT`.
  - [x] Ensure stack traces are preserved and `name` is set to `"IdentiKeyError"`.

- [x] **T2 – Implement shared logger**
  - [x] Create `src/lib/keycloak/logger.ts` exporting a singleton `logger` from `pino`.
  - [x] Configure `level` from `process.env.LOG_LEVEL ?? 'info'`.
  - [x] In `NODE_ENV === 'development'`, enable `pino-pretty` transport for readable console output; otherwise emit plain JSON.
  - [x] Add (or prepare for) redaction of obviously sensitive fields so they never appear in structured logs.

- [x] **T3 – Wire into existing foundation**
  - [x] Use `IdentiKeyError` as the canonical error type for connectivity/auth failures in `client.ts` (e.g. wrapping Keycloak admin client auth errors) without changing external APIs.
  - [x] Use `logger` for connection validation and other core messages instead of `console.log` or ad-hoc logging.

- [x] **T4 – Tests and safety checks**
  - [x] Add unit tests verifying:
    - [x] `IdentiKeyError` preserves message, code, and cause.
    - [x] `ErrorCodes` is stable and treated as a closed set for current use cases.
    - [x] `logger` honors `LOG_LEVEL` and does not throw during initialization.
  - [x] Add at least one test or harness that exercises wrapping of a synthetic Keycloak/network error into `IdentiKeyError` with `CONNECTION_FAILED` or `UNAUTHORIZED`.

## Dev Notes

- **Architecture alignment**
  - This story realizes the `errors.ts` and `logger.ts` modules described in `docs/architecture.md` under **Error Handling** and **Logging Strategy**, providing the shared primitives that all future services (users, apps, guilds, roles, auth flows, sessions, events) will consume.
  - It completes the "foundation" layer from `docs/architecture.md` alongside the existing `config.ts` and `client.ts` implementations, as specified in `docs/sprint-artifacts/tech-spec-epic-1.md` for Story 1.4.

- **Source tree components to touch**
  - `src/lib/keycloak/errors.ts` – new IdentiKey error type and codes.
  - `src/lib/keycloak/logger.ts` – new Pino logger instance and basic configuration.
  - `src/lib/keycloak/client.ts` – updated to use `IdentiKeyError` and `logger` for connectivity/auth failures (without changing its public surface).
  - `src/lib/keycloak/client.spec.ts` – extended tests to assert error wrapping behavior and avoid regressions when auth fails.

- **Testing standards summary**
  - Focus primarily on **unit-level** tests for error-wrapping behavior and logger initialization; real Keycloak I/O remains out-of-scope for this story.
  - Integration tests against a dev Keycloak instance can be added later (e.g. in Story 1.5, when connection validation is fully wired), but this story should still be testable in isolation via mocks and synthetic failures.

### Project Structure Notes

- Keep `errors.ts` and `logger.ts` generic and reusable across all epics; they should not depend on domain-specific types or services.
- Ensure all future domain services import `IdentiKeyError` and `ErrorCodes` from this shared location rather than defining their own error types.
- Ensure logging is centralized through `logger` so that CLI, MCP, and future Web UI can assume consistent structured logs regardless of where the call originates.

### Learnings from Previous Story

From **Story 1.3 – Keycloak Client Wrapper** (`docs/sprint-artifacts/1-3-keycloak-client-wrapper.md`):

- `getKeycloakClient()` already centralizes Keycloak Admin client creation and authentication using configuration from `config.ts`, which means connectivity failures have a single choke point where `IdentiKeyError` should be applied.
- A preliminary `validateConnection()` hook location was identified; this story should avoid baking validation semantics into the error type itself so that Story 1.5 can extend diagnostics cleanly.
- The wrapper is the primary consumer of configuration today; by introducing `IdentiKeyError` and `logger` here, we ensure that all future domain services inherit the same error and logging semantics when they are layered on top of the client.

These learnings imply that:

- Error wrapping for connectivity/auth must live as close as possible to `getKeycloakClient()` so downstream services do not need to reason about raw Keycloak errors.
- Logging should avoid duplicating messages at both wrapper and service layers; the wrapper should log connection/auth failures once with enough structured context (but no secrets).

### References

- [Source: `docs/epics.md` – Epic 1 / Story 1.4: Error Types & Logging Setup](../epics.md#story-14-error-types--logging-setup)
- [Source: `docs/prd.md` – FR1–FR4, Non-Functional Requirements: Security, Reliability, Observability](../prd.md)
- [Source: `docs/architecture.md` – Project Structure, Error Handling, Logging Strategy](../architecture.md)
- [Source: `docs/sprint-artifacts/tech-spec-epic-1.md` – Story 1.4 spec and acceptance criteria](./tech-spec-epic-1.md)

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/1-4-error-types-logging-setup.context.xml

### Agent Model Used

keycloak-commander – SM create-story workflow (YOLO, non-interactive)

### Debug Log References

### Completion Notes List

- Implemented `IdentiKeyError` and `ErrorCodes` in `src/lib/keycloak/errors.ts` and wired them into the Keycloak client wrapper so connectivity/auth failures are wrapped with specific codes and preserved causes.
- Added a shared `logger` in `src/lib/keycloak/logger.ts` backed by Pino, driven by `LOG_LEVEL`, and used by the client wrapper to log non-leaky diagnostics on auth failures.
- Extended tests (`errors.spec.ts`, `logger.spec.ts`, `client.spec.ts`) to cover error shape, logger configuration, and error-wrapping behavior for synthetic Keycloak auth failures.

### File List

- docs/sprint-artifacts/1-4-error-types-logging-setup.md
- src/lib/keycloak/errors.ts
- src/lib/keycloak/errors.spec.ts
- src/lib/keycloak/logger.ts
- src/lib/keycloak/logger.spec.ts
- src/lib/keycloak/client.ts
- src/lib/keycloak/client.spec.ts

## Change Log

- 2025-11-30 – Initial draft created via SM `*create-story` workflow.
