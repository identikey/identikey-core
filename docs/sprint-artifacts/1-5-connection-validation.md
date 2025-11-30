# Story 1.5: Connection Validation

Status: ready-for-dev

## Story

As a **developer**,  
I want **connection validated on startup with clear error messages**,  
so that **I know immediately if Keycloak is unreachable** (FR4).

## Acceptance Criteria

1. **Successful validation path**
   - Given `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_USERNAME`, and `KEYCLOAK_PASSWORD` are valid  
     When `validateConnection()` runs at startup  
     Then it uses the same `getKeycloakClient()` path as the rest of the system to obtain an authenticated client and calls a lightweight Keycloak introspection endpoint (e.g. server info) to verify connectivity.  
     And a success message is logged that clearly includes the Keycloak base URL and realm name.

2. **Unreachable URL diagnostics**
   - Given `KEYCLOAK_URL` points to a host or scheme that cannot be reached (network/DNS/TLS failure)  
     When `validateConnection()` runs  
     Then it fails fast with an `IdentiKeyError` using a connectivity-focused code (e.g. `CONNECTION_FAILED`) and logs a structured error that:
     - includes the configured URL (without credentials), and
     - explicitly suggests checking network, TLS, and/or URL configuration.

3. **Invalid credentials diagnostics**
   - Given `KEYCLOAK_URL` is reachable but credentials are invalid  
     When `validateConnection()` runs  
     Then it fails fast with an `IdentiKeyError` using an auth-focused code (e.g. `UNAUTHORIZED`) and logs that authentication failed,  
     And the error message and logs do **not** expose passwords, tokens, or client secrets.

4. **CLI and MCP startup behavior**
   - Given the CLI (`src/cli/index.ts`) and MCP server (`src/mcp/index.ts`) use the shared configuration and client APIs  
     When each entrypoint starts  
     Then it calls `loadConfig()` and `validateConnection()` early in initialization, before registering tools or commands, and:
     - exits with a non-zero status if validation fails, after logging actionable diagnostics, and
     - proceeds to normal operation only when validation succeeds.

5. **No redundant network overhead**
   - Given `getKeycloakClient()` already performs authentication and caches the client as a singleton  
     When `validateConnection()` is run multiple times in a process (e.g. tests, repeated CLI invocations)  
     Then it reuses the existing client instance where possible and uses a cheap, read-only endpoint for validation, avoiding unnecessary heavy or stateful operations.

## Tasks / Subtasks

- [ ] **T1 – Implement `validateConnection()`**
  - [ ] Extend `src/lib/keycloak/client.ts` with an exported `async function validateConnection(): Promise<void>` that:
    - [ ] Calls `getKeycloakClient()` to ensure configuration and authentication succeed through the same path as normal operations.
    - [ ] Invokes a lightweight Keycloak endpoint (e.g. server info) to confirm the realm is reachable.
    - [ ] Differentiates between connectivity failures (URL/transport/DNS/TLS) and authentication failures, mapping them to appropriate `ErrorCodes`.

- [ ] **T2 – Integrate error and logging primitives**
  - [ ] Use `IdentiKeyError` and `ErrorCodes` from `src/lib/keycloak/errors.ts` to wrap failures in `validateConnection()`, using at least `CONNECTION_FAILED` and `UNAUTHORIZED` as appropriate.
  - [ ] Use the shared `logger` from `src/lib/keycloak/logger.ts` to emit:
    - [ ] A clear success log with base URL and realm on success.
    - [ ] Structured error logs on failure, including URL and high-level reason but no secrets.

- [ ] **T3 – Wire validation into entrypoints**
  - [ ] Update CLI entrypoint (`src/cli/index.ts`, or equivalent) so that startup:
    - [ ] Calls `loadConfig()` and fails with a clear message if configuration is invalid.
    - [ ] Calls `validateConnection()` once before dispatching any commands, exiting non-zero on failure.
  - [ ] Update MCP server entrypoint (`src/mcp/index.ts`) to follow the same pattern: config → `validateConnection()` → server initialization.

- [ ] **T4 – Tests and diagnostics**
  - [ ] Add unit or integration-style tests (using mocks for Keycloak client where needed) that cover:
    - [ ] Successful validation with simulated server info response.
    - [ ] Unreachable URL / network error mapped to `CONNECTION_FAILED` with appropriate log behavior.
    - [ ] Invalid credentials mapped to `UNAUTHORIZED` with non-leaky messaging.
  - [ ] Add at least one harness or smoke test pattern that can be run against a real dev Keycloak instance later, verifying that CLI/MCP startup fails early and clearly when misconfigured.

## Dev Notes

- **Architecture alignment**
  - This story completes the FR4 path defined in `docs/prd.md` and `docs/sprint-artifacts/tech-spec-epic-1.md` by turning the `validateConnection()` concept into a concrete implementation wired into CLI and MCP startup.
  - It builds on the existing `config.ts`, `client.ts`, `errors.ts`, and `logger.ts` foundation described in `docs/architecture.md`, ensuring that all connectivity checks share the same configuration, error, and logging semantics.

- **Source tree components to touch**
  - `src/lib/keycloak/client.ts` – add `validateConnection()` and any minimal helpers required to distinguish connectivity vs auth failures.
  - `src/lib/keycloak/client.spec.ts` – extend tests to cover validation behavior (mocking the admin client / server info).
  - `src/cli/index.ts` – ensure early config loading and connection validation before command dispatch.
  - `src/mcp/index.ts` – ensure early config loading and connection validation before starting the MCP server loop.

- **Testing standards summary**
  - Prioritize **deterministic, unit-level tests** that simulate Keycloak responses and failures via mocks rather than requiring a real Keycloak instance in CI.
  - Reserve real-instance tests for local or manual smoke testing, using the same `validateConnection()` and startup wiring, so behavior matches what the spec describes under failure scenarios.

### Project Structure Notes

- Keep `validateConnection()` small and focused: it should orchestrate config/client acquisition and a single probe call, not introduce domain-specific behavior.
- Ensure both CLI and MCP reuse the same helper instead of re-implementing ad-hoc checks; this keeps startup semantics consistent across interfaces.
- Avoid peppering entrypoints with raw Keycloak calls; the intent is that **all** connectivity validation flows through `client.ts`.

### Learnings from Previous Story

From **Story 1.4 – Error Types & Logging Setup** (`docs/sprint-artifacts/1-4-error-types-logging-setup.md` and `.context.xml`):

- `IdentiKeyError` and `ErrorCodes` now provide a standardized way to represent connectivity and auth failures (`CONNECTION_FAILED`, `UNAUTHORIZED`), which `validateConnection()` must use rather than throwing raw errors.
- The shared `logger` module gives a single place to control log level and formatting; connection validation logs should use this instead of `console.log`, and must respect the non-leakage constraints from PRD and tech spec.
- Error and logging responsibilities live in the foundation layer; this story should not introduce new error types or logging backdoors, but instead reuse the primitives from 1.4 so later epics get consistent behavior "for free."

These learnings imply that:

- `validateConnection()` is effectively the first consumer of the error/logging primitives in a real workflow and sets the tone for how future services report failures.
- Logs produced here should be terse but diagnostic: enough information (URL, realm, high-level cause) to guide fixes, but no secrets and no duplicate noise when entrypoints wrap or surface errors.

### References

- [Source: `docs/epics.md` – Epic 1 / Story 1.5: Connection Validation](../epics.md#story-15-connection-validation)
- [Source: `docs/prd.md` – FR1–FR4, especially FR4: Connection validation on startup](../prd.md)
- [Source: `docs/architecture.md` – Keycloak client, Error Handling, Logging Strategy, Startup workflow](../architecture.md)
- [Source: `docs/sprint-artifacts/tech-spec-epic-1.md` – Story 1.5 spec and acceptance criteria for `validateConnection()` and startup behavior](./tech-spec-epic-1.md)

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/1-5-connection-validation.context.xml

### Agent Model Used

keycloak-commander – SM create-story workflow (YOLO, non-interactive)

### Debug Log References

- 2025-11-30 – Dev agent plan (Story 1.5 / T1–T4):
  - Implement `validateConnection()` in `src/lib/keycloak/client.ts` using `getKeycloakClient()` plus a lightweight probe (Keycloak server info) and classify failures into `ErrorCodes.CONNECTION_FAILED` vs `ErrorCodes.UNAUTHORIZED`.
  - Integrate `IdentiKeyError` and `logger` so success logs include base URL and realm, and failures log URL and high-level guidance (network/TLS/URL vs auth) without exposing secrets.
  - Extend `src/lib/keycloak/client.spec.ts` to cover successful validation, unreachable URL mapped to `CONNECTION_FAILED`, invalid credentials mapped to `UNAUTHORIZED`, and repeated validation runs without extra auth overhead.
  - Introduce minimal `src/cli/index.ts` and `src/mcp/index.ts` entrypoints that call `loadConfig()` and `validateConnection()` at startup and exit non-zero on validation failure, paving the way for full CLI/MCP wiring in later stories.

### Completion Notes List

- Drafted Story 1.5 to define `validateConnection()` behavior, its integration into CLI/MCP startup, and its use of existing error/logging primitives to satisfy FR4.

### File List

- docs/sprint-artifacts/1-5-connection-validation.md

## Change Log

- 2025-11-30 – Initial draft created via SM `*create-story` workflow.
