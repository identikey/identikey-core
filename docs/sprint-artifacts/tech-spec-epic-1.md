# Epic Technical Specification: Epic 1 – Foundation

Date: 2025-11-30
Author: Master Dorje
Epic ID: 1
Status: Draft

---

## Overview

Epic 1 – Foundation establishes the **project infrastructure, configuration, and Keycloak connectivity** that all other epics depend on. It wires up the core runtime contracts (config loading, Keycloak client wrapper, error/logging primitives, and connection validation) so that the higher‑level services (users, apps, guilds, roles, auth flows, sessions, events) can be implemented without re‑solving environment, auth, and diagnostics concerns.

This epic delivers a working skeleton of the **service‑first architecture** defined in `architecture.md`: SvelteKit app shell, a TypeScript core service layer around `@keycloak/keycloak-admin-client`, and entry points for MCP and CLI. From a PRD perspective, it realizes **FR1–FR4** (authentication and connection requirements) and prepares the ground for exposing all later operations via MCP and CLI.

## Objectives and Scope

**In Scope**

- Implement environment‑backed configuration loading for Keycloak connectivity, validated via Zod (FR3).
- Implement a reusable Keycloak Admin client wrapper that supports both **service account** and **username/password** auth flows, with token refresh and singleton lifecycle (FR1, FR2).
- Define standard error types (`IdentiKeyError`, error codes) and structured logging (`pino`) for all subsequent epics.
- Provide a connection validation mechanism that can be invoked at startup from **CLI** and **MCP** entrypoints, surfacing actionable diagnostics when Keycloak is unreachable or credentials are invalid (FR4).
- Ensure the **project structure and dependencies** match `architecture.md`, including creation of core directories under `src/lib/keycloak`, `src/mcp`, and `src/cli`, and the presence of `.env.example` with all required variables.

**Out of Scope**

- Domain services for users, apps, guilds, roles, auth flows, sessions, or events (Epics 2–6) beyond what is needed to validate connectivity.
- Any Web UI routes beyond the existing scaffold; Epic 1 does not add UI features.
- UX design artifacts or visual admin flows.
- Keycloak realm provisioning, realm import/export, or multi‑realm support (explicitly out of scope in the PRD).
- High‑availability deployment, clustering, or production SRE concerns (beyond basic reliability behaviors and logging).

## System Architecture Alignment

Epic 1 implements the **lower layer** of the architecture diagram in `architecture.md`:

- It realizes `src/lib/keycloak/config.ts`, `src/lib/keycloak/client.ts`, `src/lib/keycloak/errors.ts`, and `src/lib/keycloak/logger.ts` as the shared foundation for all services.
- It enforces the **IdentiKey abstraction** choice (ADR‑002) by hiding raw Keycloak connectivity details behind typed, domain‑oriented helpers that later services will consume.
- It wires configuration and client acquisition so that **MCP server (`src/mcp/index.ts`)** and **CLI (`src/cli/index.ts`)** can both obtain an authenticated client via a common API, respecting the **service‑first architecture** (ADR‑001, ADR‑003).
- It aligns with the **security architecture** section: credentials are pulled from env vars, never logged, and connections use validated HTTPS URLs.

Once this epic is complete, higher‑level epics can safely assume:

- Access to a typed, authenticated `KcAdminClient` instance via a single helper (`getKeycloakClient()`).
- A validated configuration object available throughout the codebase.
- Common logging and error primitives that preserve stack traces while redacting secrets.
- A `validateConnection()` routine that can be used by any entrypoint to gate startup.

## Detailed Design

### Services and Modules

**Core modules introduced or finalized in this epic:**

- **`src/lib/keycloak/config.ts`**
  - **Responsibility:** Load and validate all Keycloak‑related configuration from environment variables.
  - **Inputs:** `process.env.KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_USERNAME`, `KEYCLOAK_PASSWORD`, `LOG_LEVEL`.
  - **Outputs:** A typed `Config` object usable by client and services.
  - **Consumers:** `client.ts`, CLI entry (`src/cli/index.ts`), MCP server (`src/mcp/index.ts`), future services.

- **`src/lib/keycloak/client.ts`**
  - **Responsibility:** Provide a singleton, authenticated instance of `@keycloak/keycloak-admin-client` with support for both admin credentials and service account credentials, plus connection validation.
  - **Inputs:** `Config` from `config.ts`.
  - **Outputs:** `getKeycloakClient(): Promise<KcAdminClient>`, `validateConnection(): Promise<void>`.
  - **Consumers:** All domain services (users, apps, guilds, roles, auth‑flows, sessions, events), CLI, MCP.

- **`src/lib/keycloak/errors.ts`**
  - **Responsibility:** Define `IdentiKeyError` and a constrained set of error codes that domain services and entrypoints use to represent logical and connectivity issues.
  - **Inputs:** Underlying exceptions (Keycloak client errors, network errors, validation errors).
  - **Outputs:** `IdentiKeyError` instances with `code` and optional `cause`, plus `ErrorCodes` constant.
  - **Consumers:** All domain services and higher‑level code paths that want consistent error semantics.

- **`src/lib/keycloak/logger.ts`**
  - **Responsibility:** Configure a Pino logger instance with environment‑driven log level and dev‑friendly pretty output.
  - **Inputs:** `LOG_LEVEL`, `NODE_ENV`.
  - **Outputs:** `logger` object with standard logging methods.
  - **Consumers:** `client.ts`, services, CLI/MCP initialization code.

- **Project structure scaffolding (Epic Story 1.1)**
  - Ensure the following directories exist and are wired into `tsconfig.json` paths if needed:
    - `src/lib/keycloak/`
    - `src/lib/keycloak/services/`
    - `src/mcp/` and `src/mcp/tools/`
    - `src/cli/` and `src/cli/commands/`
  - Confirm `.env.example` at repo root has all `KEYCLOAK_*` and logging variables required by `config.ts`.

### Data Models and Contracts

Epic 1 defines **configuration and error contracts**, not domain entities:

- **Configuration Model (`Config`)**
  - Fields (mapped by Zod schema):
    - `keycloakUrl: string` – must be a valid URL (`https://...`) and is required.
    - `keycloakRealm: string` – defaults to `"master"` if unset.
    - `keycloakClientId: string` – defaults to `"admin-cli"` if unset.
    - `keycloakUsername: string` – required when using username/password auth.
    - `keycloakPassword: string` – required when using username/password auth.
  - Behavior:
    - If required fields are missing or invalid, the schema throws a descriptive validation error naming the offending field.
    - The same config object can be used by a future service‑account‑based auth path; no extra fields are mandated in this epic, but the shape must not preclude adding them (e.g., `KEYCLOAK_CLIENT_SECRET`).

- **Error Model (`IdentiKeyError`)**
  - Fields:
    - `message: string` – human‑readable error description; must avoid leaking secrets.
    - `code: string` – one of `ErrorCodes`, e.g.:
      - `USER_NOT_FOUND`
      - `APP_NOT_FOUND`
      - `GUILD_NOT_FOUND`
      - `AUTH_FLOW_NOT_FOUND`
      - `UNAUTHORIZED`
      - `CONNECTION_FAILED`
      - `INVALID_INPUT`
    - `cause?: Error` – optional underlying error instance.
  - Behavior:
    - `IdentiKeyError` extends `Error` and preserves stack traces.
    - Service implementations wrap low‑level Keycloak or network errors into `IdentiKeyError` with a specific code and a scrubbed message.

- **Logging Contract**
  - `logger` conforms to the Pino interface; consumer code treats it as an opaque structured logger.
  - Sensitive fields (e.g., `keycloakPassword`, tokens, secrets) are **never passed** directly into structured log objects; where needed, logs use non‑sensitive identifiers (user ID, client ID, flow alias).

### APIs and Interfaces

Epic 1 surfaces **internal APIs** for later epics and entrypoints:

- **Config Loader API**
  - Function: `loadConfig(): Config`
  - Semantics:
    - Reads environment variables and validates via Zod.
    - Throws Zod validation errors when required vars are missing or malformed; callers may catch and render user‑friendly messages.

- **Keycloak Client API**
  - Function: `getKeycloakClient(): Promise<KcAdminClient>`
    - On first call:
      - Loads config.
      - Instantiates `KcAdminClient` with `baseUrl` and `realmName`.
      - Performs `client.auth({ username, password, grantType: 'password', clientId })`.
      - Caches the authenticated instance.
    - On subsequent calls:
      - Returns the cached instance (reusing token refresh logic inside the library).
    - On failure:
      - Wraps errors in `IdentiKeyError` with code `CONNECTION_FAILED` or `UNAUTHORIZED` depending on the failure mode.
  - Function: `validateConnection(): Promise<void>`
    - Intended usage:
      - CLI startup and MCP server startup call this to fail fast if Keycloak is unreachable or credentials are invalid.
    - Behavior:
      - Calls `getKeycloakClient()` and then a cheap introspection endpoint (e.g., server info) to verify connectivity (FR4).
      - Distinguishes common error conditions:
        - DNS/connection error → guidance to check `KEYCLOAK_URL` and network.
        - 401/403 → guidance to check credentials and client configuration.

- **Error API**
  - Class: `IdentiKeyError extends Error`
  - Constant: `ErrorCodes` – frozen object enumerating canonical error codes.
  - Usage contract:
    - All domain services throw `IdentiKeyError` (or subclasses) for logical failures.
    - Entry points (CLI, MCP, Web) translate `IdentiKeyError` into user‑facing responses.

- **Logger API**
  - Export: `logger`
  - Behavior:
    - `LOG_LEVEL` controls thresholds.
    - In `NODE_ENV=development`, uses `pino-pretty` transport; otherwise JSON logs.

At this stage, no new **HTTP** routes or MCP tools are defined; those are handled in later epics. However, this epic specifies that the MCP server and CLI entrypoints **must depend on the config/client APIs** instead of configuring `@keycloak/keycloak-admin-client` inline.

### Workflows and Sequencing

**Startup workflow (CLI / MCP / Web UI dev server):**

1. Process starts (e.g., `bun run src/cli/index.ts` or `bun run src/mcp/index.ts`).
2. Early in initialization, call `loadConfig()`:
   - If validation fails, log an error with the missing/invalid variable name and exit with non‑zero status.
3. Call `validateConnection()`:
   - If Keycloak is unreachable:
     - Log `CONNECTION_FAILED` along with `keycloakUrl` (no credentials).
     - Exit with clear guidance (check URL, TLS, network).
   - If credentials are invalid:
     - Log `UNAUTHORIZED` with high‑level description only.
     - Exit with guidance to check username/password/client ID.
4. If validation succeeds:
   - Proceed to register domain services and either:
     - Start MCP stdio server loop, or
     - Dispatch CLI command logic.

**Developer feedback loop (Story 1.5):**

- Developer updates `.env` and reruns `bun run src/cli/index.ts` (or `bun run src/mcp/index.ts`).
- On each run, connection validation confirms that environment configuration and Keycloak connectivity are correct before any user‑facing operations are attempted.

## Non-Functional Requirements

### Performance

Epic 1’s performance focus is limited to **avoiding unnecessary overhead at startup and in client acquisition**:

- `getKeycloakClient()` uses a singleton pattern to avoid repeated auth handshakes on every service operation.
- Connection validation hits a lightweight, read‑only endpoint; it must not perform bulk queries.
- No additional caching layers are introduced; the Keycloak client’s existing token management is sufficient for this epic.

### Security

Security constraints implemented or enforced in this epic:

- Credentials are sourced exclusively from environment variables (`.env` in dev, real secrets in CI/prod) and **never** logged or echoed.
- `KEYCLOAK_URL` is validated as an HTTPS URL; non‑HTTPS schemas are rejected or at least called out clearly when not in development.
- Pino logger configuration is designed so that sensitive fields (passwords, token values, secrets) never appear in logs; service code must avoid serializing raw credential objects.
- MCP server will later rely on stdio transport only; this epic ensures the underlying client/auth path is safe for local execution.

### Reliability/Availability

- `validateConnection()` provides an early, deterministic signal if Keycloak is unreachable or misconfigured, instead of allowing random failures later in domain services.
- `IdentiKeyError` standardizes error signaling, making it easier to propagate precise failure modes up the stack.
- Operations that depend solely on configuration and connectivity are designed to be idempotent: running CLI/MCP startup multiple times in the face of transient network errors is safe.

### Observability

- Pino logger is configured in a way that is compatible with later centralized logging (JSON output in non‑dev environments).
- Connection validation logs:
  - A success message with realm name and base URL.
  - Clear, structured failure messages keyed on `CONNECTION_FAILED` or `UNAUTHORIZED`.
- Subsequent epics will attach additional metrics and tracing, but the foundational logging decisions and primitives are put in place here.

## Dependencies and Integrations

**Runtime dependencies (directly relevant to this epic):**

- `@keycloak/keycloak-admin-client` – official Keycloak admin client, used to authenticate and talk to the IdentiKey Keycloak instance.
- `zod` – used to define and validate the configuration schema.
- `pino` – structured logging library.
- `dotenv` – dev‑time loading of `.env` into `process.env`.

**Platform / framework dependencies (impacted by this epic but not fully exercised yet):**

- Node.js 20+ or Bun – execution environment.
- Existing SvelteKit scaffold – not directly modified, but future routes will also rely on the same config/client.

**External integrations:**

- IdentiKey’s Keycloak instance at `KEYCLOAK_URL`:
  - Realm is always `KEYCLOAK_REALM` (default `master`).
  - Auth uses the `admin-cli` client by default (`KEYCLOAK_CLIENT_ID`).
  - Admin credentials (or service account) must be provisioned outside this codebase.

This epic does **not** introduce new external systems beyond Keycloak; it standardizes how we talk to Keycloak from all interfaces.

## Acceptance Criteria (Authoritative)

1. **Project Structure & Dependencies (Story 1.1):**
   - Given a fresh clone, when `bun install` runs, then all dependencies install without error and the following packages are present: `@keycloak/keycloak-admin-client`, `@modelcontextprotocol/sdk`, `citty`, `zod`, `pino`, `dotenv`.
   - And the directories `src/lib/keycloak/`, `src/mcp/`, `src/cli/` exist and match the structure in `architecture.md`.
   - And `.env.example` contains all required `KEYCLOAK_*` and logging variables.

2. **Configuration Loading (Story 1.2, FR3):**
   - Given a `.env` file with `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_USERNAME`, `KEYCLOAK_PASSWORD`, when the config module is imported, then config is loaded and validated via Zod.
   - And missing required variables result in a clear error naming the missing variable.
   - And `KEYCLOAK_REALM` defaults to `master` and `KEYCLOAK_CLIENT_ID` defaults to `admin-cli` when omitted.

3. **Keycloak Client Wrapper (Story 1.3, FR1, FR2):**
   - Given valid credentials, when `getKeycloakClient()` is first invoked, then it returns an authenticated `KcAdminClient` instance configured for the target realm.
   - And the same instance is reused on subsequent calls (singleton behavior).
   - And authentication supports username/password flow at minimum, with an extension path for service account credentials.

4. **Error Types & Logging (Story 1.4):**
   - Given a Keycloak or network error occurs in a connectivity path, when it is handled, then it is wrapped in `IdentiKeyError` with a specific `code` and optional `cause`.
   - And the logger is configured with JSON output in production, pretty output in development, and log level driven by `LOG_LEVEL` (default `info`).
   - And no logs contain passwords, secrets, or tokens.

5. **Connection Validation (Story 1.5, FR4):**
   - Given correct URL and valid credentials, when `validateConnection()` runs, then a success message including realm name is logged and the process continues.
   - Given an unreachable Keycloak URL, when `validateConnection()` runs, then a failure is logged including the URL and guidance to check network/URL.
   - Given invalid credentials, when `validateConnection()` runs, then a failure is logged indicating authentication failed without exposing secrets.

## Traceability Mapping

**FR Coverage (Epic 1):**

- **FR1 – Service account auth** → `client.ts` auth strategy + future extension to service account; validated via `getKeycloakClient()` behavior.
- **FR2 – Username/password auth** → `client.ts` password‑grant authentication using `KEYCLOAK_USERNAME` and `KEYCLOAK_PASSWORD`.
- **FR3 – Env var configuration** → `config.ts` Zod schema and `.env.example` contract.
- **FR4 – Connection validation** → `validateConnection()` implementation and startup wiring.

**Story to Spec Sections:**

- **Story 1.1 – Project Structure & Dependencies**
  - Spec sections: _Services and Modules_, _Dependencies and Integrations_, _Acceptance Criteria #1_.
  - Components: directory scaffolding, package dependencies.
  - Test ideas: smoke run `bun install`, verify directory tree, verify `.env.example` contents.

- **Story 1.2 – Configuration Loading**
  - Spec sections: _Data Models and Contracts_, _APIs and Interfaces_, _NFR – Security_.
  - Components: `config.ts`, Zod schema, `.env` handling.
  - Test ideas: unit tests for missing/invalid env vars, defaulting behavior, and URL validation.

- **Story 1.3 – Keycloak Client Wrapper**
  - Spec sections: _Services and Modules_, _APIs and Interfaces_, _Workflows and Sequencing_.
  - Components: `client.ts`, `getKeycloakClient`, `validateConnection`.
  - Test ideas: integration tests against a dev Keycloak instance; ensure singleton behavior and auth failure modes.

- **Story 1.4 – Error Types & Logging Setup**
  - Spec sections: _Data Models and Contracts_, _NFR – Observability_, _NFR – Reliability_.
  - Components: `errors.ts`, `logger.ts`.
  - Test ideas: unit tests verifying `IdentiKeyError` codes and that logs redact sensitive info.

- **Story 1.5 – Connection Validation**
  - Spec sections: _Workflows and Sequencing_, _NFR – Reliability_, _Acceptance Criteria #5_.
  - Components: `validateConnection`, startup hooks in CLI/MCP.
  - Test ideas: simulate unreachable URL and bad credentials; assert exit behavior and log content.

## Risks, Assumptions, Open Questions

- **Risk:** Misconfigured env vars (e.g., wrong realm or URL) could pass basic validation but still point to the wrong Keycloak instance.
  - **Mitigation:** Encourage use of a dedicated dev realm and include realm name in success logs; consider adding a sanity check endpoint (e.g., realm info) in `validateConnection`.

- **Risk:** Over‑centralizing config/client logic may tempt later epics to add domain‑specific behavior into `client.ts`.
  - **Mitigation:** Keep `client.ts` focused strictly on connectivity/auth and expose domain logic only via dedicated services under `services/`.

- **Assumption:** Events and advanced auth flows are enabled/configured appropriately in the target Keycloak instance; Epic 1 only ensures we can connect, not that all APIs are enabled.
  - **Next Step:** Document realm prerequisites in the project README as Epics 5 and 6 are implemented.

- **Question:** Do we need explicit support for multiple auth modes (service account vs admin credentials) in MVP, or is admin username/password sufficient initially?
  - **Next Step:** Decide before wiring CI credentials; if service accounts are preferred, extend `Config` and `client.ts` accordingly while preserving current contracts.

## Test Strategy Summary

- **Unit Tests**
  - `config.ts`: validate happy path, missing vars, invalid URL, and defaulting behavior.
  - `errors.ts`: ensure `IdentiKeyError` preserves message, code, and cause; verify `ErrorCodes` is exhaustive for current use cases.
  - `logger.ts`: smoke‑test initialization and log level behavior (without hitting real outputs in CI).

- **Integration Tests (against a dev Keycloak instance)**
  - `getKeycloakClient()`: confirm successful auth with valid credentials and proper error classification for invalid credentials or bad URL.
  - `validateConnection()`: test scenarios for reachable/unreachable Keycloak and incorrect credentials, asserting logs and exit codes.

- **Manual / Smoke Tests**
  - Run `bun run src/cli/index.ts` (or a dedicated `bun run cli` script when present) with various `.env` configurations to ensure error messages are understandable and non‑leaky.
  - Run the MCP server in Cursor using `.cursor/mcp.json` config and verify it fails fast with clear messaging when configuration is invalid.

This epic’s test strategy is primarily focused on **correctness and safety of connectivity**, minimizing the blast radius of configuration mistakes before higher‑level functionality lands in later epics.
