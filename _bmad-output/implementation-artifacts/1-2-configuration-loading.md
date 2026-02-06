# Story 1.2: Configuration Loading

Status: done

## Story

As a **developer**,  
I want **configuration loaded from environment variables**,  
so that **I can connect to different Keycloak instances without code changes**.

## Acceptance Criteria

1. **Configuration loaded from `.env`**
   - Given a `.env` file with `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_USERNAME`, `KEYCLOAK_PASSWORD`  
     When the config module is imported  
     Then configuration is loaded into a typed object.

2. **Zod schema validation**
   - And configuration is validated with a Zod schema that enforces:
     - `KEYCLOAK_URL` is a valid URL.
     - `KEYCLOAK_USERNAME` and `KEYCLOAK_PASSWORD` are present (for password‑grant).

3. **Clear errors for missing variables**
   - And missing required variables throw a clear error that names the missing variable.

4. **URL format validation**
   - And invalid URL format for `KEYCLOAK_URL` throws a validation error (not a generic runtime error).

5. **Sensible defaults**
   - And `KEYCLOAK_REALM` defaults to `master` if not provided.
   - And `KEYCLOAK_CLIENT_ID` defaults to `admin-cli` if not provided.

## Tasks / Subtasks

- [x] **T1 – Implement config module**
  - [x] Create `src/lib/keycloak/config.ts` that: - Defines a `Config` Zod schema matching the fields above. - Loads environment variables (via `process.env` and `dotenv` in dev via `dotenv/config`). - Exposes a `loadConfig()` function that returns a typed config object or throws a Zod error.
  - [x] Ensure the module does **not** log secrets; it only validates and returns typed config.

- [x] **T2 – Wire dotenv/dev loading**
  - [x] Ensure `.env` is loaded automatically in dev via `import 'dotenv/config'` in `config.ts` (Node/MCP/CLI contexts).
  - [x] Confirm `.env.example` and the `Config` schema stay in sync (same keys and semantics).

- [x] **T3 – Unit tests for config behavior**
  - [x] Add unit tests that: - Verify happy‑path loading with all env vars set. - Verify defaulting of `KEYCLOAK_REALM` and `KEYCLOAK_CLIENT_ID`. - Verify errors for missing required vars and invalid URL.
  - [x] Make tests independent of the real developer’s `.env` (by manipulating `process.env` within tests).

- [x] **T4 – Integration sanity check**
  - [x] Use `loadConfig()` from tests to confirm it integrates cleanly and types align with the architecture spec.
  - [x] Keep docs/comments in `config.ts` minimal; behavior is obvious for an expert.

## Dev Notes

- **Architecture alignment**
  - This story delivers the `config.ts` module described in `docs/architecture.md` under **Configuration**, and is the concrete realization of the configuration layer referenced in the Epic 1 tech spec.
  - The module is the single source of truth for Keycloak connection settings across CLI, MCP, and later web UI layers.

- **Source tree components to touch**
  - `src/lib/keycloak/config.ts` – new config loader and Zod schema.
  - Test files under `src/` (e.g. `src/lib/keycloak/config.spec.ts` or similar) for unit coverage.
  - `.env.example` – already populated by Story 1.1; ensure new fields or semantics remain consistent if anything changes.

- **Testing standards summary**
  - Focus on **deterministic, unit‑level** tests of configuration behavior:
    - No network calls.
    - No reliance on real Keycloak instances.
  - Tests should be fast and compatible with the existing Vitest setup (Node environment).

### Project Structure Notes

- `config.ts` must stay independent of any Keycloak client instantiation logic (that’s Story 1.3’s concern); it should only understand env vars and validation.
- Avoid spreading env access across the codebase; all Keycloak connection settings should flow from `loadConfig()`.

### References

- [Source: `docs/epics.md` – Epic 1 / Story 1.2](../epics.md#story-12-configuration-loading)
- [Source: `docs/architecture.md` – Configuration section and sample `loadConfig` implementation](../architecture.md)
- [Source: `docs/sprint-artifacts/tech-spec-epic-1.md` – Configuration & services/mapping](./tech-spec-epic-1.md)

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/1-2-configuration-loading.context.xml

### Agent Model Used

Cursor AI – keycloak-commander / Story 1.2

### Debug Log References

### Completion Notes List

- Implemented `src/lib/keycloak/config.ts` with a Zod-backed `Config` schema and `loadConfig()` helper that reads from `process.env`, defaulting realm/client ID and log level per the architecture doc.
- Wired `dotenv` for development contexts via `import 'dotenv/config'` so CLI/MCP entrypoints automatically pick up `.env` without extra boilerplate.
- Added `src/lib/keycloak/config.spec.ts` with unit tests covering happy-path, defaults, and validation failures; Vitest unit suite (including existing tests) passes.

### File List

- NEW `src/lib/keycloak/config.ts`
- NEW `src/lib/keycloak/config.spec.ts`
