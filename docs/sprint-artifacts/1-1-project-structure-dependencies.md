# Story 1.1: Project Structure & Dependencies

Status: done

## Story

As a **developer**,  
I want **the project scaffolded with required dependencies**,  
so that **I can start building the core service layer**.

## Acceptance Criteria

1. **Dependencies installed successfully**
   - Given a fresh clone of the repository  
     When I run `bun install`  
     Then all dependencies are installed without errors.

2. **Required runtime/dev dependencies present**
   - And the following packages are available in the installed dependencies:
     - `@keycloak/keycloak-admin-client`
     - `@modelcontextprotocol/sdk`
     - `citty`
     - `zod`
     - `pino`
     - `dotenv`

3. **Project structure matches architecture**
   - And the project structure matches `docs/architecture.md` for the foundation layer:
     - `src/lib/keycloak/` directory exists (with subfolder `services/` reserved for later epics).
     - `src/mcp/` directory exists (with `tools/` subfolder).
     - `src/cli/` directory exists (with `commands/` and `utils/` subfolders as needed).

4. **Environment template prepared**
   - And `.env.example` exists at the repo root and includes all required Keycloak and logging variables described in the Architecture document (URL, realm, client ID, username, password, log level).

5. **Tooling alignment**
   - And `package.json` scripts (or equivalent Bun commands) exist or are ready to be wired so later stories can add:
     - `cli` entry for `src/cli/index.ts`.
     - `mcp` entry for `src/mcp/index.ts`.
     - `dev` entry for the SvelteKit dev server.

## Tasks / Subtasks

- [x] **T1 – Ensure dependencies are declared**
  - [x] Add `@keycloak/keycloak-admin-client`, `@modelcontextprotocol/sdk`, `citty`, `zod`, `pino`, and `dotenv` to `package.json` (using Bun add or manual edit) with versions consistent with the current toolchain.
  - [x] Run `bun install` and verify it completes without errors.

- [x] **T2 – Align source tree with architecture**
  - [x] Ensure `src/lib/keycloak/` exists.
  - [x] Ensure `src/lib/keycloak/services/` exists for later domain services.
  - [x] Ensure `src/mcp/` and `src/mcp/tools/` exist.
  - [x] Ensure `src/cli/`, `src/cli/commands/`, and `src/cli/utils/` exist.
  - [x] Confirm any necessary TypeScript path mappings in `tsconfig.json` align with this structure (no-op if already aligned).

- [x] **T3 – Prepare environment template**
  - [x] Confirm `.env.example` exists at the repo root.
  - [x] Ensure it contains, at minimum: `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_USERNAME`, `KEYCLOAK_PASSWORD`, and `LOG_LEVEL`.
  - [x] Keep values obviously non-secret placeholders (e.g., `your-password`), not real credentials.

- [x] **T4 – Package scripts and ergonomics**
  - [x] Review `package.json` scripts; if missing, plan additions for: - `"cli": "bun run src/cli/index.ts"`  
         - `"mcp": "bun run src/mcp/index.ts"`  
         - `"dev": "vite dev"`  
         (Actual creation of these may be deferred to a later story if already covered elsewhere in the tech spec; note any deltas in Dev Notes.)

## Dev Notes

- **Architecture alignment**
  - This story is implementing the foundational project structure from `docs/architecture.md`, particularly the `Project Structure` section and the dependencies list (`@keycloak/keycloak-admin-client`, `@modelcontextprotocol/sdk`, `citty`, `zod`, `pino`, `dotenv`).
  - The created directories are scaffolding for later epics (users, apps, guilds, roles, auth-flows, sessions, events) and must not bake in domain-specific behavior yet.

- **Source tree components to touch**
  - `package.json` – declare required dependencies (and scripts if not already present).
  - `tsconfig.json` – verify or adjust path mappings to recognize `src/lib/keycloak`, `src/mcp`, and `src/cli` if needed.
  - `.env.example` – ensure it matches the configuration contract in `docs/architecture.md` (Keycloak URL/realm/client and admin credentials, plus log level).
  - `src/` – ensure the directory skeleton matches the Architecture diagram; no functional code required in this story.

- **Testing standards summary**
  - Primary validation is via `bun install` and simple structural checks (directories and files exist).
  - No new automated tests are strictly required for this story; later configuration and service stories will introduce unit/integration tests. However, if convenient, a lightweight script or check can be added in a future story to assert directory presence.

### Project Structure Notes

- Aligns with the architecture’s service-first pattern:
  - `src/lib/keycloak/` will host `config.ts`, `client.ts`, `errors.ts`, `logger.ts`, and `types.ts` in later stories.
  - `src/mcp/` will become the MCP stdio server entry with tool registrations per domain.
  - `src/cli/` will be the citty-based CLI root with domain subcommands.
- Any deviations from `docs/architecture.md` structure should be captured in the Change Log once implemented.

### References

- [Source: `docs/epics.md` – Epic 1 / Story 1.1](../epics.md#epic-1-foundation)
- [Source: `docs/architecture.md` – Project Structure, Dependencies, Configuration](../architecture.md)
- [Source: `docs/sprint-artifacts/tech-spec-epic-1.md` – Services/Modules & Dependencies sections](./tech-spec-epic-1.md)

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/1-1-project-structure-dependencies.context.xml

### Agent Model Used

Cursor AI – keycloak-commander / Story 1.1

### Debug Log References

### Completion Notes List

- Dependencies and scripts required for the foundation layer have been added to `package.json` in line with `docs/architecture.md`.
- Core directory scaffolding for `src/lib/keycloak/`, `src/mcp/`, and `src/cli/` (with their key subfolders) is now present, ready for subsequent epics to populate.
- `.env.example` is present and matches the Keycloak/logging variables defined in the architecture document; local dev must still customize real values.
- `bun install` and the Vitest unit suite completed successfully on the developer machine, confirming the scaffold and deps are healthy.

### File List

- NEW `src/lib/keycloak/.gitkeep`
- NEW `src/lib/keycloak/services/.gitkeep`
- NEW `src/mcp/.gitkeep`
- NEW `src/mcp/tools/.gitkeep`
- NEW `src/cli/.gitkeep`
- NEW `src/cli/commands/.gitkeep`
- NEW `src/cli/utils/.gitkeep`
- MODIFIED `package.json`
