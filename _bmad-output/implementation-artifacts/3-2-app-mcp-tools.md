# Story 3.2: App MCP Tools

**Status:** ready-for-dev  
**Epic:** 3 - App Management  
**FR Coverage:** FR14-19 (Apps/Clients via MCP)  
**Story Key:** 3-2-app-mcp-tools

---

## Story

As an **AI agent or operator**,  
I want **MCP tools that expose App (OIDC client) operations**,  
So that **I can list, create, update, delete, and manage app secrets via the MCP protocol**.

---

## Acceptance Criteria

### AC1: List Apps Tool
- [ ] Tool `list_apps` is registered and callable via MCP
- [ ] Input: optional `max`, `offset`, optional `clientId` (filter by client ID)
- [ ] Output: `{ apps: App[], count: number }` (JSON + structuredContent)
- [ ] Delegates to `AppService.list(options)` (and filter by clientId if provided)
- [ ] Errors (e.g. Keycloak unreachable) returned as MCP error with actionable context (same pattern as user tools)

### AC2: Get App Tool
- [ ] Tool `get_app` with input `id` (Keycloak client UUID)
- [ ] Output: `{ app: App }`
- [ ] Delegates to `AppService.get(id)`; on APP_NOT_FOUND return structured error (no crash)

### AC3: Create App Tool
- [ ] Tool `create_app` with inputs: `clientId` (required), optional `name`, `description`, `enabled`, `protocol`, `redirectUris` (array), `webOrigins` (array), `publicClient`, `standardFlowEnabled`, `directAccessGrantsEnabled`
- [ ] Output: `{ app: App }` (created app with id)
- [ ] Delegates to `AppService.create(data)`; duplicate clientId / invalid input return structured error

### AC4: Update App Tool
- [ ] Tool `update_app` with input `id` and optional fields (same shape as create where applicable)
- [ ] Output: `{ app: App }`
- [ ] Delegates to `AppService.update(id, data)`; APP_NOT_FOUND → structured error

### AC5: Delete App Tool
- [ ] Tool `delete_app` with input `id`
- [ ] Output: `{ success: true, deletedAppId: string }`
- [ ] Delegates to `AppService.delete(id)`; APP_NOT_FOUND → structured error

### AC6: Client Secret Tools (Confidential Clients)
- [ ] Tool `get_app_secret`: input `id`, output `{ secret: string }` or structured error (e.g. public client or not found). **Do not** log or echo secret in tool description; document that secret is sensitive.
- [ ] Tool `regenerate_app_secret`: input `id`, output `{ secret: string }` (new secret). Same security note.
- [ ] Both delegate to `AppService.getSecret(id)` and `AppService.regenerateSecret(id)` respectively

### AC7: Registration and Wiring
- [ ] All app tools registered via a single function `registerAppTools(server, appService)` in `src/mcp/tools/apps.ts`
- [ ] `registerAllTools` in `src/mcp/tools/index.ts` accepts `appService` and calls `registerAppTools`
- [ ] MCP server entrypoint (`src/mcp/index.ts`) obtains `AppService` via `getAppService()` and passes it into `registerAllTools`. If `getAppService` does not exist yet (3.1 not done), this story depends on 3.1 being implemented first.

---

## Tasks / Subtasks

- [ ] **Task 1: App MCP tools module** (AC: 1–6)
  - [ ] Create `src/mcp/tools/apps.ts`
  - [ ] Define Zod schemas for App (and optional CreateAppInput/UpdateAppInput for validation) matching 3.1 domain types
  - [ ] Reuse or mirror `formatError` pattern from `users.ts` (IdentiKeyError, context object)
  - [ ] Implement `registerAppTools(server, appService)` with tools: list_apps, get_app, create_app, update_app, delete_app, get_app_secret, regenerate_app_secret

- [ ] **Task 2: Wire into tools index and server** (AC: 7)
  - [ ] Export `registerAppTools` from `src/mcp/tools/index.ts`
  - [ ] Extend `registerAllTools(server, services)` to accept `appService` and call `registerAppTools(server, appService)`
  - [ ] In `src/mcp/index.ts`: call `getAppService()` (from `src/lib/keycloak/services`), pass to `registerAllTools`

- [ ] **Task 3: Tests** (AC: all)
  - [ ] Add `src/mcp/tools/apps.spec.ts`: mock AppService, verify each tool is registered and invokes the correct service method with expected args; verify error path returns formatError-style response

---

## Dev Notes

### Dependency on Story 3.1
- **3.1 (AppService Core Operations)** must be implemented first. This story assumes `AppService`, `getAppService()`, and domain types `App`, `CreateAppInput`, `UpdateAppInput` exist in `src/lib/keycloak/services` and types.
- If 3.1 is not yet done, implement 3.1 before or in tandem; do not reimplement Keycloak client logic in MCP layer.

### Architecture Constraints
- **Service-first:** MCP tools only call AppService. No direct `client.clients.*` in this story.
- **Naming:** Use "App" in tool names and descriptions (list_apps, get_app, etc.) per ADR-002. Internal Keycloak "client" can appear in comments only.
- **Secrets:** Never log or include client secrets in tool descriptions or examples. Return secret only in the structured output; document that consumers must handle it securely.

### Previous Story (3.1) Intelligence
- AppService API: `list(options?)`, `get(id)`, `create(data)`, `update(id, data)`, `delete(id)`, `getSecret(id)`, `regenerateSecret(id)`.
- ListOptions: `{ max?, offset? }`; list can filter by clientId (see 3.1 AC1).
- Errors: `IdentiKeyError` with codes such as `APP_NOT_FOUND`, `INVALID_INPUT`.

### MCP Pattern (from users.ts)
- `server.registerTool(name, { title, description, inputSchema, outputSchema }, async (args) => { ... })`
- inputSchema/outputSchema use Zod schemas with `.describe()` for tool UX
- Return `{ content: [{ type: 'text', text: JSON.stringify(output, null, 2) }], structuredContent: output }` on success
- On error: return `formatError(error, { operation, ...context })` → `{ content: [...], isError: true }`
- Import `McpServer` from `@modelcontextprotocol/sdk/server/mcp.js`, `IdentiKeyError` from keycloak errors

### File Structure
- New file: `src/mcp/tools/apps.ts` (registerAppTools + tool handlers)
- Modify: `src/mcp/tools/index.ts` (export registerAppTools, add appService to registerAllTools)
- Modify: `src/mcp/index.ts` (getAppService, pass into registerAllTools)

### References
- [Source: _bmad-output/implementation-artifacts/3-1-appservice-core-operations.md] — AppService API, types, errors
- [Source: src/mcp/tools/users.ts] — registerUserTools, formatError, tool registration pattern
- [Source: src/mcp/tools/index.ts] — registerAllTools signature
- [Source: src/mcp/index.ts] — server startup, getUserService/getAuthFlowService pattern

### Developer Context (Guardrails)
- **Do not** add CLI commands in this story; those are 3.3 (App CLI commands).
- **Do not** implement AppService here; it lives in 3.1. Only the MCP wrapper.
- **Do not** expose raw Keycloak ClientRepresentation; use App domain type in schemas and output.

### Testing Requirements
- Mock AppService (e.g. jest.fn() or vi.fn() per project test runner). For each tool: assert it’s registered (or invoke and assert correct method called with correct args). Assert error path returns object with isError and content.
- No live Keycloak or MCP transport required; unit tests only.

### Story Completion Status
- **Status:** ready-for-dev  
- **Completion note:** Ultimate context engine analysis completed. Depends on 3.1 (AppService). Mirrors Epic 2 User MCP tools pattern exactly.

---

## Dev Agent Record

### Agent Model Used

{{agent_model_name_version}}

### Debug Log References

### Completion Notes List

### File List
