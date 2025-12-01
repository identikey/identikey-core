# Story 2.2: User MCP Tools

Status: done

## Story

As an **AI agent**,  
I want **MCP tools for all user operations**,  
so that **I can help admins manage users conversationally**.

## Acceptance Criteria

1. **MCP tool surface**
   - Given MCP server is running  
     When tools are listed  
     Then the following user tools are available:

     | Tool                     | Maps to                      | Input Schema                                                 |
     | ------------------------ | ---------------------------- | ------------------------------------------------------------ |
     | `list_users`             | UserService.list             | `{ search?: string, max?: number, offset?: number }`         |
     | `get_user`               | UserService.get              | `{ id: string }`                                             |
     | `create_user`            | UserService.create           | `{ username, email?, firstName?, lastName?, enabled? }`      |
     | `update_user`            | UserService.update           | `{ id, username?, email?, firstName?, lastName?, enabled? }` |
     | `delete_user`            | UserService.delete           | `{ id }`                                                     |
     | `reset_user_password`    | UserService.resetPassword    | `{ id, password, temporary? }`                               |
     | `get_user_credentials`   | UserService.getCredentials   | `{ id }`                                                     |
     | `delete_user_credential` | UserService.deleteCredential | `{ id, credentialId }`                                       |

2. **Tool metadata**
   - Each tool has a descriptive `title` and `description` for AI discoverability.

3. **Structured responses (FR50)**
   - Responses include `structuredContent` with typed data for AI reasoning.

4. **Error handling (FR51)**
   - Error responses include actionable messages with context (user ID, operation attempted, error code).

## Tasks / Subtasks

- [x] **T1 – Implement MCP user tools**
  - [x] Create `src/mcp/tools/users.ts` with Zod schemas for input validation.
  - [x] Implement `list_users` tool: call `UserService.list/search`, return users array.
  - [x] Implement `get_user` tool: call `UserService.get`, return single user.
  - [x] Implement `create_user` tool: call `UserService.create`, return created user.
  - [x] Implement `update_user` tool: call `UserService.update`, return updated user.
  - [x] Implement `delete_user` tool: call `UserService.delete`, confirm deletion.
  - [x] Implement `reset_user_password` tool: call `UserService.resetPassword`, confirm reset.
  - [x] Implement `get_user_credentials` tool: call `UserService.getCredentials`, return credentials array.
  - [x] Implement `delete_user_credential` tool: call `UserService.deleteCredential`, confirm deletion.

- [x] **T2 – Register tools and integrate with MCP server**
  - [x] Create `src/mcp/tools/index.ts` to export a `registerUserTools(server, userService)` function.
  - [x] Update `src/mcp/index.ts` to obtain `UserService` via `getUserService()` and register tools on startup.
  - [x] Ensure MCP server validates connection before registering tools.

- [x] **T3 – Tests**
  - [x] Add Vitest tests for MCP user tools verifying input validation and response structure.
  - [x] Verify error responses include IdentiKeyError codes and actionable messages.
  - [x] Test tool registration succeeds with mocked UserService.

## Dev Notes

- **Architecture alignment**
  - This story implements the MCP interface for user operations as defined in `docs/architecture.md` (MCP Tool Pattern section).
  - Tools delegate to `UserService` from Story 2.1 — no business logic in tools, just schema validation and response formatting.
  - Follows MCP SDK patterns: `server.tool()` registration with Zod schemas.

- **Source tree components to touch**
  - `src/mcp/tools/users.ts` – implement all user MCP tools.
  - `src/mcp/tools/index.ts` – export registration function.
  - `src/mcp/index.ts` – wire up UserService and register tools.

- **Testing standards summary**
  - Mock `UserService` to test tool logic in isolation.
  - Verify Zod schemas reject invalid inputs.
  - Verify responses include both `content` (text for display) and `structuredContent` (typed data).

### Project Structure Notes

- Follow the **MCP tool pattern** from `docs/architecture.md`: tools in `src/mcp/tools/`, registered via a `registerXxxTools()` function.
- Tool names use snake_case per MCP conventions (e.g., `list_users`, not `listUsers`).
- Input schemas use Zod with `.describe()` for each field to aid AI understanding.

### Learnings from Previous Story

**From Story 2.1 – UserService Core Operations** (`docs/sprint-artifacts/2-1-userservice-core-operations.md`):

- **New Service Created**: `UserService` available at `src/lib/keycloak/services/users.ts` with full CRUD + credential operations.
- **Factory Available**: Use `getUserService()` from `src/lib/keycloak/services/index.ts` to obtain authenticated instance.
- **Domain Types Available**: `User`, `CreateUserInput`, `UpdateUserInput`, `ListOptions`, `Credential` in `src/lib/keycloak/types.ts`.
- **Error Handling Established**: All errors are `IdentiKeyError` with codes (`USER_NOT_FOUND`, `INVALID_INPUT`, `UNAUTHORIZED`, `CONNECTION_FAILED`).
- **Test Patterns**: 26 unit tests demonstrate mocking patterns for Keycloak client.

These imply:

- MCP tools should call `UserService` methods directly without reimplementing logic.
- Error handling is already done in the service layer; tools just need to format error responses.
- Use existing types for response schemas.

[Source: docs/sprint-artifacts/2-1-userservice-core-operations.md#Dev-Agent-Record]

### References

- [Source: `docs/epics.md` – Epic 2 / Story 2.2: User MCP Tools](../epics.md)
- [Source: `docs/architecture.md` – MCP Tool Pattern](../architecture.md)
- [Source: `docs/sprint-artifacts/2-1-userservice-core-operations.md` – UserService implementation](./2-1-userservice-core-operations.md)

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/2-2-user-mcp-tools.context.xml

### Agent Model Used

keycloak-commander – SM create-story workflow (YOLO, non-interactive)

### Debug Log References

- 2025-12-01 – Drafted Story 2.2 from epics.md and previous story learnings.

### Completion Notes List

- Drafted Story 2.2 to define MCP tools for user operations, building on UserService from Story 2.1.
- Mapped all 8 user tools to UserService methods with input schemas.
- Identified dependencies on UserService, getUserService factory, and domain types.
- ✅ Implemented all 8 MCP tools in `src/mcp/tools/users.ts` with Zod input/output schemas.
- ✅ Created `src/mcp/tools/index.ts` with `registerUserTools()` and `registerAllTools()` helpers.
- ✅ Updated `src/mcp/index.ts` to obtain `UserService` via `getUserService()` and register tools at startup.
- ✅ Added 16 Vitest tests covering tool registration, input handling, structuredContent responses, and error formatting.
- ✅ All 61 tests pass (16 new + 45 existing).

### File List

- docs/sprint-artifacts/2-2-user-mcp-tools.md
- src/mcp/tools/users.ts (new)
- src/mcp/tools/index.ts (new)
- src/mcp/tools/users.spec.ts (new)
- src/mcp/index.ts (modified)

## Change Log

- 2025-12-01 – Initial draft created via SM `*create-story` workflow.
- 2025-12-01 – Implemented all tasks (T1, T2, T3): 8 MCP user tools, registration helpers, and 16 tests. All 61 tests pass.
