# Story 5.2: Login Flow MCP Tools

Status: done

## Story

As an **AI agent**,  
I want **MCP tools for authentication flow operations**,  
So that **I can help admins debug and manage login flows through conversational interfaces**.

## Acceptance Criteria

1. **list_login_flows tool**
   - Given an authenticated MCP connection  
     When I call `list_login_flows`  
     Then I receive all flows with: id, alias, description, providerId, topLevel, builtIn

2. **get_login_flow tool**
   - Given flow alias "browser"  
     When I call `get_login_flow({ flowAlias: "browser" })`  
     Then I receive the flow details
   - Given invalid alias  
     Then I receive structured error with `AUTH_FLOW_NOT_FOUND`

3. **list_flow_executions tool**
   - Given flow alias "browser"  
     When I call `list_flow_executions({ flowAlias: "browser" })`  
     Then I receive executions with hierarchy info (level, index)
   - And executions are sorted by level + index

4. **copy_login_flow tool**
   - Given flow "browser" and new alias "browser-custom"  
     When I call `copy_login_flow({ sourceAlias: "browser", newAlias: "browser-custom" })`  
     Then a new flow is created and returned
   - Given duplicate alias  
     Then I receive structured error with `INVALID_INPUT`

5. **Error handling**
   - All tools return structured MCP errors with actionable context

## Tasks / Subtasks

- [x] **T1 – Implement registerAuthFlowTools**
  - [x] Create `src/mcp/tools/auth-flows.ts`
  - [x] Implement `list_login_flows` tool
  - [x] Implement `get_login_flow` tool
  - [x] Implement `list_flow_executions` tool
  - [x] Implement `copy_login_flow` tool

- [x] **T2 – Wire into MCP server**
  - [x] Update `src/mcp/tools/index.ts` to register auth flow tools
  - [x] Update `src/mcp/index.ts` to inject AuthFlowService

- [x] **T3 – Tests**
  - [x] Add Vitest tests for all 4 MCP tools (11 tests)
  - [x] Test structured output format
  - [x] Test error handling

## Dev Notes

- Follows same pattern as `src/mcp/tools/users.ts`
- Tools delegate to `AuthFlowService` methods
- Output uses structured JSON for AI consumption
- Execution modification tools (add/remove/update requirement) deferred to Story 5.4

### FR Coverage

- FR34: `list_login_flows`
- FR35: `get_login_flow`
- FR36: `list_flow_executions`
- FR40: `copy_login_flow`

### References

- [Tech Spec: Epic 5](./tech-spec-epic-5.md)
- [Story 5.1: AuthFlowService](./5-1-authflowservice-core-operations.md)

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/tech-spec-epic-5.md
- src/mcp/tools/users.ts (pattern reference)

### Agent Model Used

keycloak-commander – dev-story workflow

### Debug Log References

- 2025-12-01 – Drafted Story 5.2 from Epic 5 tech spec

### Completion Notes List

- 2025-12-01: Implemented 4 MCP tools for login flow operations
- Tools delegate to AuthFlowService from Story 5-1
- All 11 unit tests passing
- Wired into MCP server with AuthFlowService injection

### File List

- docs/sprint-artifacts/5-2-login-flow-mcp-tools.md
- src/mcp/tools/auth-flows.ts (registerAuthFlowTools)
- src/mcp/tools/auth-flows.spec.ts (11 tests)
- src/mcp/tools/index.ts (updated)
- src/mcp/index.ts (updated)

## Change Log

- 2025-12-01 – Initial draft created
