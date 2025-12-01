# Story 5.1: AuthFlowService Core Operations

Status: ready-for-dev

## Story

As an **admin**,  
I want **a service that wraps Keycloak authentication flow operations**,  
So that **MCP and CLI can share the same logic for debugging login flows**.

## Acceptance Criteria

1. **List flows**
   - Given an authenticated Keycloak client  
     When I call `AuthFlowService.list()`  
     Then I receive all authentication flows with: id, alias, description, providerId, topLevel, builtIn

2. **Get flow details**
   - Given a flow alias "browser"  
     When I call `AuthFlowService.get("browser")`  
     Then I receive the flow's full configuration
   - Given an invalid alias  
     Then I receive `AUTH_FLOW_NOT_FOUND` error

3. **List executions**
   - Given flow alias "browser"  
     When I call `AuthFlowService.listExecutions("browser")`  
     Then I receive all executions with: id, displayName, requirement, configurable, providerId, level, index, authenticationFlow
   - And executions are ordered by their hierarchy (level + index)

4. **Copy flow**
   - Given built-in flow "browser"  
     When I call `AuthFlowService.copy("browser", "browser-custom")`  
     Then a new flow "browser-custom" is created with same executions
   - And the new flow has `builtIn: false`

5. **Error wrapping**
   - All Keycloak API errors are wrapped in `IdentiKeyError` with appropriate codes

## Tasks / Subtasks

- [ ] **T1 – Define types and mappers**
  - [ ] Add `LoginFlow`, `FlowExecution`, `FlowBindingType` to `src/lib/keycloak/types.ts`
  - [ ] Create `src/lib/keycloak/mappers/auth-flows.ts` with `mapKeycloakFlow`, `mapKeycloakExecution`

- [ ] **T2 – Implement AuthFlowService**
  - [ ] Create `src/lib/keycloak/services/auth-flows.ts`
  - [ ] Implement `list()` — list all flows
  - [ ] Implement `get(flowAlias)` — get single flow
  - [ ] Implement `listExecutions(flowAlias)` — list flow steps with hierarchy
  - [ ] Implement `copy(sourceAlias, newAlias)` — copy flow

- [ ] **T3 – Export service**
  - [ ] Add `getAuthFlowService()` factory to `src/lib/keycloak/services/index.ts`

- [ ] **T4 – Tests**
  - [ ] Add Vitest tests for AuthFlowService methods
  - [ ] Mock `@keycloak/keycloak-admin-client` authenticationManagement
  - [ ] Test error handling for not-found cases

## Dev Notes

- **Keycloak API**: Uses `client.authenticationManagement` resource
  - `getFlows()` — list flows
  - `getExecutions({ flow })` — list executions for flow
  - `copyFlow({ flow }, { newName })` — copy flow

- **Execution hierarchy**: Keycloak returns flat list with `level` and `index` fields. These determine nesting depth and position.

- **Built-in flows**: Cannot be modified directly. Must copy first.

- **FR coverage**: This story covers FR34 (list), FR35 (get details), FR36 (list executions), FR40 (copy)

### Project Structure Notes

- Service follows pattern from `UserService` — thin wrapper, IdentiKey types, error wrapping
- Mappers handle Keycloak → IdentiKey type conversion

### Learnings from Epic 2

- Service constructor takes authenticated `KcAdminClient`
- Factory function (`getAuthFlowService()`) handles client instantiation
- Error wrapping uses `IdentiKeyError` with specific codes
- Mappers handle undefined fields gracefully

### References

- [Tech Spec: Epic 5](./tech-spec-epic-5.md)
- [Source: `docs/epics.md` – Story 5.1](../epics.md)
- [Source: `docs/architecture.md` – Service patterns](../architecture.md)

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/tech-spec-epic-5.md

### Agent Model Used

keycloak-commander – SM create-story workflow

### Debug Log References

- 2025-12-01 – Drafted Story 5.1 from Epic 5 tech spec

### Completion Notes List

- Drafted Story 5.1 to define AuthFlowService core operations
- Scoped to list/get/executions/copy (read operations + copy)
- Execution modification deferred to Story 5.4
- Default binding deferred to Story 5.5

### File List

- docs/sprint-artifacts/5-1-authflowservice-core-operations.md

## Change Log

- 2025-12-01 – Initial draft created via SM `create-story` workflow
