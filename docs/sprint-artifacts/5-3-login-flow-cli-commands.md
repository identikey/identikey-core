# Story 5.3: Login Flow CLI Commands

Status: done

## Story

As an **admin**,  
I want **CLI commands for authentication flow operations**,  
So that **I can debug and manage login flows from the command line**.

## Acceptance Criteria

1. **kc auth-flows list**
   - Lists all authentication flows with alias, providerId, topLevel, builtIn
   - Supports `--json` output

2. **kc auth-flows get \<alias\>**
   - Shows full flow details
   - Returns error for unknown alias

3. **kc auth-flows executions \<alias\>**
   - Lists executions with hierarchy indentation based on level
   - Shows displayName, requirement, providerId
   - Supports `--json` output

4. **kc auth-flows copy \<source\> \<new-alias\>**
   - Creates copy of flow
   - Returns confirmation with new flow details

## Tasks / Subtasks

- [x] **T1 – Implement CLI commands**
  - [x] Create `src/cli/commands/auth-flows/list.ts`
  - [x] Create `src/cli/commands/auth-flows/get.ts`
  - [x] Create `src/cli/commands/auth-flows/executions.ts`
  - [x] Create `src/cli/commands/auth-flows/copy.ts`
  - [x] Create `src/cli/commands/auth-flows/index.ts`

- [x] **T2 – Output formatters**
  - [x] Add `printFlowsTable`, `printFlowDetails`, `printExecutionsTable` to output.ts

- [x] **T3 – Wire into CLI**
  - [x] Update `src/cli/index.ts` to register auth-flows command

- [x] **T4 – Tests**
  - [x] Add Vitest tests for CLI commands (18 tests)

## Dev Notes

- Follows pattern from `src/cli/commands/users/`
- Execution display shows hierarchy via indentation (2 spaces per level)

### FR Coverage

- FR34: `kc auth-flows list`
- FR35: `kc auth-flows get`
- FR36: `kc auth-flows executions`
- FR40: `kc auth-flows copy`

## Dev Agent Record

### Agent Model Used

keycloak-commander – dev-story workflow

### Completion Notes List

- 2025-12-01: Implemented 4 CLI commands for login flow operations
- Added output formatters: printFlowsTable, printFlowDetails, printExecutionsTable
- Executions show hierarchy via level-based indentation
- All 18 unit tests passing

### File List

- docs/sprint-artifacts/5-3-login-flow-cli-commands.md
- src/cli/commands/auth-flows/list.ts
- src/cli/commands/auth-flows/get.ts
- src/cli/commands/auth-flows/executions.ts
- src/cli/commands/auth-flows/copy.ts
- src/cli/commands/auth-flows/index.ts
- src/cli/commands/auth-flows/auth-flows.spec.ts (18 tests)
- src/cli/utils/output.ts (updated)
- src/cli/index.ts (updated)

## Change Log

- 2025-12-01 – Initial draft created
