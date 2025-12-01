# Story 2.3: User CLI Commands

Status: done

## Story

As a **human admin**,  
I want **CLI commands for all user operations**,  
so that **I can test and debug user management**.

## Acceptance Criteria

1. **CLI command surface**
   - Given CLI is installed  
     When I run `kc users --help`  
     Then I see available subcommands: list, get, create, update, delete, reset-password, credentials

2. **List users command**
   - `kc users list [--search <term>] [--max <n>] [--json]`
   - Lists users in table format (default) or JSON
   - Table shows: id, username, email, enabled

3. **Get user command**
   - `kc users get <id> [--json]`
   - Shows full user details

4. **Create user command**
   - `kc users create --username <u> [--email <e>] [--firstName <f>] [--lastName <l>] [--json]`
   - Creates user, outputs created user

5. **Update user command**
   - `kc users update <id> [--username <u>] [--email <e>] [--enabled <bool>] [--json]`
   - Updates user attributes

6. **Delete user command**
   - `kc users delete <id> [--force]`
   - Deletes user, asks confirmation unless --force

7. **Reset password command**
   - `kc users reset-password <id> [--temporary]`
   - Prompts for new password (no echo)
   - Sets password

8. **Credentials command**
   - `kc users credentials <id> [--json]`
   - Lists user's credentials (passkeys, OTP, etc.)
   - `kc users credentials <id> --delete <credId> [--force]`
   - Removes credential with confirmation

## Tasks / Subtasks

- [x] **T1 – Implement CLI user commands**
  - [x] Create `src/cli/commands/users/index.ts` as the users subcommand with nested commands.
  - [x] Implement `list.ts`: call `UserService.list/search`, output table or JSON.
  - [x] Implement `get.ts`: call `UserService.get`, output full user details.
  - [x] Implement `create.ts`: call `UserService.create`, output created user.
  - [x] Implement `update.ts`: call `UserService.update`, output updated user.
  - [x] Implement `delete.ts`: call `UserService.delete`, with confirmation prompt.
  - [x] Implement `reset-password.ts`: prompt for password, call `UserService.resetPassword`.
  - [x] Implement `credentials.ts`: list credentials, with --delete option.

- [x] **T2 – Create CLI utilities and wire up main entry**
  - [x] Create `src/cli/utils/output.ts` for table/JSON formatting helpers.
  - [x] Update `src/cli/index.ts` to register the users subcommand and validate connection on startup.
  - [x] Ensure CLI outputs clean, human-readable errors (not raw stack traces).

- [x] **T3 – Tests**
  - [x] Add Vitest tests for CLI commands verifying argument parsing and output formatting.
  - [x] Test table output includes expected columns.
  - [x] Test JSON output is valid JSON matching domain types.

## Dev Notes

- **Architecture alignment**
  - This story implements the CLI interface for user operations as defined in `docs/architecture.md` (CLI Command Pattern section).
  - Commands delegate to `UserService` from Story 2.1 — no business logic in commands, just argument parsing and output formatting.
  - Uses citty for CLI framework per architecture decision ADR-004.

- **Source tree components to touch**
  - `src/cli/commands/users/` – implement all user CLI commands.
  - `src/cli/utils/output.ts` – table and JSON formatters.
  - `src/cli/index.ts` – wire up users subcommand.

- **Testing standards summary**
  - Mock `UserService` to test command logic in isolation.
  - Verify citty parses arguments correctly.
  - Verify output formatters produce expected table/JSON.

### Project Structure Notes

- Follow the **CLI command pattern** from `docs/architecture.md`: commands in `src/cli/commands/users/`, registered via citty's `subCommands`.
- Command names use kebab-case per CLI conventions (e.g., `reset-password`, not `resetPassword`).
- Use `--json` flag for scripting/piping output.

### Learnings from Previous Story

**From Story 2.2 – User MCP Tools** (`docs/sprint-artifacts/2-2-user-mcp-tools.md`):

- **MCP Tools Created**: 8 MCP tools in `src/mcp/tools/users.ts` demonstrate the pattern of thin wrappers over UserService.
- **Error Formatting**: `formatError()` function shows how to present IdentiKeyError with context — reuse pattern for CLI.
- **Registration Pattern**: `registerUserTools()` shows how to wire up handlers — CLI will use citty's `subCommands` instead.
- **Zod Schemas**: Input schemas defined for MCP can inform CLI argument validation (same fields, different mechanism).

These imply:

- CLI commands should follow the same thin-wrapper pattern as MCP tools.
- Reuse error formatting concepts but adapt for terminal output.
- Use same field names for consistency across interfaces.

[Source: docs/sprint-artifacts/2-2-user-mcp-tools.md#Dev-Agent-Record]

### References

- [Source: `docs/epics.md` – Epic 2 / Story 2.3: User CLI Commands](../epics.md)
- [Source: `docs/architecture.md` – CLI Command Pattern](../architecture.md)
- [Source: `docs/sprint-artifacts/2-1-userservice-core-operations.md` – UserService implementation](./2-1-userservice-core-operations.md)
- [Source: `docs/sprint-artifacts/2-2-user-mcp-tools.md` – MCP tools implementation](./2-2-user-mcp-tools.md)

## Dev Agent Record

### Context Reference

- docs/sprint-artifacts/2-3-user-cli-commands.context.xml

### Agent Model Used

keycloak-commander – SM create-story workflow (YOLO, non-interactive)

### Debug Log References

- 2025-12-01 – Drafted Story 2.3 from epics.md and previous story learnings.
- 2025-12-01 – Implemented all CLI commands, output utilities, and tests.

### Completion Notes List

- Drafted Story 2.3 to define CLI commands for user operations, building on UserService from Story 2.1.
- Mapped all user operations to CLI commands with argument schemas.
- Identified dependencies on UserService, citty framework, and output utilities.
- Implemented 7 CLI commands (list, get, create, update, delete, reset-password, credentials) as thin wrappers over UserService.
- Created output utilities for table/JSON formatting and error display.
- Added 27 Vitest tests covering argument parsing, output formatting, and error handling.

### File List

- docs/sprint-artifacts/2-3-user-cli-commands.md
- src/cli/index.ts
- src/cli/utils/output.ts
- src/cli/commands/users/index.ts
- src/cli/commands/users/list.ts
- src/cli/commands/users/get.ts
- src/cli/commands/users/create.ts
- src/cli/commands/users/update.ts
- src/cli/commands/users/delete.ts
- src/cli/commands/users/reset-password.ts
- src/cli/commands/users/credentials.ts
- src/cli/commands/users/users.spec.ts

## Change Log

- 2025-12-01 – Initial draft created via SM `*create-story` workflow.
