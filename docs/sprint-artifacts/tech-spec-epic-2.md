# Epic Technical Specification: User Administration

Date: 2025-12-01
Author: Master Dorje
Epic ID: epic-2
Status: Draft

---

## Overview

Epic 2 implements **comprehensive user administration** for IdentiKey's admin interface. This epic delivers full CRUD operations for user management, credential handling, and search/pagination capabilities — exposed through both MCP tools (for AI agents) and CLI commands (for human testing). The implementation abstracts Keycloak's "Realm Users" into IdentiKey's cleaner "Users" terminology while maintaining full feature parity with Keycloak Admin API user operations.

## Objectives and Scope

**In Scope:**

- Complete UserService wrapping all Keycloak user operations (FR5-FR13)
- User CRUD: list, search, get, create, update, delete
- Password management: reset password with temporary/permanent options
- Credential management: list credentials (WebAuthn passkeys, OTP devices), delete specific credentials
- Search by username, email, firstName, lastName with pagination support
- MCP tools exposing all operations with structured schemas for AI reasoning
- CLI commands mirroring MCP operations with JSON and table output formats
- IdentiKey domain type mappings (User, CreateUserInput, UpdateUserInput)

**Out of Scope:**

- Guild (group) membership operations (covered in Epic 4)
- Role assignment operations (covered in Epic 4)
- User federation configuration
- Account linking or identity provider associations
- User attribute customization beyond standard fields

## System Architecture Alignment

**Service Layer:** `src/lib/keycloak/services/users.ts` implements UserService as primary interface to Keycloak Admin API user operations, following the service-first pattern defined in architecture.md.

**Type Abstraction:** User domain types (`User`, `CreateUserInput`, `UpdateUserInput`) abstract Keycloak's `UserRepresentation`, mapping terminology per ADR-002. Mapper functions in `src/lib/keycloak/mappers/users.ts` handle Keycloak ↔ IdentiKey transformations.

**Error Handling:** All operations wrap Keycloak exceptions in `IdentiKeyError` with typed error codes (`USER_NOT_FOUND`, `INVALID_INPUT`, etc.), leveraging foundation from Story 1.4.

**Interface Consistency:** MCP tools (`src/mcp/tools/users.ts`) and CLI commands (`src/cli/commands/users/`) consume UserService identically, ensuring behavioral consistency across interfaces per architecture's service-first mandate.

## Detailed Design

### Services and Modules

| Module/Service        | Responsibility                                   | Inputs                       | Outputs                  | Owner/Location                       |
| --------------------- | ------------------------------------------------ | ---------------------------- | ------------------------ | ------------------------------------ |
| **UserService**       | Core user operations wrapping Keycloak Admin API | KcAdminClient instance       | User domain types        | `src/lib/keycloak/services/users.ts` |
| **UserMapper**        | Keycloak ↔ IdentiKey type transformations        | `UserRepresentation`, `User` | Mapped types             | `src/lib/keycloak/mappers/users.ts`  |
| **MCP User Tools**    | Expose UserService via MCP protocol              | Zod-validated tool inputs    | Structured MCP responses | `src/mcp/tools/users.ts`             |
| **CLI User Commands** | Expose UserService via CLI                       | Command args (citty)         | Formatted table/JSON     | `src/cli/commands/users/`            |

**Service Method Summary:**

```typescript
class UserService {
  list(options?: ListOptions): Promise<User[]>
  search(query: string, options?: ListOptions): Promise<User[]>
  get(id: string): Promise<User>
  create(data: CreateUserInput): Promise<User>
  update(id: string, data: UpdateUserInput): Promise<User>
  delete(id: string): Promise<void>
  resetPassword(id: string, password: string, temporary?: boolean): Promise<void>
  getCredentials(id: string): Promise<Credential[]>
  deleteCredential(id: string, credentialId: string): Promise<void>
}
```

### Data Models and Contracts

**User (IdentiKey domain type):**

```typescript
interface User {
  id: string;                    // UUID from Keycloak
  username: string;              // Unique username
  email?: string;                // Optional email
  firstName?: string;            // Optional first name
  lastName?: string;             // Optional last name
  enabled: boolean;              // Account enabled status
  emailVerified?: boolean;       // Email verification status
  createdTimestamp?: number;     // Unix timestamp
  guilds?: string[];             // Group IDs (populated on-demand)
}
```

**CreateUserInput:**

```typescript
interface CreateUserInput {
  username: string;              // Required, must be unique
  email?: string;
  firstName?: string;
  lastName?: string;
  enabled?: boolean;             // Defaults to true
}
```

**UpdateUserInput (all fields optional):**

```typescript
interface UpdateUserInput {
  email?: string;
  firstName?: string;
  lastName?: string;
  enabled?: boolean;
  emailVerified?: boolean;
}
```

**Credential:**

```typescript
interface Credential {
  id: string;                    // Credential UUID
  type: string;                  // 'password' | 'otp' | 'webauthn' | etc.
  userLabel?: string;            // User-provided label
  createdDate?: number;          // Unix timestamp
  credentialData?: unknown;      // Type-specific data
}
```

**ListOptions:**

```typescript
interface ListOptions {
  search?: string;               // Search query (username/email/name)
  max?: number;                  // Max results (default 100)
  offset?: number;               // Pagination offset (default 0)
}
```

**Mapping Notes:**

- Keycloak `UserRepresentation.id` → `User.id`
- Keycloak `groups` → `guilds` (array of group paths)
- Username is immutable after creation (Keycloak constraint)

### APIs and Interfaces

**MCP Tools (8 tools):**

| Tool Name                | Input Schema                                                                                     | Output Schema                   | Maps to Service Method           |
| ------------------------ | ------------------------------------------------------------------------------------------------ | ------------------------------- | -------------------------------- |
| `list_users`             | `{ search?: string, max?: number, offset?: number }`                                             | `{ users: User[] }`             | `UserService.list()`             |
| `get_user`               | `{ id: string }`                                                                                 | `{ user: User }`                | `UserService.get()`              |
| `create_user`            | `{ username: string, email?: string, firstName?: string, lastName?: string, enabled?: boolean }` | `{ user: User }`                | `UserService.create()`           |
| `update_user`            | `{ id: string, email?: string, firstName?: string, lastName?: string, enabled?: boolean }`       | `{ user: User }`                | `UserService.update()`           |
| `delete_user`            | `{ id: string }`                                                                                 | `{ success: boolean }`          | `UserService.delete()`           |
| `reset_user_password`    | `{ id: string, password: string, temporary?: boolean }`                                          | `{ success: boolean }`          | `UserService.resetPassword()`    |
| `get_user_credentials`   | `{ id: string }`                                                                                 | `{ credentials: Credential[] }` | `UserService.getCredentials()`   |
| `delete_user_credential` | `{ id: string, credentialId: string }`                                                           | `{ success: boolean }`          | `UserService.deleteCredential()` |

**CLI Commands:**

```bash
kc users list [--search <query>] [--max <n>] [--offset <n>] [--json]
kc users get <id> [--json]
kc users create --username <u> [--email <e>] [--first-name <f>] [--last-name <l>] [--enabled] [--json]
kc users update <id> [--email <e>] [--first-name <f>] [--last-name <l>] [--enabled <bool>] [--json]
kc users delete <id> [--force]
kc users reset-password <id> [--temporary]
kc users credentials <id> [--json]
kc users delete-credential <id> <credentialId> [--force]
```

**Error Responses:**

All operations return `IdentiKeyError` with codes:

- `USER_NOT_FOUND` - User ID doesn't exist
- `INVALID_INPUT` - Validation failed (e.g., duplicate username)
- `UNAUTHORIZED` - Keycloak auth failed
- `CONNECTION_FAILED` - Keycloak unreachable

### Workflows and Sequencing

**User Creation Flow:**

1. CLI/MCP receives create request with username + optional fields
2. Zod validates input schema
3. UserService.create() called
4. Keycloak Admin API: `POST /admin/realms/identikey/users`
5. Keycloak returns 201 + Location header with new user ID
6. UserService.get(newId) fetches complete user object
7. Mapper transforms Keycloak → IdentiKey User type
8. Response returned to caller

**User Search Flow:**

1. CLI/MCP calls list_users with search query
2. UserService delegates to Keycloak: `GET /users?search=query&max=100&first=0`
3. Keycloak returns matching users (searches username, email, firstName, lastName)
4. Mapper batch-transforms results
5. Filtered/formatted response returned

**Credential Management Flow:**

1. User reports "I can't log in with my passkey"
2. Admin (via AI agent): "Get credentials for user X"
3. MCP tool `get_user_credentials` → UserService.getCredentials()
4. Keycloak: `GET /users/{id}/credentials`
5. Returns list of credentials with types and labels
6. Admin identifies problematic passkey
7. MCP tool `delete_user_credential` removes it
8. User re-registers passkey

**Session Context:**

UserService maintains no state between calls. Each method:

1. Uses injected authenticated KcAdminClient
2. Makes Keycloak API call(s)
3. Transforms response via mapper
4. Returns or throws IdentiKeyError

## Non-Functional Requirements

### Performance

**Target Latency:**

- List operations: < 500ms for 100 users
- Get single user: < 200ms
- Create/update/delete: < 300ms
- Credential operations: < 400ms

**Pagination Requirements:**

- Default page size: 100 users (aligned with PRD pagination defaults)
- Max page size: 1000 users (Keycloak limit)
- Large realm support: Must handle 10,000+ users via pagination

**Keycloak API Efficiency:**

- UserService makes exactly 1 API call per operation (no N+1 queries)
- Exception: create() makes 2 calls (create + get for full object)

**Bottleneck:** Keycloak Admin API response time is the limiting factor. Architecture enables caching layer if needed in future.

### Security

**NFR1 - Credential Protection:**

- Passwords never logged, never returned in API responses
- CLI password prompts use no-echo terminal input
- MCP password inputs marked as sensitive in schema
- Pino logger configured to redact `password`, `secret`, `credentials` fields

**NFR2 - MCP Transport:**

- MCP server uses stdio only (no network exposure) per architecture
- Tool execution limited to local Cursor process

**NFR3 - Keycloak Communication:**

- All Keycloak API calls over HTTPS (enforced by config validation)
- Admin credentials stored in environment variables only
- Client secret never exposed in error messages

**NFR4 - Credential Management:**

- `get_user_credentials` returns credential metadata only (no secrets)
- Credential deletion requires explicit ID (no bulk operations)

**Audit Trail:**

- All user operations logged via Keycloak admin events (Epic 6)
- Pino logs include operation type, user ID, outcome (success/error)

### Reliability/Availability

**Idempotency:**

- Create: Fails with `INVALID_INPUT` if username exists (Keycloak constraint)
- Update: Idempotent — repeated updates with same data succeed
- Delete: Idempotent — deleting non-existent user throws `USER_NOT_FOUND` but is safe to retry

**Error Recovery:**

- Network failures: Keycloak client auto-retries with exponential backoff
- Token expiry: Client auto-refreshes tokens transparently
- Connection validation: validateConnection() called at startup per Story 1.5

**Graceful Degradation:**

- If Keycloak unreachable, clear error messages guide admin to check connection
- MCP errors include actionable suggestions (FR51)
- CLI errors use exit codes: 0 (success), 1 (error), 2 (not found)

**Data Consistency:**

- UserService operations are atomic at Keycloak API level
- No local state — each operation reflects current Keycloak state
- Race conditions (concurrent updates) handled by Keycloak's optimistic locking

### Observability

**Structured Logging (Pino):**

```typescript
logger.info({ userId, operation: 'get_user' }, 'Fetching user details');
logger.error({ userId, err, operation: 'delete_user' }, 'Failed to delete user');
```

**Log Levels:**

- `info`: Successful operations, high-level flow
- `warn`: Deprecated features, rate limit warnings
- `error`: Failed operations with stack traces
- `debug`: Keycloak API request/response details (dev only)

**Metrics (Future):**

- Operation counts by type (list, create, update, etc.)
- Error rates by error code
- P95/P99 latency per operation

**Correlation:**

- Each operation logged with `userId` for traceability
- MCP tool calls include `toolName` in logs
- CLI commands include `command` in logs

**Debugging Support:**

- Error responses include Keycloak error details when available
- MCP responses include full error context for AI reasoning (FR51)
- CLI verbose mode (future): `--verbose` flag shows full API responses

## Dependencies and Integrations

**Core Dependencies:**

| Package                           | Version | Purpose                            | Epic 2 Usage                                |
| --------------------------------- | ------- | ---------------------------------- | ------------------------------------------- |
| `@keycloak/keycloak-admin-client` | ^25.0.0 | Official Keycloak Admin API client | All UserService operations wrap this client |
| `@modelcontextprotocol/sdk`       | ^1.0.0  | MCP protocol implementation        | MCP server + tool registration              |
| `citty`                           | ^0.1.6  | CLI framework                      | CLI command structure and argument parsing  |
| `zod`                             | ^3.24.0 | Schema validation                  | MCP input/output schemas, config validation |
| `pino`                            | ^9.5.0  | Structured logging                 | Operation logging, error tracking           |

**Integration Points:**

**1. Keycloak Admin API (External Service):**

- **Endpoint:** `${KEYCLOAK_URL}/admin/realms/identikey/users`
- **Authentication:** Password grant via `@keycloak/keycloak-admin-client`
- **Operations Used:**
  - `users.find({ search, max, first })` - List/search users
  - `users.findOne({ id })` - Get user by ID
  - `users.create(...)` - Create new user
  - `users.update({ id }, data)` - Update user
  - `users.del({ id })` - Delete user
  - `users.resetPassword({ id }, { value, temporary })` - Password reset
  - `users.getCredentials({ id })` - List credentials
  - `users.deleteCredential({ id, credentialId })` - Remove credential

**2. Foundation Services (Internal):**

- **Keycloak Client Wrapper** (`src/lib/keycloak/client.ts`) - Provides authenticated client instance
- **Config Module** (`src/lib/keycloak/config.ts`) - Environment-based configuration
- **Error Types** (`src/lib/keycloak/errors.ts`) - IdentiKeyError wrapping
- **Logger** (`src/lib/keycloak/logger.ts`) - Pino instance for structured logging

**3. MCP Server (Internal):**

- UserService → MCP tools registered in `src/mcp/tools/users.ts`
- MCP server (`src/mcp/index.ts`) coordinates tool execution
- stdio transport to Cursor

**4. CLI Framework (Internal):**

- UserService → CLI commands in `src/cli/commands/users/`
- CLI main (`src/cli/index.ts`) via citty's `runMain()`
- Output utilities (`src/cli/utils/output.ts`) for table/JSON formatting

**Version Constraints:**

- Keycloak Server: Compatible with Keycloak 22.x - 25.x (IdentiKey's deployed version)
- Node.js: ≥20.0.0 (required by @keycloak/keycloak-admin-client)
- TypeScript: ^5.9.3 (project-wide)

**No External Network Dependencies** beyond Keycloak — all operations are direct Keycloak API calls.

## Acceptance Criteria (Authoritative)

**AC1: UserService Core Operations (Story 2.1)**

- GIVEN an authenticated Keycloak client instance
- WHEN UserService is instantiated
- THEN all methods (list, search, get, create, update, delete, resetPassword, getCredentials, deleteCredential) are available and return IdentiKey domain types

**AC2: User Listing with Pagination (FR5, Story 2.1, 2.5)**

- GIVEN users exist in Keycloak realm
- WHEN calling `list({ max: 50, offset: 100 })`
- THEN exactly 50 users are returned starting from offset 100
- AND results are mapped to IdentiKey `User` type

**AC3: User Search (FR6, Story 2.4)**

- GIVEN users with various attributes
- WHEN calling `search("john", { max: 100 })`
- THEN users matching "john" in username, email, firstName, or lastName are returned
- AND search is case-insensitive and supports partial matches

**AC4: User Creation (FR8, Story 2.1)**

- GIVEN valid `CreateUserInput` with username
- WHEN calling `create({ username: "testuser", email: "test@example.com" })`
- THEN user is created in Keycloak
- AND created user object is returned with generated ID
- AND enabled defaults to true if not specified

**AC5: User Update (FR9, Story 2.1)**

- GIVEN an existing user ID
- WHEN calling `update(id, { email: "newemail@example.com", enabled: false })`
- THEN user's email and enabled status are updated in Keycloak
- AND updated user object is returned

**AC6: User Deletion (FR10, Story 2.1)**

- GIVEN an existing user ID
- WHEN calling `delete(id)`
- THEN user is permanently deleted from Keycloak
- AND operation is idempotent (deleting non-existent user throws USER_NOT_FOUND)

**AC7: Password Reset (FR11, Story 2.1)**

- GIVEN an existing user ID and new password
- WHEN calling `resetPassword(id, "newpassword123", temporary: true)`
- THEN user's password is set to "newpassword123"
- AND user must change password on next login (temporary flag)

**AC8: Credential Management (FR12, FR13, Story 2.6)**

- GIVEN a user with WebAuthn credentials
- WHEN calling `getCredentials(id)`
- THEN list of credentials is returned with id, type, label, createdDate
- AND when calling `deleteCredential(id, credentialId)`
- THEN specified credential is removed

**AC9: MCP Tool Exposure (FR49, FR50, FR51, Story 2.2)**

- GIVEN MCP server is running
- WHEN tools are listed
- THEN 8 user tools are registered (list_users, get_user, create_user, update_user, delete_user, reset_user_password, get_user_credentials, delete_user_credential)
- AND each tool has Zod input/output schemas
- AND responses include structuredContent for AI reasoning
- AND errors include actionable messages

**AC10: CLI Command Exposure (FR52-FR55, Story 2.3)**

- GIVEN CLI is installed
- WHEN running `kc users --help`
- THEN available subcommands are listed with descriptions
- AND each command supports `--json` flag for JSON output
- AND each command supports table output (default)
- AND help text explains all flags and arguments

**AC11: Error Handling**

- GIVEN a non-existent user ID
- WHEN calling any user operation
- THEN `IdentiKeyError` with code `USER_NOT_FOUND` is thrown
- AND error message includes the user ID attempted

**AC12: Type Safety**

- GIVEN UserService methods are called
- WHEN using TypeScript
- THEN all inputs and outputs have full type definitions
- AND Keycloak types never leak to callers (abstraction maintained)

## Traceability Mapping

| AC   | Spec Section         | Component/API                                        | Test Approach                                                 |
| ---- | -------------------- | ---------------------------------------------------- | ------------------------------------------------------------- |
| AC1  | Services and Modules | `UserService` class                                  | Unit test: instantiate service, verify methods exist          |
| AC2  | Data Models, APIs    | `UserService.list()`                                 | Unit test: mock Keycloak response, verify pagination params   |
| AC3  | APIs, Workflows      | `UserService.search()`                               | Unit test: verify search query passed to Keycloak correctly   |
| AC4  | APIs, Workflows      | `UserService.create()`                               | Unit test + E2E: create user, verify in Keycloak              |
| AC5  | APIs                 | `UserService.update()`                               | Unit test + E2E: update user, verify changes persisted        |
| AC6  | APIs                 | `UserService.delete()`                               | Unit test + E2E: delete user, verify removal                  |
| AC7  | APIs                 | `UserService.resetPassword()`                        | Unit test: verify password credential set with temporary flag |
| AC8  | APIs, Data Models    | `UserService.getCredentials()`, `deleteCredential()` | Unit test: mock credential list, verify deletion              |
| AC9  | APIs, MCP Tools      | `src/mcp/tools/users.ts`                             | Integration test: call tools via MCP, verify responses        |
| AC10 | CLI Commands         | `src/cli/commands/users/*`                           | E2E test: execute CLI commands, verify output format          |
| AC11 | Error Handling       | `IdentiKeyError`                                     | Unit test: trigger error conditions, verify error codes       |
| AC12 | Type Safety          | All UserService types                                | TypeScript compilation + unit tests                           |

**Coverage:**

- FR5-FR13 → AC1-AC8, AC11-AC12
- FR49-FR51 → AC9
- FR52-FR55 → AC10

## Risks, Assumptions, Open Questions

**RISK-1: Keycloak API Version Compatibility**

- **Description:** Keycloak Admin API can have breaking changes between versions
- **Impact:** High — UserService operations could fail after Keycloak upgrade
- **Mitigation:** Pin @keycloak/keycloak-admin-client version, document tested Keycloak versions, add integration tests
- **Status:** Accepted — will validate against IdentiKey's deployed version (TBD)

**RISK-2: Credential Type Handling**

- **Description:** Keycloak supports many credential types (password, otp, webauthn, x509, kerberos, etc.) with varying structures
- **Impact:** Medium — Credential display/deletion might not handle all types gracefully
- **Mitigation:** Focus on common types (password, otp, webauthn) in MVP; add type-specific handling incrementally
- **Status:** Mitigated — getCredentials returns generic structure, apps handle specifics

**RISK-3: Username Immutability**

- **Description:** Keycloak doesn't allow username changes after creation
- **Impact:** Low — Could confuse admins expecting to rename users
- **Mitigation:** Document constraint clearly, consider workaround (delete + recreate) for rare cases
- **Status:** Accepted — PRD doesn't require username updates

**RISK-4: Large User Searches**

- **Description:** Searching 10,000+ users could timeout or return incomplete results
- **Impact:** Medium — Degraded UX for large realms
- **Mitigation:** Implement pagination correctly, consider search debouncing in CLI/Web UI
- **Status:** Mitigated via pagination (AC2)

**ASSUMPTION-1: Single Realm Operation**

- **Assumption:** All operations target `identikey` realm only (master realm excluded)
- **Validation:** Enforced by config (Story 1.2), architecture decision
- **Impact if Wrong:** Low — easy to extend for multi-realm in future

**ASSUMPTION-2: Email Uniqueness Not Enforced**

- **Assumption:** Keycloak realm allows duplicate emails (common config)
- **Validation:** Check IdentiKey's realm settings
- **Impact if Wrong:** Medium — user creation might fail unexpectedly

**ASSUMPTION-3: Events Enabled**

- **Assumption:** Keycloak realm has login/admin events enabled for audit
- **Validation:** Verify in realm settings before Epic 6
- **Impact if Wrong:** High — Event queries (Epic 6) won't work

**QUESTION-1: Bulk Operations?**

- **Question:** Should UserService support bulk create/update/delete?
- **Decision Needed:** Not in MVP scope per PRD; consider for growth features
- **Blocker:** No

**QUESTION-2: User Attribute Customization?**

- **Question:** IdentiKey might need custom user attributes beyond standard fields
- **Decision Needed:** Epic 2 implements standard fields only; extend in future story if needed
- **Blocker:** No

**QUESTION-3: Group/Guild Membership in User Response?**

- **Question:** Should `User` type include guild memberships by default?
- **Decision:** Populate on-demand (optional field) to avoid extra API calls — guild operations in Epic 4
- **Blocker:** No

## Test Strategy Summary

**Test Levels:**

**1. Unit Tests (Vitest):**

- **Coverage Target:** 80%+ for UserService, mappers
- **Focus Areas:**
  - UserService method logic (mocked Keycloak client)
  - Mapper transformations (Keycloak ↔ IdentiKey types)
  - Error handling (USER_NOT_FOUND, INVALID_INPUT, etc.)
  - Input validation (Zod schemas)
- **Location:** Co-located with source (`users.spec.ts`, `users.ts`)

**2. Integration Tests (Vitest + MCP SDK):**

- **Focus Areas:**
  - MCP tool registration and execution
  - Tool input validation via Zod
  - Structured responses for AI reasoning
- **Location:** `src/mcp/tools/users.spec.ts`

**3. E2E Tests (Playwright + Real Keycloak):**

- **Focus Areas:**
  - Full user lifecycle: create → get → update → delete
  - CLI command execution with real output
  - Credential management flow
  - Pagination behavior with large datasets
- **Prerequisites:** Test Keycloak instance (consider Testcontainers)
- **Location:** `e2e/users.test.ts`

**4. Manual Testing:**

- **Scenarios:**
  - AI agent conversation: "Create user john@example.com and reset their password"
  - CLI usage: All commands with various flag combinations
  - Error cases: Invalid IDs, duplicate usernames, network failures

**Test Data Strategy:**

- **Unit tests:** Mocked Keycloak responses (fixtures)
- **E2E tests:** Ephemeral test users created/destroyed per test
- **Test realm:** Separate `identikey-test` realm to avoid polluting production

**Edge Cases to Test:**

- Empty search results
- Pagination beyond available users
- Special characters in usernames/emails
- Very long attribute values
- Concurrent updates (race conditions)
- Token expiry during operation

**Acceptance Test Mapping:**

- Each AC (AC1-AC12) has corresponding test case(s)
- Traceability: Test name includes AC number (e.g., `test_AC4_user_creation`)

**CI/CD Integration:**

- Unit tests run on every commit
- E2E tests run on PR merge to main
- Test Keycloak instance spun up via Docker Compose for CI
