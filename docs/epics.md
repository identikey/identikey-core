# keycloak-commander — Epic Breakdown

**Author:** Master Dorje
**Date:** 2025-11-30
**Project Level:** Internal Tool → Product
**Target Scale:** Single developer (now) → Team (future)

---

## Overview

This document breaks down the PRD's 55 functional requirements into implementable epics and stories. Each epic delivers **end-to-end user value** — service layer + MCP tools + CLI commands together.

**Living Document Notice:** This is the initial version based on PRD + Architecture. Will be updated when UX Design is created for Web UI.

### Epic Summary

| Epic | Name                      | FRs Covered | Stories | Value Delivered                                    |
| ---- | ------------------------- | ----------- | ------- | -------------------------------------------------- |
| 1    | Foundation                | FR1-4       | 5       | Project setup, config, Keycloak connection working |
| 2    | User Administration       | FR5-13      | 6       | Admin can manage users via MCP and CLI             |
| 3    | App Management            | FR14-19     | 4       | Admin can manage apps via MCP and CLI              |
| 4    | Guild & Role Management   | FR20-33     | 6       | Admin can organize users and assign roles          |
| 5    | Login Flow Administration | FR34-41     | 5       | Admin can debug and configure auth flows           |
| 6    | Sessions & Events         | FR42-48     | 4       | Admin can debug login issues and audit activity    |

**Total:** 6 Epics, 30 Stories

---

## Functional Requirements Inventory

### Authentication & Connection (FR1-4)

- FR1: System can authenticate to Keycloak Admin API using service account credentials
- FR2: System can authenticate using admin username/password
- FR3: Connection configuration is provided via environment variables
- FR4: System validates connection on startup and reports clear errors if unreachable

### User Management (FR5-13)

- FR5: Admins can list all users with pagination
- FR6: Admins can search users by username, email, first name, or last name
- FR7: Admins can get detailed information for a specific user
- FR8: Admins can create new users with required attributes
- FR9: Admins can update user attributes (name, email, enabled status, etc.)
- FR10: Admins can delete users
- FR11: Admins can reset a user's password
- FR12: Admins can view a user's credentials (passkeys, OTP devices, etc.)
- FR13: Admins can delete specific credentials from a user

### App/Client Management (FR14-19)

- FR14: Admins can list all apps (OIDC clients)
- FR15: Admins can get detailed configuration for a specific app
- FR16: Admins can create new apps with standard OIDC configuration
- FR17: Admins can update app configuration (redirect URIs, scopes, etc.)
- FR18: Admins can retrieve an app's client secret
- FR19: Admins can regenerate an app's client secret

### Guild/Group Management (FR20-27)

- FR20: Admins can list all guilds
- FR21: Admins can get details for a specific guild
- FR22: Admins can create new guilds
- FR23: Admins can update guild attributes
- FR24: Admins can delete guilds
- FR25: Admins can list members of a guild
- FR26: Admins can add users to a guild
- FR27: Admins can remove users from a guild

### Role Management (FR28-33)

- FR28: Admins can list all realm-level roles
- FR29: Admins can list client-specific roles for an app
- FR30: Admins can assign realm roles to users
- FR31: Admins can remove realm roles from users
- FR32: Admins can assign realm roles to guilds
- FR33: Admins can remove realm roles from guilds

### Login Flow Management (FR34-41)

- FR34: Admins can list all login flows
- FR35: Admins can get detailed configuration of a login flow
- FR36: Admins can list executions (steps) within a login flow
- FR37: Admins can add executions to a login flow
- FR38: Admins can remove executions from a login flow
- FR39: Admins can reorder executions within a login flow
- FR40: Admins can copy an existing login flow to create a new one
- FR41: Admins can set a login flow as the default for browser/direct-grant/etc.

### Session Management (FR42-44)

- FR42: Admins can list active sessions for a specific user
- FR43: Admins can force logout a specific user (terminate all sessions)
- FR44: Admins can force logout all users (realm-wide session termination)

### Event & Audit Queries (FR45-48)

- FR45: Admins can query login events (successful and failed authentications)
- FR46: Admins can filter login events by user, time range, event type, and client
- FR47: Admins can query admin events (configuration changes)
- FR48: Admins can filter admin events by time range, operation type, and resource

### MCP Interface (FR49-51)

- FR49: All FR5-FR48 operations are exposed as MCP tools callable by AI agents
- FR50: MCP responses include structured data suitable for AI reasoning
- FR51: MCP error responses include actionable information for debugging

### CLI Interface (FR52-55)

- FR52: All FR5-FR48 operations are exposed as CLI commands
- FR53: CLI supports JSON output format for scripting
- FR54: CLI supports human-readable table output format
- FR55: CLI provides help text for all commands

---

## FR Coverage Map

| Epic                              | FRs Covered                                                   |
| --------------------------------- | ------------------------------------------------------------- |
| Epic 1: Foundation                | FR1, FR2, FR3, FR4                                            |
| Epic 2: User Administration       | FR5, FR6, FR7, FR8, FR9, FR10, FR11, FR12, FR13, FR49*, FR52* |
| Epic 3: App Management            | FR14, FR15, FR16, FR17, FR18, FR19, FR49*, FR52*              |
| Epic 4: Guild & Role Management   | FR20-27, FR28-33, FR49*, FR52*                                |
| Epic 5: Login Flow Administration | FR34, FR35, FR36, FR37, FR38, FR39, FR40, FR41, FR49*, FR52*  |
| Epic 6: Sessions & Events         | FR42, FR43, FR44, FR45, FR46, FR47, FR48, FR49*, FR52*        |

\*FR49-55 (MCP/CLI interface requirements) are implemented incrementally across Epics 2-6 as each domain is built.

**Coverage Validation:** ✅ All 55 FRs mapped to epics.

---

## Epic 1: Foundation

**Goal:** Establish project infrastructure, configuration, and Keycloak connectivity so all subsequent epics have a solid base to build on.

**User Value:** Developer can connect to Keycloak and verify the system works.

**FRs Covered:** FR1, FR2, FR3, FR4

---

### Story 1.1: Project Structure & Dependencies

As a **developer**,
I want **the project scaffolded with required dependencies**,
So that **I can start building the core service layer**.

**Acceptance Criteria:**

**Given** a fresh clone of the repository
**When** I run `bun install`
**Then** all dependencies are installed without errors

**And** the following packages are available:

- `@keycloak/keycloak-admin-client`
- `@modelcontextprotocol/sdk`
- `citty`
- `zod`
- `pino`
- `dotenv`

**And** the project structure matches architecture.md:

- `src/lib/keycloak/` directory exists
- `src/mcp/` directory exists
- `src/cli/` directory exists

**Prerequisites:** None (first story)

**Technical Notes:**

- Add dependencies to package.json
- Create directory structure per architecture.md
- Add `.env.example` with required variables
- Update tsconfig if needed for new paths

---

### Story 1.2: Configuration Loading

As a **developer**,
I want **configuration loaded from environment variables**,
So that **I can connect to different Keycloak instances without code changes**.

**Acceptance Criteria:**

**Given** a `.env` file with `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_USERNAME`, `KEYCLOAK_PASSWORD`
**When** the config module is imported
**Then** configuration is loaded and validated with Zod schema

**And** missing required variables throw clear error with variable name
**And** invalid URL format throws validation error
**And** `KEYCLOAK_REALM` defaults to `identikey` if not provided (master realm is reserved for Keycloak admin only)
**And** `KEYCLOAK_CLIENT_ID` defaults to `admin-cli` if not provided

**Prerequisites:** Story 1.1

**Technical Notes:**

- Create `src/lib/keycloak/config.ts`
- Use Zod for schema validation
- Load dotenv in development
- Export typed config object

---

### Story 1.3: Keycloak Client Wrapper

As a **developer**,
I want **a wrapper around @keycloak/keycloak-admin-client**,
So that **services can get an authenticated client instance**.

**Acceptance Criteria:**

**Given** valid Keycloak credentials in environment
**When** I call `getKeycloakClient()`
**Then** I receive an authenticated `KcAdminClient` instance

**And** the client is authenticated using password grant (FR2)
**And** the client can also authenticate using service account if configured (FR1)
**And** the client is cached (singleton per process)
**And** re-authentication happens automatically on token expiry

**Prerequisites:** Story 1.2

**Technical Notes:**

- Create `src/lib/keycloak/client.ts`
- Use singleton pattern for client instance
- Implement lazy authentication (connect on first use)
- Handle token refresh

---

### Story 1.4: Error Types & Logging Setup

As a **developer**,
I want **standardized error types and structured logging**,
So that **errors are consistent and debuggable across all services**.

**Acceptance Criteria:**

**Given** a Keycloak API error occurs
**When** it's caught in the service layer
**Then** it's wrapped in `IdentiKeyError` with code, message, and cause

**And** pino logger is configured with:

- JSON output in production
- Pretty output in development
- Log level from `LOG_LEVEL` env var (default: `info`)

**And** sensitive data (passwords, secrets) is never logged

**Prerequisites:** Story 1.2

**Technical Notes:**

- Create `src/lib/keycloak/errors.ts` with `IdentiKeyError` class
- Create `src/lib/keycloak/logger.ts` with pino setup
- Define error codes enum per architecture.md
- Configure pino redaction for sensitive fields

---

### Story 1.5: Connection Validation

As a **developer**,
I want **connection validated on startup with clear error messages**,
So that **I know immediately if Keycloak is unreachable** (FR4).

**Acceptance Criteria:**

**Given** Keycloak URL is correct and credentials are valid
**When** connection validation runs
**Then** success message is logged with realm name

**Given** Keycloak URL is unreachable
**When** connection validation runs
**Then** error includes URL and suggests checking network/URL

**Given** credentials are invalid
**When** connection validation runs
**Then** error says "Authentication failed" without exposing password

**Prerequisites:** Story 1.3, Story 1.4

**Technical Notes:**

- Add `validateConnection()` function to client.ts
- Call from CLI startup and MCP server init
- Use Keycloak's serverInfo endpoint to verify connectivity
- Log success/failure with appropriate levels

---

## Epic 2: User Administration

**Goal:** Enable full user management capabilities through both MCP and CLI interfaces.

**User Value:** Admin can list, search, create, update, delete users and manage their credentials — via conversation with AI agent or CLI commands.

**FRs Covered:** FR5, FR6, FR7, FR8, FR9, FR10, FR11, FR12, FR13

---

### Story 2.1: UserService Core Operations

As an **admin**,
I want **a service that wraps Keycloak user operations**,
So that **MCP and CLI can share the same logic**.

**Acceptance Criteria:**

**Given** an authenticated Keycloak client
**When** UserService is instantiated
**Then** the following methods are available:

| Method                                    | FR   | Description                                                    |
| ----------------------------------------- | ---- | -------------------------------------------------------------- |
| `list(options?)`                          | FR5  | List users with pagination (max, offset)                       |
| `search(query, options?)`                 | FR6  | Search by username, email, firstName, lastName                 |
| `get(id)`                                 | FR7  | Get user by ID                                                 |
| `create(data)`                            | FR8  | Create user with username, email, firstName, lastName, enabled |
| `update(id, data)`                        | FR9  | Update user attributes                                         |
| `delete(id)`                              | FR10 | Delete user                                                    |
| `resetPassword(id, password, temporary?)` | FR11 | Set new password                                               |
| `getCredentials(id)`                      | FR12 | List user credentials                                          |
| `deleteCredential(id, credentialId)`      | FR13 | Remove specific credential                                     |

**And** all methods return IdentiKey domain types (not raw Keycloak types)
**And** errors are wrapped in `IdentiKeyError`

**Prerequisites:** Epic 1 complete

**Technical Notes:**

- Create `src/lib/keycloak/services/users.ts`
- Create mapper functions in `src/lib/keycloak/mappers/users.ts`
- Define `User`, `CreateUserInput`, `UpdateUserInput` types
- Implement pagination with sensible defaults (max: 100)

---

### Story 2.2: User MCP Tools

As an **AI agent**,
I want **MCP tools for all user operations**,
So that **I can help admins manage users conversationally**.

**Acceptance Criteria:**

**Given** MCP server is running
**When** tools are listed
**Then** the following user tools are available:

| Tool                     | Maps to                      | Input Schema                                            |
| ------------------------ | ---------------------------- | ------------------------------------------------------- |
| `list_users`             | UserService.list             | `{ search?: string, max?: number }`                     |
| `get_user`               | UserService.get              | `{ id: string }`                                        |
| `create_user`            | UserService.create           | `{ username, email?, firstName?, lastName?, enabled? }` |
| `update_user`            | UserService.update           | `{ id, ...updateFields }`                               |
| `delete_user`            | UserService.delete           | `{ id }`                                                |
| `reset_user_password`    | UserService.resetPassword    | `{ id, password, temporary? }`                          |
| `get_user_credentials`   | UserService.getCredentials   | `{ id }`                                                |
| `delete_user_credential` | UserService.deleteCredential | `{ id, credentialId }`                                  |

**And** each tool has descriptive title and description
**And** responses include `structuredContent` for AI reasoning (FR50)
**And** errors include actionable messages (FR51)

**Prerequisites:** Story 2.1

**Technical Notes:**

- Create `src/mcp/tools/users.ts`
- Use Zod schemas for input/output validation
- Follow pattern from architecture.md
- Register tools in `src/mcp/tools/index.ts`

---

### Story 2.3: User CLI Commands

As a **human admin**,
I want **CLI commands for all user operations**,
So that **I can test and debug user management**.

**Acceptance Criteria:**

**Given** CLI is installed
**When** I run `kc users --help`
**Then** I see available subcommands: list, get, create, update, delete, reset-password, credentials

**And** `kc users list [--search <term>] [--max <n>] [--json]`

- Lists users in table format (default) or JSON
- Table shows: id, username, email, enabled

**And** `kc users get <id> [--json]`

- Shows full user details

**And** `kc users create --username <u> [--email <e>] [--json]`

- Creates user, outputs created user

**And** `kc users delete <id> [--force]`

- Deletes user, asks confirmation unless --force

**And** `kc users reset-password <id>`

- Prompts for new password (no echo)
- Sets password

**And** `kc users credentials <id>`

- Lists user's credentials (passkeys, OTP, etc.)

**Prerequisites:** Story 2.1, Story 2.2

**Technical Notes:**

- Create `src/cli/commands/users/` with index.ts and subcommand files
- Use citty's subCommands for nested structure
- Create `src/cli/utils/output.ts` for table/JSON formatting
- Table formatting can use simple console.table or cli-table3

---

### Story 2.4: User Search Integration

As an **admin**,
I want **to search users by multiple criteria**,
So that **I can find users quickly** (FR6).

**Acceptance Criteria:**

**Given** users exist with various attributes
**When** I search via MCP `list_users({ search: "john" })`
**Then** users matching "john" in username, email, firstName, or lastName are returned

**And** CLI `kc users list --search john` produces same results
**And** search is case-insensitive
**And** partial matches work (searching "jo" finds "john")

**Prerequisites:** Story 2.1, Story 2.2, Story 2.3

**Technical Notes:**

- Keycloak's `users.find({ search })` handles this natively
- Verify behavior matches expectations
- Document any Keycloak-specific search behavior

---

### Story 2.5: Pagination Support

As an **admin**,
I want **paginated results for large user lists**,
So that **I can handle realms with many users** (FR5).

**Acceptance Criteria:**

**Given** more than 100 users exist
**When** I call `list_users({ max: 50 })`
**Then** exactly 50 users are returned

**And** MCP tool accepts `offset` parameter for pagination
**And** CLI accepts `--offset` flag
**And** response includes total count if available from Keycloak

**Prerequisites:** Story 2.1

**Technical Notes:**

- Keycloak uses `first` (offset) and `max` parameters
- Map to cleaner API: `offset` and `max`
- Check if Keycloak provides total count header

---

### Story 2.6: Credential Management

As an **admin**,
I want **to view and remove user credentials**,
So that **I can help users with authentication issues** (FR12, FR13).

**Acceptance Criteria:**

**Given** a user has WebAuthn credentials registered
**When** I call `get_user_credentials({ id })`
**Then** I see a list with credential id, type, label, and created date

**And** calling `delete_user_credential({ id, credentialId })` removes the credential
**And** CLI `kc users credentials <id>` shows formatted table
**And** CLI `kc users credentials <id> --delete <credId>` removes credential with confirmation

**Prerequisites:** Story 2.1, Story 2.2, Story 2.3

**Technical Notes:**

- Keycloak credentials API: `users.getCredentials({ id })`
- Credential types: password, otp, webauthn, etc.
- Map credential types to user-friendly names

---

## Epic 3: App Management

**Goal:** Enable full OIDC client (app) management through MCP and CLI.

**User Value:** Admin can list, create, configure, and manage apps and their secrets — enabling onboarding of new applications to IdentiKey.

**FRs Covered:** FR14, FR15, FR16, FR17, FR18, FR19

---

### Story 3.1: AppService Core Operations

As an **admin**,
I want **a service that wraps Keycloak client operations**,
So that **I can manage apps (OIDC clients) programmatically**.

**Acceptance Criteria:**

**Given** an authenticated Keycloak client
**When** AppService is instantiated
**Then** the following methods are available:

| Method                 | FR   | Description                       |
| ---------------------- | ---- | --------------------------------- |
| `list()`               | FR14 | List all apps                     |
| `get(id)`              | FR15 | Get app details by ID or clientId |
| `create(data)`         | FR16 | Create new OIDC client            |
| `update(id, data)`     | FR17 | Update app config                 |
| `getSecret(id)`        | FR18 | Get client secret                 |
| `regenerateSecret(id)` | FR19 | Generate new secret               |

**And** apps are returned as IdentiKey `App` type (not Keycloak `ClientRepresentation`)
**And** `clientId` is mapped to `name` in IdentiKey terminology

**Prerequisites:** Epic 1 complete

**Technical Notes:**

- Create `src/lib/keycloak/services/apps.ts`
- Keycloak uses `clients` resource (confusingly named)
- Filter out internal Keycloak clients (account, admin-cli, etc.) from list
- Default new clients to: publicClient=false, standardFlowEnabled=true

---

### Story 3.2: App MCP Tools

As an **AI agent**,
I want **MCP tools for app management**,
So that **I can help admins configure OIDC clients**.

**Acceptance Criteria:**

**Given** MCP server is running
**When** tools are listed
**Then** the following app tools are available:

| Tool                    | Input Schema                             |
| ----------------------- | ---------------------------------------- |
| `list_apps`             | `{}`                                     |
| `get_app`               | `{ id: string }`                         |
| `create_app`            | `{ name, redirectUris?, publicClient? }` |
| `update_app`            | `{ id, ...updateFields }`                |
| `get_app_secret`        | `{ id }`                                 |
| `regenerate_app_secret` | `{ id }`                                 |

**And** `get_app_secret` returns masked secret with option for full reveal
**And** `create_app` returns the created app with its client secret

**Prerequisites:** Story 3.1

**Technical Notes:**

- Create `src/mcp/tools/apps.ts`
- Be careful with secret exposure — warn in response that secret is sensitive
- Include common OIDC config fields in create/update

---

### Story 3.3: App CLI Commands

As a **human admin**,
I want **CLI commands for app management**,
So that **I can onboard and configure apps**.

**Acceptance Criteria:**

**Given** CLI is installed
**When** I run `kc apps --help`
**Then** I see: list, get, create, update, secret, regenerate-secret

**And** `kc apps list [--json]` shows apps table (id, name, enabled, publicClient)
**And** `kc apps get <id> [--json]` shows full config
**And** `kc apps create --name <n> [--redirect-uri <u>]` creates app
**And** `kc apps secret <id>` shows client secret (with warning)
**And** `kc apps regenerate-secret <id> [--force]` regenerates with confirmation

**Prerequisites:** Story 3.1, Story 3.2

**Technical Notes:**

- Create `src/cli/commands/apps/`
- Secret output should include warning about sensitivity
- Consider `--quiet` flag for scripted secret retrieval

---

### Story 3.4: App Configuration Updates

As an **admin**,
I want **to update app configuration**,
So that **I can modify redirect URIs, enable/disable apps, etc.** (FR17).

**Acceptance Criteria:**

**Given** an existing app
**When** I call `update_app({ id, redirectUris: ["https://new.example.com/callback"] })`
**Then** the app's redirect URIs are updated

**And** the following fields can be updated:

- `redirectUris` (array of URIs)
- `enabled` (boolean)
- `publicClient` (boolean)
- `webOrigins` (array of origins for CORS)
- `description` (string)

**And** CLI supports: `kc apps update <id> --redirect-uri <u> --enabled true`

**Prerequisites:** Story 3.1, Story 3.2, Story 3.3

**Technical Notes:**

- Validate redirect URIs are valid URLs
- Warn if changing publicClient on existing app (may break existing integrations)

---

## Epic 4: Guild & Role Management

**Goal:** Enable organizational structure management — guilds (groups) and role assignments.

**User Value:** Admin can organize users into guilds, manage roles, and control access — the foundation for future delegated administration.

**FRs Covered:** FR20-27 (Guilds), FR28-33 (Roles)

---

### Story 4.1: GuildService Core Operations

As an **admin**,
I want **a service for guild (group) management**,
So that **I can organize users into organizational units**.

**Acceptance Criteria:**

**Given** an authenticated Keycloak client
**When** GuildService is instantiated
**Then** the following methods are available:

| Method                          | FR   | Description            |
| ------------------------------- | ---- | ---------------------- |
| `list()`                        | FR20 | List all guilds        |
| `get(id)`                       | FR21 | Get guild details      |
| `create(data)`                  | FR22 | Create guild           |
| `update(id, data)`              | FR23 | Update guild           |
| `delete(id)`                    | FR24 | Delete guild           |
| `listMembers(id)`               | FR25 | List guild members     |
| `addMember(guildId, userId)`    | FR26 | Add user to guild      |
| `removeMember(guildId, userId)` | FR27 | Remove user from guild |

**And** guilds are returned as IdentiKey `Guild` type
**And** member operations return updated member list

**Prerequisites:** Epic 1 complete, Epic 2 complete (for user references)

**Technical Notes:**

- Create `src/lib/keycloak/services/guilds.ts`
- Keycloak groups are hierarchical — expose flat list initially, note path
- `listMembers` uses `groups.listMembers({ id })`

---

### Story 4.2: RoleService Core Operations

As an **admin**,
I want **a service for role management**,
So that **I can assign permissions to users and guilds**.

**Acceptance Criteria:**

**Given** an authenticated Keycloak client
**When** RoleService is instantiated
**Then** the following methods are available:

| Method                                   | FR   | Description                  |
| ---------------------------------------- | ---- | ---------------------------- |
| `listRealmRoles()`                       | FR28 | List realm-level roles       |
| `listClientRoles(clientId)`              | FR29 | List roles for specific app  |
| `assignRoleToUser(userId, roleName)`     | FR30 | Assign realm role to user    |
| `removeRoleFromUser(userId, roleName)`   | FR31 | Remove realm role from user  |
| `assignRoleToGuild(guildId, roleName)`   | FR32 | Assign realm role to guild   |
| `removeRoleFromGuild(guildId, roleName)` | FR33 | Remove realm role from guild |

**And** role assignment is idempotent (assigning twice doesn't error)

**Prerequisites:** Epic 1 complete

**Technical Notes:**

- Create `src/lib/keycloak/services/roles.ts`
- Realm roles: `roles.find()`
- Client roles: `clients.listRoles({ id: clientId })`
- Role mapping: `users.addRealmRoleMappings({ id, roles: [...] })`

---

### Story 4.3: Guild MCP Tools

As an **AI agent**,
I want **MCP tools for guild management**,
So that **I can help organize users**.

**Acceptance Criteria:**

**Given** MCP server is running
**Then** the following guild tools are available:

| Tool                  | Input Schema          |
| --------------------- | --------------------- |
| `list_guilds`         | `{}`                  |
| `get_guild`           | `{ id }`              |
| `create_guild`        | `{ name }`            |
| `update_guild`        | `{ id, name? }`       |
| `delete_guild`        | `{ id }`              |
| `list_guild_members`  | `{ id }`              |
| `add_guild_member`    | `{ guildId, userId }` |
| `remove_guild_member` | `{ guildId, userId }` |

**Prerequisites:** Story 4.1

**Technical Notes:**

- Create `src/mcp/tools/guilds.ts`

---

### Story 4.4: Role MCP Tools

As an **AI agent**,
I want **MCP tools for role management**,
So that **I can help assign permissions**.

**Acceptance Criteria:**

**Given** MCP server is running
**Then** the following role tools are available:

| Tool                     | Input Schema            |
| ------------------------ | ----------------------- |
| `list_realm_roles`       | `{}`                    |
| `list_app_roles`         | `{ appId }`             |
| `assign_role_to_user`    | `{ userId, roleName }`  |
| `remove_role_from_user`  | `{ userId, roleName }`  |
| `assign_role_to_guild`   | `{ guildId, roleName }` |
| `remove_role_from_guild` | `{ guildId, roleName }` |

**Prerequisites:** Story 4.2

**Technical Notes:**

- Create `src/mcp/tools/roles.ts`

---

### Story 4.5: Guild CLI Commands

As a **human admin**,
I want **CLI commands for guild management**,
So that **I can organize users from terminal**.

**Acceptance Criteria:**

**Given** CLI is installed
**When** I run `kc guilds --help`
**Then** I see: list, get, create, update, delete, members, add-member, remove-member

**And** `kc guilds list` shows guilds table (id, name, path, memberCount)
**And** `kc guilds members <id>` shows member list
**And** `kc guilds add-member <guildId> <userId>` adds user
**And** `kc guilds remove-member <guildId> <userId>` removes user

**Prerequisites:** Story 4.1, Story 4.3

**Technical Notes:**

- Create `src/cli/commands/guilds/`

---

### Story 4.6: Role CLI Commands

As a **human admin**,
I want **CLI commands for role management**,
So that **I can assign permissions from terminal**.

**Acceptance Criteria:**

**Given** CLI is installed
**When** I run `kc roles --help`
**Then** I see: list, list-app-roles, assign, remove

**And** `kc roles list` shows realm roles
**And** `kc roles list-app-roles <appId>` shows app-specific roles
**And** `kc roles assign <roleName> --user <userId>` assigns to user
**And** `kc roles assign <roleName> --guild <guildId>` assigns to guild
**And** `kc roles remove <roleName> --user <userId>` removes from user

**Prerequisites:** Story 4.2, Story 4.4

**Technical Notes:**

- Create `src/cli/commands/roles/`

---

## Epic 5: Login Flow Administration

**Goal:** Enable authentication flow debugging and configuration — the PRIMARY use case for Master Dorje.

**User Value:** Admin can investigate auth issues, view flow configurations, and modify authentication steps — this is the killer feature for debugging WebAuthn and conditional auth.

**FRs Covered:** FR34, FR35, FR36, FR37, FR38, FR39, FR40, FR41

---

### Story 5.1: AuthFlowService Core Operations

As an **admin**,
I want **a service for authentication flow management**,
So that **I can debug and configure login flows**.

**Acceptance Criteria:**

**Given** an authenticated Keycloak client
**When** AuthFlowService is instantiated
**Then** the following methods are available:

| Method                                       | FR   | Description                  |
| -------------------------------------------- | ---- | ---------------------------- |
| `list()`                                     | FR34 | List all login flows         |
| `get(flowAlias)`                             | FR35 | Get flow details             |
| `listExecutions(flowAlias)`                  | FR36 | List flow executions (steps) |
| `addExecution(flowAlias, data)`              | FR37 | Add execution to flow        |
| `removeExecution(flowAlias, executionId)`    | FR38 | Remove execution             |
| `reorderExecutions(flowAlias, executionIds)` | FR39 | Reorder executions           |
| `copy(sourceAlias, newAlias)`                | FR40 | Copy flow                    |
| `setDefault(flowAlias, bindingType)`         | FR41 | Set as default               |

**And** executions include: id, displayName, requirement (REQUIRED/OPTIONAL/DISABLED), configurable, index
**And** binding types: browser, direct-grant, registration, reset-credentials, docker-auth

**Prerequisites:** Epic 1 complete

**Technical Notes:**

- Create `src/lib/keycloak/services/auth-flows.ts`
- Keycloak API: `authenticationManagement`
- Executions are nested (subflows) — expose flat list with level indicator
- This is complex API — handle edge cases carefully

---

### Story 5.2: Login Flow MCP Tools

As an **AI agent**,
I want **MCP tools for login flow management**,
So that **I can help debug authentication issues conversationally**.

**Acceptance Criteria:**

**Given** MCP server is running
**Then** the following tools are available:

| Tool                      | Input Schema                            |
| ------------------------- | --------------------------------------- |
| `list_login_flows`        | `{}`                                    |
| `get_login_flow`          | `{ flowAlias }`                         |
| `list_flow_executions`    | `{ flowAlias }`                         |
| `add_flow_execution`      | `{ flowAlias, provider, requirement? }` |
| `remove_flow_execution`   | `{ flowAlias, executionId }`            |
| `reorder_flow_executions` | `{ flowAlias, executionIds }`           |
| `copy_login_flow`         | `{ sourceAlias, newAlias }`             |
| `set_default_login_flow`  | `{ flowAlias, bindingType }`            |

**And** `list_flow_executions` shows clear hierarchy and current config
**And** responses help AI understand auth flow structure

**Prerequisites:** Story 5.1

**Technical Notes:**

- Create `src/mcp/tools/auth-flows.ts`
- Include helpful descriptions for AI to understand flow concepts
- Format executions to show hierarchy clearly

---

### Story 5.3: Login Flow CLI Commands

As a **human admin**,
I want **CLI commands for login flow management**,
So that **I can debug auth flows from terminal**.

**Acceptance Criteria:**

**Given** CLI is installed
**When** I run `kc auth-flows --help`
**Then** I see: list, get, executions, add, remove, reorder, copy, set-default

**And** `kc auth-flows list` shows flows table (alias, providerId, builtIn)
**And** `kc auth-flows executions <alias>` shows execution tree with indentation
**And** `kc auth-flows copy <source> <new>` copies flow
**And** `kc auth-flows set-default <alias> --binding browser` sets binding

**Prerequisites:** Story 5.1, Story 5.2

**Technical Notes:**

- Create `src/cli/commands/auth-flows/`
- Execution display should use tree-like indentation for subflows
- Show requirement status clearly (REQUIRED, OPTIONAL, DISABLED)

---

### Story 5.4: Execution Modification

As an **admin**,
I want **to add, remove, and reorder flow executions**,
So that **I can customize authentication flows** (FR37, FR38, FR39).

**Acceptance Criteria:**

**Given** a login flow "browser-custom"
**When** I add an execution via `add_flow_execution({ flowAlias: "browser-custom", provider: "webauthn-authenticator" })`
**Then** the WebAuthn authenticator is added to the flow

**And** I can set requirement to REQUIRED, ALTERNATIVE, CONDITIONAL, DISABLED
**And** removing execution removes it and reorders remaining
**And** reorder accepts array of execution IDs in desired order

**Prerequisites:** Story 5.1

**Technical Notes:**

- Adding execution: `authenticationManagement.addExecution({ flow, provider })`
- Requirement update: `authenticationManagement.updateExecution({ flow, execution })`
- Reorder: `authenticationManagement.raisePriority/lowerPriority` or batch update

---

### Story 5.5: Flow Copy & Defaults

As an **admin**,
I want **to copy flows and set defaults**,
So that **I can safely experiment with auth config** (FR40, FR41).

**Acceptance Criteria:**

**Given** built-in "browser" flow
**When** I call `copy_login_flow({ sourceAlias: "browser", newAlias: "browser-custom" })`
**Then** a new flow "browser-custom" is created with same executions

**And** I can set it as default: `set_default_login_flow({ flowAlias: "browser-custom", bindingType: "browser" })`
**And** setting default affects all browser authentication

**Prerequisites:** Story 5.1

**Technical Notes:**

- Copy: `authenticationManagement.copyFlow({ flow: source, newName })`
- Set binding: Update realm with new flow binding
- Warn before changing default (affects all logins!)

---

## Epic 6: Sessions & Events

**Goal:** Enable session management and event queries for debugging authentication issues.

**User Value:** Admin can see who's logged in, force logouts, and investigate "why did login fail?" through event queries — critical for debugging.

**FRs Covered:** FR42-44 (Sessions), FR45-48 (Events)

---

### Story 6.1: SessionService Core Operations

As an **admin**,
I want **a service for session management**,
So that **I can view and terminate user sessions**.

**Acceptance Criteria:**

**Given** an authenticated Keycloak client
**When** SessionService is instantiated
**Then** the following methods are available:

| Method                     | FR   | Description                         |
| -------------------------- | ---- | ----------------------------------- |
| `listUserSessions(userId)` | FR42 | List active sessions for user       |
| `logoutUser(userId)`       | FR43 | Terminate all sessions for user     |
| `logoutAll()`              | FR44 | Terminate all sessions (realm-wide) |

**And** session info includes: id, username, ipAddress, started, lastAccess, clients
**And** `logoutAll` requires explicit confirmation flag

**Prerequisites:** Epic 1 complete

**Technical Notes:**

- Create `src/lib/keycloak/services/sessions.ts`
- Sessions: `users.listSessions({ id })`
- Logout user: `users.logout({ id })`
- Logout all: Post to realm logout-all endpoint

---

### Story 6.2: EventService Core Operations

As an **admin**,
I want **a service for querying events**,
So that **I can investigate authentication issues**.

**Acceptance Criteria:**

**Given** an authenticated Keycloak client (and events enabled in Keycloak)
**When** EventService is instantiated
**Then** the following methods are available:

| Method                       | FR   | Description        |
| ---------------------------- | ---- | ------------------ |
| `queryLoginEvents(filters?)` | FR45 | Query login events |
| `queryAdminEvents(filters?)` | FR47 | Query admin events |

**And** login event filters include (FR46):

- `userId` - filter by user
- `dateFrom`, `dateTo` - time range
- `type` - event type (LOGIN, LOGIN_ERROR, LOGOUT, etc.)
- `client` - filter by client/app

**And** admin event filters include (FR48):

- `dateFrom`, `dateTo` - time range
- `operationType` - CREATE, UPDATE, DELETE, ACTION
- `resourceType` - USER, CLIENT, GROUP, etc.

**And** events include: time, type, userId, clientId, ipAddress, details, error (if any)

**Prerequisites:** Epic 1 complete

**Technical Notes:**

- Create `src/lib/keycloak/services/events.ts`
- Login events: `attackDetection` or `events.find({ ... })`
- Admin events: `events.findAdmin({ ... })`
- ⚠️ Requires events enabled in Keycloak realm settings!

---

### Story 6.3: Session & Event MCP Tools

As an **AI agent**,
I want **MCP tools for sessions and events**,
So that **I can help debug "why did login fail?" questions**.

**Acceptance Criteria:**

**Given** MCP server is running
**Then** the following tools are available:

| Tool                 | Input Schema                                                  |
| -------------------- | ------------------------------------------------------------- |
| `list_user_sessions` | `{ userId }`                                                  |
| `logout_user`        | `{ userId }`                                                  |
| `logout_all_users`   | `{ confirm: true }`                                           |
| `query_login_events` | `{ userId?, dateFrom?, dateTo?, type?, client?, max? }`       |
| `query_admin_events` | `{ dateFrom?, dateTo?, operationType?, resourceType?, max? }` |

**And** `query_login_events` is the key tool for "why did user X's login fail?"
**And** event responses include human-readable timestamps and error details

**Prerequisites:** Story 6.1, Story 6.2

**Technical Notes:**

- Create `src/mcp/tools/sessions.ts`
- Create `src/mcp/tools/events.ts`
- Format timestamps as ISO strings AND relative ("2 hours ago")
- Include error details prominently for LOGIN_ERROR events

---

### Story 6.4: Session & Event CLI Commands

As a **human admin**,
I want **CLI commands for sessions and events**,
So that **I can investigate issues from terminal**.

**Acceptance Criteria:**

**Given** CLI is installed
**When** I run `kc sessions --help`
**Then** I see: list, logout, logout-all

**And** `kc sessions list <userId>` shows session table (id, ip, started, lastAccess)
**And** `kc sessions logout <userId>` terminates sessions with confirmation
**And** `kc sessions logout-all --confirm` terminates all sessions

**When** I run `kc events --help`
**Then** I see: login, admin

**And** `kc events login [--user <id>] [--type LOGIN_ERROR] [--from <date>] [--max 50]`

- Shows login events table (time, type, user, client, ip, error)

**And** `kc events admin [--type UPDATE] [--resource USER] [--max 50]`

- Shows admin events table (time, operation, resource, resourcePath)

**Prerequisites:** Story 6.1, Story 6.2, Story 6.3

**Technical Notes:**

- Create `src/cli/commands/sessions/`
- Create `src/cli/commands/events/`
- Date parsing: accept ISO strings, relative ("1h ago", "yesterday")
- Color-code error events in terminal output

---

## FR Coverage Matrix

| FR   | Description                | Epic     | Story           |
| ---- | -------------------------- | -------- | --------------- |
| FR1  | Service account auth       | Epic 1   | 1.3             |
| FR2  | Username/password auth     | Epic 1   | 1.3             |
| FR3  | Env var configuration      | Epic 1   | 1.2             |
| FR4  | Connection validation      | Epic 1   | 1.5             |
| FR5  | List users with pagination | Epic 2   | 2.1, 2.5        |
| FR6  | Search users               | Epic 2   | 2.1, 2.4        |
| FR7  | Get user details           | Epic 2   | 2.1             |
| FR8  | Create users               | Epic 2   | 2.1             |
| FR9  | Update users               | Epic 2   | 2.1             |
| FR10 | Delete users               | Epic 2   | 2.1             |
| FR11 | Reset password             | Epic 2   | 2.1             |
| FR12 | View credentials           | Epic 2   | 2.6             |
| FR13 | Delete credentials         | Epic 2   | 2.6             |
| FR14 | List apps                  | Epic 3   | 3.1             |
| FR15 | Get app details            | Epic 3   | 3.1             |
| FR16 | Create apps                | Epic 3   | 3.1             |
| FR17 | Update apps                | Epic 3   | 3.4             |
| FR18 | Get app secret             | Epic 3   | 3.1             |
| FR19 | Regenerate secret          | Epic 3   | 3.1             |
| FR20 | List guilds                | Epic 4   | 4.1             |
| FR21 | Get guild details          | Epic 4   | 4.1             |
| FR22 | Create guilds              | Epic 4   | 4.1             |
| FR23 | Update guilds              | Epic 4   | 4.1             |
| FR24 | Delete guilds              | Epic 4   | 4.1             |
| FR25 | List guild members         | Epic 4   | 4.1             |
| FR26 | Add guild member           | Epic 4   | 4.1             |
| FR27 | Remove guild member        | Epic 4   | 4.1             |
| FR28 | List realm roles           | Epic 4   | 4.2             |
| FR29 | List app roles             | Epic 4   | 4.2             |
| FR30 | Assign role to user        | Epic 4   | 4.2             |
| FR31 | Remove role from user      | Epic 4   | 4.2             |
| FR32 | Assign role to guild       | Epic 4   | 4.2             |
| FR33 | Remove role from guild     | Epic 4   | 4.2             |
| FR34 | List login flows           | Epic 5   | 5.1             |
| FR35 | Get flow details           | Epic 5   | 5.1             |
| FR36 | List executions            | Epic 5   | 5.1             |
| FR37 | Add execution              | Epic 5   | 5.4             |
| FR38 | Remove execution           | Epic 5   | 5.4             |
| FR39 | Reorder executions         | Epic 5   | 5.4             |
| FR40 | Copy flow                  | Epic 5   | 5.5             |
| FR41 | Set default flow           | Epic 5   | 5.5             |
| FR42 | List user sessions         | Epic 6   | 6.1             |
| FR43 | Logout user                | Epic 6   | 6.1             |
| FR44 | Logout all                 | Epic 6   | 6.1             |
| FR45 | Query login events         | Epic 6   | 6.2             |
| FR46 | Filter login events        | Epic 6   | 6.2             |
| FR47 | Query admin events         | Epic 6   | 6.2             |
| FR48 | Filter admin events        | Epic 6   | 6.2             |
| FR49 | MCP exposes all ops        | Epic 2-6 | All MCP stories |
| FR50 | MCP structured responses   | Epic 2-6 | All MCP stories |
| FR51 | MCP error messages         | Epic 2-6 | All MCP stories |
| FR52 | CLI exposes all ops        | Epic 2-6 | All CLI stories |
| FR53 | CLI JSON output            | Epic 2-6 | All CLI stories |
| FR54 | CLI table output           | Epic 2-6 | All CLI stories |
| FR55 | CLI help text              | Epic 2-6 | All CLI stories |

**Coverage Validation:** ✅ All 55 FRs mapped to stories.

---

## Summary

| Epic                              | Stories | Primary Value                                 |
| --------------------------------- | ------- | --------------------------------------------- |
| Epic 1: Foundation                | 5       | Project infrastructure, Keycloak connectivity |
| Epic 2: User Administration       | 6       | Full user management via MCP + CLI            |
| Epic 3: App Management            | 4       | OIDC client management via MCP + CLI          |
| Epic 4: Guild & Role Management   | 6       | Organizational structure and permissions      |
| Epic 5: Login Flow Administration | 5       | Auth flow debugging and configuration         |
| Epic 6: Sessions & Events         | 4       | Session control and event investigation       |

**Total: 30 Stories across 6 Epics**

**Recommended Order:** Epic 1 → Epic 2 → Epic 5 → Epic 6 → Epic 3 → Epic 4

_Rationale: Foundation first, then Users (most common ops), then Login Flows + Events (Master Dorje's primary use case for debugging), then Apps and Guilds (less urgent)._

---

## Document Status

**Status:** ✅ Approved
**Approved By:** Master Dorje
**Approved Date:** 2025-11-30

---

_For implementation: Use the `dev-story` workflow to implement individual stories from this breakdown._

_This document will be updated when UX Design is created for Web UI phase._
