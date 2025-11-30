# keycloak-commander — Product Requirements Document

**Author:** Master Dorje
**Date:** 2025-11-30
**Version:** 1.0

---

## Executive Summary

keycloak-commander is the **administrative interface for IdentiKey's identity platform**. While powered by Keycloak under the hood, users interact with IdentiKey concepts—not Keycloak terminology. The system abstracts the underlying IAM complexity into a clean, purpose-built admin experience.

The architecture is **MCP-first**: AI agents (via Cursor, etc.) are primary power users for development and debugging. A CLI enables human testing, and a SvelteKit web UI will provide visual administration for guild/group admins.

### What Makes This Special

**IdentiKey IS the product, Keycloak is invisible.** Users don't need to know they're interacting with Keycloak. The admin interface speaks IdentiKey's language:

- "Users" not "Realm Users"
- "Apps" not "OIDC Clients"
- "Guilds" not "Groups"
- "Login Flows" not "Authentication Flows"

**AI-native administration.** MCP enables conversational debugging: "Why did user X's login fail?" becomes a real workflow, not a fantasy.

---

## Project Classification

**Technical Type:** Developer Tool / Admin Platform
**Domain:** Identity & Access Management (General complexity, security-sensitive)
**Complexity:** Medium

This is internal tooling that grows into a product. Phase 1 serves the developer (Master Dorje) via MCP + CLI. Future phases expose a web UI for delegated administration.

---

## Success Criteria

### Phase 1 Success (MCP + CLI)

1. **Conversational Admin Works** — Can ask an AI agent "show me failed logins for user X" or "what's the current auth flow config" and get actionable answers
2. **Auth Flow Debugging is Fast** — Can investigate WebAuthn/conditional auth issues without clicking through Keycloak UI
3. **Every Operation is Testable** — CLI covers all MCP operations for human verification
4. **Foundation is Solid** — Core service layer is clean enough to expose via web routes later

### Phase 2 Success (Web UI)

1. **Guild Admins Self-Serve** — Group admins manage their own users without platform admin involvement
2. **IdentiKey Feels Native** — UI speaks IdentiKey language; users don't know it's Keycloak
3. **Onboarding is Smooth** — New apps (clients) can be configured without deep IAM knowledge

---

## Product Scope

### MVP — Phase 1 (MCP + CLI)

**Core Service Layer** wrapping Keycloak Admin API:

| Domain              | Capabilities                                                                              |
| ------------------- | ----------------------------------------------------------------------------------------- |
| **Auth Flows**      | List, get details, list executions, add/remove/reorder executions, copy flow, set default |
| **Users**           | List, search, get details, create, update, delete, reset password, get/delete credentials |
| **Clients (Apps)**  | List, get details, create, update, get secret, regenerate secret                          |
| **Groups (Guilds)** | List, get details, create, update, delete, list members, add/remove members               |
| **Roles**           | List realm roles, list client roles, assign/unassign to users/groups                      |
| **Sessions**        | List user sessions, force logout user, force logout all                                   |
| **Events**          | Query login events, query admin events (requires events enabled in Keycloak)              |

**MCP Server** exposing all operations to AI agents

**CLI** mirroring MCP operations for human testing/debugging

### Growth Features (Post-MVP)

| Domain                 | Capabilities                            |
| ---------------------- | --------------------------------------- |
| **Identity Providers** | List, create, update, delete IDPs       |
| **Protocol Mappers**   | List, create, update mappers per client |
| **Client Scopes**      | Manage scopes, assign to clients        |
| **Required Actions**   | List, configure onboarding requirements |

### Vision (Future)

| Domain              | Capabilities                                     |
| ------------------- | ------------------------------------------------ |
| **Web UI**          | SvelteKit admin dashboard                        |
| **Delegated Admin** | Guild admins manage their scope only             |
| **Realm Settings**  | Token lifetimes, session config, etc.            |
| **Brute Force**     | View/clear blocked users/IPs                     |
| **TUI Mode**        | Interactive terminal UI with keyboard navigation |

---

## Developer Tool Specific Requirements

### Architecture

```
┌─────────────────────────────────────────────────────┐
│              Keycloak Admin REST API                │
│                (IdentiKey instance)                 │
└─────────────────────────────────────────────────────┘
                          ▲
                          │ HTTP
┌─────────────────────────────────────────────────────┐
│              Core Service Layer                     │
│     (TypeScript classes, IdentiKey abstractions)    │
│                                                     │
│  AuthFlowService | UserService | ClientService      │
│  GroupService | RoleService | SessionService        │
│  EventService | ...                                 │
└─────────────────────────────────────────────────────┘
          ▲                ▲                ▲
          │                │                │
    ┌─────┴─────┐    ┌─────┴─────┐    ┌─────┴─────┐
    │MCP Server │    │    CLI    │    │  Web UI   │
    │  (stdio)  │    │           │    │(SvelteKit)│
    └───────────┘    └───────────┘    └───────────┘
         ↑                ↑
    AI Agents         Humans
    (Cursor)        (testing)
```

### MCP Server

- **Transport:** stdio (local MCP for Cursor)
- **Tools:** One tool per operation (e.g., `list_users`, `get_auth_flow`, `query_login_events`)
- **Responses:** Structured data AI can reason about
- **Error Handling:** Clear error messages that help AI diagnose issues

### CLI

- **Framework:** TBD (Commander.js, oclif, or similar)
- **Output Formats:** JSON (default), table (human-friendly)
- **Config:** Environment variables for Keycloak connection (`KEYCLOAK_URL`, `KEYCLOAK_REALM`, credentials)
- **Auth:** Service account or admin credentials
- **Commands:** Mirror MCP tools 1:1 for testability

### IdentiKey Abstraction Layer

Map Keycloak concepts to IdentiKey terminology:

| Keycloak Term       | IdentiKey Term                        |
| ------------------- | ------------------------------------- |
| Realm               | (hidden — always identikey)           |
| Client              | App                                   |
| Group               | Guild                                 |
| Authentication Flow | Login Flow                            |
| User Federation     | (hidden)                              |
| Protocol Mapper     | (exposed as "Token Claims" if needed) |

---

## Functional Requirements

### Authentication & Connection

- **FR1:** System can authenticate to Keycloak Admin API using service account credentials
- **FR2:** System can authenticate using admin username/password
- **FR3:** Connection configuration is provided via environment variables
- **FR4:** System validates connection on startup and reports clear errors if unreachable

### User Management

- **FR5:** Admins can list all users with pagination
- **FR6:** Admins can search users by username, email, first name, or last name
- **FR7:** Admins can get detailed information for a specific user
- **FR8:** Admins can create new users with required attributes
- **FR9:** Admins can update user attributes (name, email, enabled status, etc.)
- **FR10:** Admins can delete users
- **FR11:** Admins can reset a user's password
- **FR12:** Admins can view a user's credentials (passkeys, OTP devices, etc.)
- **FR13:** Admins can delete specific credentials from a user

### App (Client) Management

- **FR14:** Admins can list all apps (OIDC clients)
- **FR15:** Admins can get detailed configuration for a specific app
- **FR16:** Admins can create new apps with standard OIDC configuration
- **FR17:** Admins can update app configuration (redirect URIs, scopes, etc.)
- **FR18:** Admins can retrieve an app's client secret
- **FR19:** Admins can regenerate an app's client secret

### Guild (Group) Management

- **FR20:** Admins can list all guilds
- **FR21:** Admins can get details for a specific guild
- **FR22:** Admins can create new guilds
- **FR23:** Admins can update guild attributes
- **FR24:** Admins can delete guilds
- **FR25:** Admins can list members of a guild
- **FR26:** Admins can add users to a guild
- **FR27:** Admins can remove users from a guild

### Role Management

- **FR28:** Admins can list all realm-level roles
- **FR29:** Admins can list client-specific roles for an app
- **FR30:** Admins can assign realm roles to users
- **FR31:** Admins can remove realm roles from users
- **FR32:** Admins can assign realm roles to guilds
- **FR33:** Admins can remove realm roles from guilds

### Login Flow (Authentication Flow) Management

- **FR34:** Admins can list all login flows
- **FR35:** Admins can get detailed configuration of a login flow
- **FR36:** Admins can list executions (steps) within a login flow
- **FR37:** Admins can add executions to a login flow
- **FR38:** Admins can remove executions from a login flow
- **FR39:** Admins can reorder executions within a login flow
- **FR40:** Admins can copy an existing login flow to create a new one
- **FR41:** Admins can set a login flow as the default for browser/direct-grant/etc.

### Session Management

- **FR42:** Admins can list active sessions for a specific user
- **FR43:** Admins can force logout a specific user (terminate all sessions)
- **FR44:** Admins can force logout all users (realm-wide session termination)

### Event & Audit Queries

- **FR45:** Admins can query login events (successful and failed authentications)
- **FR46:** Admins can filter login events by user, time range, event type, and client
- **FR47:** Admins can query admin events (configuration changes)
- **FR48:** Admins can filter admin events by time range, operation type, and resource

### MCP Interface

- **FR49:** All FR5-FR48 operations are exposed as MCP tools callable by AI agents
- **FR50:** MCP responses include structured data suitable for AI reasoning
- **FR51:** MCP error responses include actionable information for debugging

### CLI Interface

- **FR52:** All FR5-FR48 operations are exposed as CLI commands
- **FR53:** CLI supports JSON output format for scripting
- **FR54:** CLI supports human-readable table output format
- **FR55:** CLI provides help text for all commands

---

## Non-Functional Requirements

### Security

- **NFR1:** Credentials (Keycloak admin password, client secrets) are never logged or exposed in error messages
- **NFR2:** MCP server only accepts local connections (stdio transport, not network-exposed)
- **NFR3:** CLI does not store credentials in command history (reads from env vars or prompts)
- **NFR4:** All Keycloak API calls use HTTPS in production

### Reliability

- **NFR5:** Operations are idempotent where possible (safe to retry)
- **NFR6:** Failed operations return clear error messages with Keycloak error details
- **NFR7:** Connection failures are handled gracefully with retry guidance

### Developer Experience

- **NFR8:** MCP tools have descriptive names and parameter documentation
- **NFR9:** CLI commands follow consistent naming conventions (`kc <domain> <action>`)
- **NFR10:** Error messages suggest corrective actions when possible

### Maintainability

- **NFR11:** Core service layer is independent of interface (MCP/CLI/Web can share code)
- **NFR12:** Keycloak API version compatibility is documented
- **NFR13:** TypeScript types are generated or maintained for Keycloak API responses

---

## Technical Constraints

- **Keycloak Version:** Must work with IdentiKey's deployed Keycloak instance (version TBD)
- **Realm:** Always operates on `identikey` realm (master realm is reserved for Keycloak administration only)
- **Runtime:** Node.js / TypeScript (aligns with SvelteKit for future web UI)
- **MCP:** Local stdio transport for Cursor integration

---

## Out of Scope (MVP)

- Realm creation/deletion
- Full import/export functionality
- Multi-realm support
- Keycloak deployment/operations
- User self-service (that's Keycloak's account console)
- High-availability concerns

---

## Document Status

**Status:** ✅ Approved
**Approved By:** Master Dorje
**Approved Date:** 2025-11-30
**PRD Version:** 1.0
**FR Count:** 55
**NFR Count:** 13

---

_This PRD captures the requirements for keycloak-commander — IdentiKey's AI-native identity platform admin interface._

_Next: Architecture workflow for technical design decisions, then epic breakdown for implementation planning._
