# Product Brief: keycloak-commander

**Date:** 2025-11-30
**Author:** Master Dorje
**Context:** Internal Developer Tooling → IdentiKey Platform Admin Interface

---

## Executive Summary

_keycloak-commander_ is **the administrative interface for IdentiKey's identity platform**. While powered by Keycloak under the hood, users interact with IdentiKey concepts—not Keycloak terminology. The system abstracts the underlying IAM complexity into a clean, purpose-built admin experience.

The architecture is **MCP-first**: a local MCP server enables AI agents (in Cursor, etc.) to directly execute admin operations. A CLI provides human-accessible testing and debugging. Future phases add a web UI for self-service administration by guild/group admins.

**Key Insight:** This isn't "a Keycloak admin tool"—it's THE admin app for IdentiKey. Users will never know they're interacting with Keycloak. The interface speaks IdentiKey's language and grows into the full administrative experience for the platform.

---

## Core Vision

### Problem Statement

IdentiKey needs a dedicated administrative interface that:

- Speaks IdentiKey's language, not Keycloak's
- Enables AI-assisted debugging of complex auth flows (WebAuthn, conditional authentication)
- Provides self-service capabilities for guild admins without exposing IAM complexity
- Supports developer workflows (MCP for agents, CLI for testing)

The raw Keycloak admin console is click-heavy, Keycloak-terminology-heavy, and impossible for AI agents to assist with effectively.

### Proposed Solution

**IdentiKey Admin** — A purpose-built interface that abstracts Keycloak into IdentiKey concepts:

| Keycloak Term       | IdentiKey Term                |
| ------------------- | ----------------------------- |
| Realm               | _(hidden — always identikey)_ |
| Client              | App                           |
| Group               | Guild                         |
| Authentication Flow | Login Flow                    |
| Protocol Mapper     | Token Claims                  |

Three interfaces expose these abstractions:

1. **MCP Server** (primary) — AI agents call IdentiKey operations directly. Enables conversational debugging: "show me the current login flow," "what failed for user X," "list all apps."

2. **CLI** — Human-accessible commands for testing each operation, debugging, and quick one-off tasks.

3. **Web UI** (future) — SvelteKit dashboard for visual administration. Self-service for guild admins to manage their own users without seeing Keycloak complexity.

---

## Target Users

### Primary User (Now)

**Master Dorje** — Building and debugging IdentiKey's authentication system. Uses MCP via Cursor agents to investigate issues, configure flows, and manage the Keycloak instance.

### Future Users

**Guild/Group Administrators** — Non-technical admins who manage users within their organizational unit. They'll use the web UI to:

- Add/remove users in their group
- Reset passwords, manage credentials
- View their group's user list
- Assign group-specific roles

**Permissions Model:** Scoped access—admins can only see and manage what they have permissions for. Global user search may be available for adding users, but administration is locked to your own group/role scope.

---

## IdentiKey Architecture Context

- **Dedicated `identikey` Realm** — All IdentiKey users, apps, guilds live here (master realm is reserved for Keycloak administration only)
- **Multi-tenant via Clients** — Multiple applications connect via OIDC
- **Shared User Database** — Users can authenticate to any client they're authorized for
- **Groups = "Guilds"** — Organizational units with delegated admin capabilities

---

## MVP Scope — Core Features

### Tier 1: Essential (MCP + CLI)

| Domain         | Operations                                                                                                   |
| -------------- | ------------------------------------------------------------------------------------------------------------ |
| **Auth Flows** | List flows, get flow details, list executions, add/remove/reorder executions, copy flow, set flow as default |
| **Users**      | List, search, get details, create, update, delete, reset password, get credentials, delete credentials       |
| **Clients**    | List, get details, create, update, get client secret, regenerate secret                                      |
| **Groups**     | List, get details, create, update, delete, list members, add/remove members                                  |
| **Roles**      | List realm roles, list client roles, assign/unassign roles to users/groups                                   |
| **Sessions**   | List user sessions, force logout user, force logout all                                                      |

### Tier 1.5: High Priority (Enable Events First!)

| Domain           | Operations                       | Why                                                      |
| ---------------- | -------------------------------- | -------------------------------------------------------- |
| **Events/Audit** | Query login events, admin events | Debug auth failures, see "why did login fail for user X" |

> ⚠️ **Action Required:** Enable event logging in Keycloak (Realm Settings → Events → Save events: ON). This unlocks conversational debugging like "show me failed logins for user X in the last hour."

### Tier 2: Valuable Additions

| **Identity Providers** | List, create, update, delete IDPs | Add social logins, SAML federation |
| **Protocol Mappers** | List, create, update mappers per client | Control what claims appear in tokens |
| **Client Scopes** | Manage scopes, assign to clients | OAuth scope management |
| **Required Actions** | List, configure (verify email, update password, etc.) | Onboarding flows |

### Tier 3: Nice-to-Have

| Domain              | Operations                            | Why                                    |
| ------------------- | ------------------------------------- | -------------------------------------- |
| **Realm Settings**  | Get/update realm config               | Adjust timeouts, token lifetimes, etc. |
| **Brute Force**     | Check blocked users/IPs, clear blocks | Security debugging                     |
| **User Federation** | Manage LDAP/AD connections            | If external user sources needed        |
| **Credentials**     | Password policies, WebAuthn config    | Credential management at realm level   |

---

## Technical Preferences

- **Framework:** SvelteKit (scaffolded)
- **MCP:** Local MCP server (Node/TypeScript)
- **CLI:** TypeScript, potentially using a framework like Commander.js or similar
- **Target:** Keycloak Admin REST API
- **Realm:** Always `identikey` (master realm reserved for Keycloak admin operations only)

### Architecture Pattern

```
┌─────────────────────────────────────────────────────┐
│                  Keycloak Admin API                 │
└─────────────────────────────────────────────────────┘
                          ▲
                          │
┌─────────────────────────────────────────────────────┐
│              Core Service Layer                     │
│  (TypeScript classes encapsulating API operations)  │
└─────────────────────────────────────────────────────┘
          ▲                ▲                ▲
          │                │                │
    ┌─────┴─────┐    ┌─────┴─────┐    ┌─────┴─────┐
    │ MCP Server│    │    CLI    │    │  Web UI   │
    │  (Agent)  │    │  (Human)  │    │ (SvelteKit)│
    └───────────┘    └───────────┘    └───────────┘
```

---

## Out of Scope (MVP)

- Realm creation/deletion (using existing master realm)
- Full import/export functionality
- Multi-realm support
- High-availability / clustering concerns
- Keycloak deployment/operations (it's already deployed)

---

## Keycloak Features Worth Investigating

Given your multi-tenant shared-user-database setup, these Keycloak features might be clutch:

### Token & Claims

- **Group Membership Mappers** — Include `groups` claim in tokens → apps know which guilds user belongs to
- **Client Scopes** — Control which claims each client receives
- **Offline Tokens** — Long-lived refresh tokens for apps that need them

### User Organization

- **Group Hierarchies** — Nested groups (parent guild → sub-guilds)
- **Default Groups** — Auto-assign new users to specific groups on registration
- **Auto-Group-on-Login** — Custom authenticator or first-broker-login flow to add user to group based on which client they're authenticating through (more advanced)

### Security & Policy

- **Fine-Grained Authorization (UMA/Policies)** — Complex permission models beyond basic roles
- **Client Policies** — Enforce security standards (require PKCE, etc.) across all OIDC clients

### Self-Service

- **Account Console Theming** — Users self-manage credentials, MFA, sessions via Keycloak's built-in account UI

> **Clarification on Mappers vs Auto-Assignment:**
>
> - **Mappers** = outbound, tell the app about the user (token includes group info)
> - **Auto-assignment** = inbound, put user in group on registration/login (requires flow customization or API call)

---

## Success Metrics

- **MCP works locally** — Agent can list users, describe auth flows, make changes
- **CLI covers Tier 1 operations** — Every MCP operation is testable via CLI
- **Auth flow debugging is conversational** — Can ask agent "why is WebAuthn failing" and get actionable answers
- **Foundation for web UI** — Service layer is clean enough to expose via SvelteKit routes

---

## Document Status

**Status:** ✅ Approved
**Approved By:** Master Dorje
**Approved Date:** 2025-11-30

---

_This Product Brief captures the vision for keycloak-commander — IdentiKey's identity platform admin interface._

_Related: [PRD](./prd.md) details the specific requirements (55 FRs, 13 NFRs)._
_Next: Architecture workflow for technical design, then epic breakdown for implementation._
