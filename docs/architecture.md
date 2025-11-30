# Architecture — keycloak-commander

**Author:** Master Dorje
**Date:** 2025-11-30
**Version:** 1.0

---

## Executive Summary

keycloak-commander is IdentiKey's administrative interface, abstracting Keycloak into IdentiKey domain concepts. The architecture follows a **service-first pattern**: a core TypeScript service layer wraps Keycloak Admin API, consumed by three interfaces — MCP server (AI agents), CLI (human testing), and Web UI (future SvelteKit dashboard).

---

## Project Initialization

SvelteKit is already scaffolded. Add dependencies:

```bash
# Core dependencies
bun add @keycloak/keycloak-admin-client @modelcontextprotocol/sdk citty zod pino

# Dev dependencies (if not present)
bun add -d dotenv
```

---

## Decision Summary

| Category        | Decision                        | Version | Affects         | Rationale                              |
| --------------- | ------------------------------- | ------- | --------------- | -------------------------------------- |
| Framework       | SvelteKit                       | 2.x     | Web UI          | Already scaffolded                     |
| Language        | TypeScript                      | 5.x     | All             | Type safety, Keycloak client types     |
| Keycloak Client | @keycloak/keycloak-admin-client | latest  | Core services   | Official client, full API coverage     |
| MCP SDK         | @modelcontextprotocol/sdk       | latest  | MCP server      | Official SDK, stdio transport          |
| CLI Framework   | citty                           | latest  | CLI             | Lightweight, modern, TypeScript-native |
| Validation      | Zod                             | 3.x     | All             | MCP schemas, input validation          |
| Logging         | Pino                            | latest  | Core services   | Structured JSON logs                   |
| Styling         | Tailwind CSS                    | 4.x     | Web UI          | Already scaffolded                     |
| Testing         | Vitest + Playwright             | latest  | All             | Already scaffolded                     |
| Database        | Drizzle + Postgres              | latest  | Web UI (future) | Already scaffolded                     |

---

## Project Structure

```
keycloak-commander/
├── src/
│   ├── lib/
│   │   ├── keycloak/                 # Core service layer
│   │   │   ├── client.ts             # Keycloak client wrapper & auth
│   │   │   ├── config.ts             # Configuration loading
│   │   │   ├── errors.ts             # IdentiKey error types
│   │   │   ├── types.ts              # IdentiKey domain types
│   │   │   └── services/             # Domain services
│   │   │       ├── index.ts          # Service exports
│   │   │       ├── users.ts          # User operations
│   │   │       ├── apps.ts           # Client/App operations
│   │   │       ├── guilds.ts         # Group/Guild operations
│   │   │       ├── roles.ts          # Role operations
│   │   │       ├── auth-flows.ts     # Authentication flow operations
│   │   │       ├── sessions.ts       # Session operations
│   │   │       └── events.ts         # Event/audit operations
│   │   ├── server/                   # Existing server utilities
│   │   │   ├── auth.ts
│   │   │   └── db/
│   │   └── index.ts
│   ├── mcp/                          # MCP server entry point
│   │   ├── index.ts                  # MCP server main
│   │   ├── server.ts                 # McpServer setup
│   │   └── tools/                    # Tool definitions
│   │       ├── index.ts              # Register all tools
│   │       ├── users.ts              # User tools
│   │       ├── apps.ts               # App tools
│   │       ├── guilds.ts             # Guild tools
│   │       ├── roles.ts              # Role tools
│   │       ├── auth-flows.ts         # Auth flow tools
│   │       ├── sessions.ts           # Session tools
│   │       └── events.ts             # Event tools
│   ├── cli/                          # CLI entry point
│   │   ├── index.ts                  # CLI main (citty runMain)
│   │   ├── commands/                 # Command definitions
│   │   │   ├── users/
│   │   │   │   ├── index.ts          # users subcommand
│   │   │   │   ├── list.ts
│   │   │   │   ├── get.ts
│   │   │   │   ├── create.ts
│   │   │   │   └── ...
│   │   │   ├── apps/
│   │   │   ├── guilds/
│   │   │   ├── roles/
│   │   │   ├── auth-flows/
│   │   │   ├── sessions/
│   │   │   └── events/
│   │   └── utils/                    # CLI utilities
│   │       ├── output.ts             # Table/JSON formatters
│   │       └── prompts.ts            # Interactive prompts (future TUI)
│   ├── routes/                       # SvelteKit routes (future Web UI)
│   │   ├── +layout.svelte
│   │   └── +page.svelte
│   └── app.html
├── docs/
│   ├── product-brief-keycloak-commander-2025-11-30.md
│   ├── prd.md
│   └── architecture.md               # This file
├── package.json
├── svelte.config.js
├── vite.config.ts
├── tsconfig.json
└── .env.example                      # Environment template
```

---

## FR Category to Architecture Mapping

| FR Category             | Service                  | MCP Tools             | CLI Commands           |
| ----------------------- | ------------------------ | --------------------- | ---------------------- |
| Auth/Connection (FR1-4) | `client.ts`, `config.ts` | —                     | —                      |
| Users (FR5-13)          | `services/users.ts`      | `tools/users.ts`      | `commands/users/`      |
| Apps (FR14-19)          | `services/apps.ts`       | `tools/apps.ts`       | `commands/apps/`       |
| Guilds (FR20-27)        | `services/guilds.ts`     | `tools/guilds.ts`     | `commands/guilds/`     |
| Roles (FR28-33)         | `services/roles.ts`      | `tools/roles.ts`      | `commands/roles/`      |
| Login Flows (FR34-41)   | `services/auth-flows.ts` | `tools/auth-flows.ts` | `commands/auth-flows/` |
| Sessions (FR42-44)      | `services/sessions.ts`   | `tools/sessions.ts`   | `commands/sessions/`   |
| Events (FR45-48)        | `services/events.ts`     | `tools/events.ts`     | `commands/events/`     |
| MCP Interface (FR49-51) | —                        | `mcp/server.ts`       | —                      |
| CLI Interface (FR52-55) | —                        | —                     | `cli/index.ts`         |

---

## Technology Stack Details

### Core Technologies

**Keycloak Admin Client**

```typescript
import KcAdminClient from '@keycloak/keycloak-admin-client';

const client = new KcAdminClient({
  baseUrl: process.env.KEYCLOAK_URL,
  realmName: process.env.KEYCLOAK_REALM // always 'master'
});

await client.auth({
  username: process.env.KEYCLOAK_USERNAME,
  password: process.env.KEYCLOAK_PASSWORD,
  grantType: 'password',
  clientId: process.env.KEYCLOAK_CLIENT_ID // 'admin-cli'
});
```

**MCP Server (stdio)**

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const server = new McpServer({
  name: 'keycloak-commander',
  version: '1.0.0'
});

// Register tools...

const transport = new StdioServerTransport();
await server.connect(transport);
```

**CLI (citty)**

```typescript
import { defineCommand, runMain } from 'citty';

const main = defineCommand({
  meta: { name: 'kc', description: 'IdentiKey Admin CLI' },
  subCommands: {
    users: () => import('./commands/users'),
    apps: () => import('./commands/apps'),
    guilds: () => import('./commands/guilds'),
    // ...
  }
});

runMain(main);
```

### Integration Points

```
┌─────────────────────────────────────────────────────────────┐
│                 Keycloak Admin REST API                     │
│                 (https://auth.identikey.io)                 │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │ HTTPS
┌─────────────────────────────────────────────────────────────┐
│                    Keycloak Client                          │
│              (@keycloak/keycloak-admin-client)              │
│                                                             │
│  • Auth: password grant (admin credentials)                 │
│  • Realm: always 'master'                                   │
│  • Auto token refresh                                       │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │
┌─────────────────────────────────────────────────────────────┐
│                   Core Service Layer                        │
│                                                             │
│  UserService | AppService | GuildService | RoleService      │
│  AuthFlowService | SessionService | EventService            │
│                                                             │
│  • IdentiKey domain abstractions                            │
│  • Keycloak → IdentiKey terminology mapping                 │
│  • Structured error handling                                │
│  • Pino logging                                             │
└─────────────────────────────────────────────────────────────┘
           ▲                    ▲                    ▲
           │                    │                    │
┌──────────┴───────┐ ┌─────────┴─────────┐ ┌───────┴────────┐
│   MCP Server     │ │       CLI         │ │    Web UI      │
│   (stdio)        │ │     (citty)       │ │  (SvelteKit)   │
│                  │ │                   │ │                │
│ • AI agents      │ │ • Human testing   │ │ • Future       │
│ • Cursor         │ │ • Debugging       │ │ • Guild admin  │
│ • Zod schemas    │ │ • JSON/table out  │ │ • Self-service │
└──────────────────┘ └───────────────────┘ └────────────────┘
```

---

## IdentiKey Abstraction Layer

Map Keycloak concepts to IdentiKey terminology throughout the codebase:

| Keycloak Term       | IdentiKey Term       | Notes                          |
| ------------------- | -------------------- | ------------------------------ |
| Realm               | _(hidden)_           | Always `master`, never exposed |
| Client              | App                  | OIDC clients are "apps"        |
| Group               | Guild                | Organizational units           |
| Authentication Flow | Login Flow           | Auth flow config               |
| User Federation     | _(hidden)_           | Not exposed in MVP             |
| Protocol Mapper     | Token Claims         | If exposed later               |
| Client Scope        | _(hidden initially)_ | Future growth feature          |

**Type Mapping Example:**

```typescript
// src/lib/keycloak/types.ts

// IdentiKey domain types (what MCP/CLI expose)
export interface User {
  id: string;
  username: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  enabled: boolean;
  guilds: string[]; // mapped from groups
}

export interface App {
  id: string;
  name: string;       // mapped from clientId
  displayName?: string;
  enabled: boolean;
  publicClient: boolean;
  redirectUris: string[];
}

export interface Guild {
  id: string;
  name: string;
  path: string;
  memberCount?: number;
}
```

---

## Implementation Patterns

### Naming Conventions

| Thing         | Convention      | Example                              |
| ------------- | --------------- | ------------------------------------ |
| Files         | kebab-case      | `auth-flows.ts`                      |
| Classes/Types | PascalCase      | `UserService`, `IdentiKeyError`      |
| Functions     | camelCase       | `listUsers`, `getAuthFlow`           |
| CLI commands  | kebab-case      | `kc users list`, `kc auth-flows get` |
| MCP tools     | snake_case      | `list_users`, `get_auth_flow`        |
| Env vars      | SCREAMING_SNAKE | `KEYCLOAK_URL`                       |

### Service Layer Pattern

```typescript
// src/lib/keycloak/services/users.ts
import type KcAdminClient from '@keycloak/keycloak-admin-client';
import type { User, CreateUserInput, UpdateUserInput, ListOptions } from '../types';
import { IdentiKeyError } from '../errors';
import { mapKeycloakUser } from '../mappers';

export class UserService {
  constructor(private client: KcAdminClient) {}

  async list(options?: ListOptions): Promise<User[]> {
    const kcUsers = await this.client.users.find({
      search: options?.search,
      max: options?.max ?? 100,
      first: options?.offset ?? 0
    });
    return kcUsers.map(mapKeycloakUser);
  }

  async get(id: string): Promise<User> {
    const kcUser = await this.client.users.findOne({ id });
    if (!kcUser) throw new IdentiKeyError('User not found', 'USER_NOT_FOUND');
    return mapKeycloakUser(kcUser);
  }

  async create(data: CreateUserInput): Promise<User> {
    const { id } = await this.client.users.create({
      username: data.username,
      email: data.email,
      firstName: data.firstName,
      lastName: data.lastName,
      enabled: data.enabled ?? true
    });
    return this.get(id);
  }

  // ... update, delete, resetPassword, etc.
}
```

### MCP Tool Pattern

```typescript
// src/mcp/tools/users.ts
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { UserService } from '../../lib/keycloak/services/users';

const UserSchema = z.object({
  id: z.string(),
  username: z.string(),
  email: z.string().optional(),
  firstName: z.string().optional(),
  lastName: z.string().optional(),
  enabled: z.boolean(),
  guilds: z.array(z.string())
});

export function registerUserTools(server: McpServer, userService: UserService) {
  server.registerTool(
    'list_users',
    {
      title: 'List Users',
      description: 'List all users with optional search filter',
      inputSchema: {
        search: z.string().optional().describe('Search by username, email, name'),
        max: z.number().optional().describe('Max results (default 100)')
      },
      outputSchema: { users: z.array(UserSchema) }
    },
    async ({ search, max }) => {
      const users = await userService.list({ search, max });
      return {
        content: [{ type: 'text', text: JSON.stringify(users, null, 2) }],
        structuredContent: { users }
      };
    }
  );

  server.registerTool(
    'get_user',
    {
      title: 'Get User',
      description: 'Get detailed information for a specific user',
      inputSchema: { id: z.string().describe('User ID') },
      outputSchema: { user: UserSchema }
    },
    async ({ id }) => {
      const user = await userService.get(id);
      return {
        content: [{ type: 'text', text: JSON.stringify(user, null, 2) }],
        structuredContent: { user }
      };
    }
  );

  // ... more user tools
}
```

### CLI Command Pattern

```typescript
// src/cli/commands/users/list.ts
import { defineCommand } from 'citty';
import { getUserService } from '../../../lib/keycloak/services';
import { printTable, printJson } from '../../utils/output';

export default defineCommand({
  meta: {
    name: 'list',
    description: 'List users'
  },
  args: {
    search: {
      type: 'string',
      alias: 's',
      description: 'Search by username, email, or name'
    },
    max: {
      type: 'string', // citty uses string, parse to number
      alias: 'm',
      description: 'Max results'
    },
    json: {
      type: 'boolean',
      alias: 'j',
      description: 'Output as JSON'
    }
  },
  async run({ args }) {
    const userService = await getUserService();
    const users = await userService.list({
      search: args.search,
      max: args.max ? parseInt(args.max) : undefined
    });

    if (args.json) {
      printJson(users);
    } else {
      printTable(users, ['id', 'username', 'email', 'enabled']);
    }
  }
});
```

---

## Error Handling

```typescript
// src/lib/keycloak/errors.ts
export class IdentiKeyError extends Error {
  constructor(
    message: string,
    public code: string,
    public cause?: Error
  ) {
    super(message);
    this.name = 'IdentiKeyError';
  }
}

// Error codes
export const ErrorCodes = {
  USER_NOT_FOUND: 'USER_NOT_FOUND',
  APP_NOT_FOUND: 'APP_NOT_FOUND',
  GUILD_NOT_FOUND: 'GUILD_NOT_FOUND',
  AUTH_FLOW_NOT_FOUND: 'AUTH_FLOW_NOT_FOUND',
  UNAUTHORIZED: 'UNAUTHORIZED',
  CONNECTION_FAILED: 'CONNECTION_FAILED',
  INVALID_INPUT: 'INVALID_INPUT'
} as const;
```

---

## Logging Strategy

```typescript
// src/lib/keycloak/logger.ts
import pino from 'pino';

export const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  transport: process.env.NODE_ENV === 'development'
    ? { target: 'pino-pretty' }
    : undefined
});

// Usage in services
logger.info({ userId }, 'Fetching user');
logger.error({ err, userId }, 'Failed to fetch user');
```

**CLI output stays clean** — services log to pino, CLI formats user-facing output separately.

---

## Configuration

```bash
# .env.example
KEYCLOAK_URL=https://auth.identikey.io
KEYCLOAK_REALM=master
KEYCLOAK_CLIENT_ID=admin-cli
KEYCLOAK_USERNAME=admin
KEYCLOAK_PASSWORD=your-password

LOG_LEVEL=info
```

```typescript
// src/lib/keycloak/config.ts
import { z } from 'zod';

const ConfigSchema = z.object({
  keycloakUrl: z.string().url(),
  keycloakRealm: z.string().default('master'),
  keycloakClientId: z.string().default('admin-cli'),
  keycloakUsername: z.string(),
  keycloakPassword: z.string()
});

export function loadConfig() {
  return ConfigSchema.parse({
    keycloakUrl: process.env.KEYCLOAK_URL,
    keycloakRealm: process.env.KEYCLOAK_REALM,
    keycloakClientId: process.env.KEYCLOAK_CLIENT_ID,
    keycloakUsername: process.env.KEYCLOAK_USERNAME,
    keycloakPassword: process.env.KEYCLOAK_PASSWORD
  });
}
```

---

## Security Architecture

- **NFR1:** Credentials never logged — pino configured to redact sensitive fields
- **NFR2:** MCP server uses stdio only — no network exposure
- **NFR3:** CLI reads credentials from env vars, not command args
- **NFR4:** All Keycloak API calls over HTTPS (enforced by URL validation)

---

## Development Environment

### Prerequisites

- Node.js 20+ (or Bun)
- Access to IdentiKey Keycloak instance
- Admin credentials for Keycloak

### Setup Commands

```bash
# Clone and install
git clone <repo>
cd keycloak-commander
bun install

# Configure environment
cp .env.example .env
# Edit .env with your Keycloak credentials

# Run CLI
bun run src/cli/index.ts users list

# Run MCP server (for Cursor)
bun run src/mcp/index.ts

# Run Web UI dev server
bun run dev
```

### package.json Scripts (to add)

```json
{
	"scripts": {
		"cli": "bun run src/cli/index.ts",
		"mcp": "bun run src/mcp/index.ts",
		"dev": "vite dev"
	}
}
```

### Cursor MCP Configuration

Add to `.cursor/mcp.json`:

```json
{
	"mcpServers": {
		"keycloak-commander": {
			"command": "bun",
			"args": ["run", "src/mcp/index.ts"],
			"cwd": "/path/to/keycloak-commander"
		}
	}
}
```

---

## Architecture Decision Records (ADRs)

### ADR-001: Service-First Architecture

**Decision:** Core service layer independent of interfaces
**Rationale:** Enables code reuse across MCP, CLI, and Web UI without duplication
**Consequences:** Slight abstraction overhead, but maximizes maintainability

### ADR-002: IdentiKey Abstraction Over Keycloak

**Decision:** Hide Keycloak terminology, expose IdentiKey domain concepts
**Rationale:** Users shouldn't need to know it's Keycloak under the hood
**Consequences:** Mapping layer required, but cleaner API surface

### ADR-003: MCP as Primary Interface

**Decision:** Design for MCP-first, CLI for testing
**Rationale:** AI agents are the power users; CLI validates operations work
**Consequences:** MCP tool design drives service API shape

### ADR-004: citty for CLI

**Decision:** Use citty instead of Commander.js
**Rationale:** Lighter, modern TypeScript-native, fits unjs ecosystem
**Consequences:** Less ecosystem/examples, but simpler codebase

### ADR-005: Pino for Logging

**Decision:** Structured JSON logging with pino
**Rationale:** Fast, structured logs for debugging; CLI output stays clean
**Consequences:** Need pino-pretty for dev readability

---

## Document Status

**Status:** ✅ Approved
**Approved By:** Master Dorje
**Approved Date:** 2025-11-30

---

_Generated by BMAD Decision Architecture Workflow v1.0_
_This architecture ensures AI agents implement keycloak-commander consistently._
