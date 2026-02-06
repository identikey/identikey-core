# Tech Spec — Epic 5: Login Flow Administration

**Date:** 2025-12-01
**Epic:** Login Flow Administration (FR34-41)
**Status:** Contexted

---

## Overview

Epic 5 implements the PRIMARY use case for keycloak-commander: debugging and configuring authentication flows. This enables admins to investigate "why did login fail?", view flow configurations, and modify authentication steps—critical for debugging WebAuthn and conditional auth.

---

## Keycloak API Context

### Authentication Management API

Keycloak's `authenticationManagement` resource handles all flow operations:

```typescript
// List flows
client.authenticationManagement.getFlows();

// Get executions (steps) for a flow
client.authenticationManagement.getExecutions({ flow: 'browser' });

// Add execution to flow
client.authenticationManagement.addExecution({
  flow: 'browser',
  provider: 'auth-otp-form'
});

// Update execution (change requirement)
client.authenticationManagement.updateExecution({
  flow: 'browser'
}, execution);

// Copy flow
client.authenticationManagement.copyFlow({
  flow: 'browser'
}, { newName: 'browser-custom' });

// Delete execution
client.authenticationManagement.delExecution({ id: executionId });
```

### Flow Structure

```
Login Flow (e.g., "browser")
├── Execution: Cookie (ALTERNATIVE)
├── Execution: Identity Provider Redirector (ALTERNATIVE)
└── Subflow: forms (ALTERNATIVE)
    ├── Execution: Username Password Form (REQUIRED)
    └── Subflow: conditional-otp (CONDITIONAL)
        ├── Execution: Condition - User Configured (REQUIRED)
        └── Execution: OTP Form (REQUIRED)
```

### Key Concepts

| Concept         | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| **Flow**        | Top-level authentication flow (browser, direct-grant, etc.)  |
| **Execution**   | A single authenticator step in a flow                        |
| **Subflow**     | Nested flow within a parent flow                             |
| **Requirement** | REQUIRED, ALTERNATIVE, CONDITIONAL, DISABLED                 |
| **Provider**    | Authenticator implementation (e.g., `auth-otp-form`)         |
| **Binding**     | Maps flow to auth type (browser, direct-grant, registration) |

### Execution Hierarchy

Executions have a `level` and `index` that determine nesting:

- `level: 0` = top-level execution
- `level: 1` = child of subflow at level 0
- `index` = position within that level

---

## IdentiKey Domain Types

```typescript
// src/lib/keycloak/types.ts additions

export interface LoginFlow {
  id: string;
  alias: string;           // Display name
  description?: string;
  providerId: string;      // e.g., "basic-flow"
  topLevel: boolean;
  builtIn: boolean;
}

export interface FlowExecution {
  id: string;
  displayName: string;
  requirement: 'REQUIRED' | 'ALTERNATIVE' | 'CONDITIONAL' | 'DISABLED';
  configurable: boolean;
  providerId?: string;
  level: number;           // Nesting depth
  index: number;           // Position at this level
  authenticationFlow: boolean;  // True if this is a subflow
}

export type FlowBindingType =
  | 'browser'
  | 'direct-grant'
  | 'registration'
  | 'reset-credentials'
  | 'docker-auth';
```

---

## Service Interface

```typescript
// src/lib/keycloak/services/auth-flows.ts

export class AuthFlowService {
  constructor(private client: KcAdminClient) {}

  // FR34: List all login flows
  async list(): Promise<LoginFlow[]>

  // FR35: Get flow details
  async get(flowAlias: string): Promise<LoginFlow>

  // FR36: List executions (steps) within a flow
  async listExecutions(flowAlias: string): Promise<FlowExecution[]>

  // FR37: Add execution to flow
  async addExecution(flowAlias: string, provider: string, requirement?: string): Promise<FlowExecution>

  // FR38: Remove execution from flow
  async removeExecution(flowAlias: string, executionId: string): Promise<void>

  // FR39: Reorder executions (raise/lower priority)
  async raiseExecutionPriority(flowAlias: string, executionId: string): Promise<void>
  async lowerExecutionPriority(flowAlias: string, executionId: string): Promise<void>

  // FR40: Copy flow
  async copy(sourceAlias: string, newAlias: string): Promise<LoginFlow>

  // FR41: Set default flow binding
  async setDefault(flowAlias: string, bindingType: FlowBindingType): Promise<void>

  // Helper: Update execution requirement
  async updateExecutionRequirement(
    flowAlias: string,
    executionId: string,
    requirement: string
  ): Promise<FlowExecution>
}
```

---

## MCP Tools

| Tool                           | Description                     | Input                                     |
| ------------------------------ | ------------------------------- | ----------------------------------------- |
| `list_login_flows`             | List all authentication flows   | `{}`                                      |
| `get_login_flow`               | Get flow details                | `{ flowAlias }`                           |
| `list_flow_executions`         | List steps in a flow            | `{ flowAlias }`                           |
| `add_flow_execution`           | Add authenticator to flow       | `{ flowAlias, provider, requirement? }`   |
| `remove_flow_execution`        | Remove authenticator            | `{ flowAlias, executionId }`              |
| `update_execution_requirement` | Change REQUIRED/ALTERNATIVE/etc | `{ flowAlias, executionId, requirement }` |
| `copy_login_flow`              | Create copy of flow             | `{ sourceAlias, newAlias }`               |
| `set_default_login_flow`       | Set as default for binding      | `{ flowAlias, bindingType }`              |

---

## CLI Commands

```
kc auth-flows list [--json]
kc auth-flows get <alias> [--json]
kc auth-flows executions <alias> [--json]
kc auth-flows add <alias> --provider <p> [--requirement REQUIRED|ALTERNATIVE|CONDITIONAL|DISABLED]
kc auth-flows remove <alias> <executionId> [--force]
kc auth-flows copy <sourceAlias> <newAlias>
kc auth-flows set-default <alias> --binding <browser|direct-grant|registration|reset-credentials>
```

---

## Execution Display Format

For CLI table output, show hierarchy with indentation:

```
EXECUTIONS for "browser":

  ID                                    NAME                          REQUIREMENT    LEVEL
  ────────────────────────────────────────────────────────────────────────────────────────
  exec-1                                Cookie                        ALTERNATIVE    0
  exec-2                                Identity Provider Redirector  ALTERNATIVE    0
  exec-3                                forms                         ALTERNATIVE    0
    exec-4                              Username Password Form        REQUIRED       1
    exec-5                              conditional-otp               CONDITIONAL    1
      exec-6                            Condition - User Configured   REQUIRED       2
      exec-7                            OTP Form                      REQUIRED       2
```

---

## Error Handling

```typescript
// New error codes for auth flows
AUTH_FLOW_NOT_FOUND: 'AUTH_FLOW_NOT_FOUND',
EXECUTION_NOT_FOUND: 'EXECUTION_NOT_FOUND',
FLOW_IS_BUILTIN: 'FLOW_IS_BUILTIN',  // Can't modify built-in flows
INVALID_PROVIDER: 'INVALID_PROVIDER'
```

---

## Stories

| Story | Description                     | FRs           |
| ----- | ------------------------------- | ------------- |
| 5-1   | AuthFlowService Core Operations | FR34-36, FR40 |
| 5-2   | Login Flow MCP Tools            | FR49-51       |
| 5-3   | Login Flow CLI Commands         | FR52-55       |
| 5-4   | Execution Modification          | FR37-39       |
| 5-5   | Flow Copy & Defaults            | FR40-41       |

---

## Implementation Notes

1. **Built-in flows are read-only** — Keycloak prevents modification. Copy first, then modify.

2. **Execution hierarchy** — The `level` field from Keycloak determines nesting. Display with indentation.

3. **Provider discovery** — Use `authenticationManagement.getFormProviders()` to list available authenticators.

4. **Reordering** — Keycloak uses raise/lower priority, not absolute positioning. For "reorder to position X", may need multiple calls.

5. **Binding update** — Setting default updates realm settings, not the flow itself.

---

## References

- [Keycloak Admin REST API — Authentication Management](https://www.keycloak.org/docs-api/latest/rest-api/index.html#_authentication_management_resource)
- `docs/epics.md` — Epic 5 stories
- `docs/architecture.md` — Service patterns
