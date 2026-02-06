# Story 3.1: AppService Core Operations

**Status:** ready-for-dev  
**Epic:** 3 - App Management  
**FR Coverage:** FR14-19 (Apps/Clients CRUD — PRD Future Backlog)  
**Story Key:** 3-1-appservice-core-operations

---

## Story

As a **developer/administrator**,  
I want **core CRUD operations for OIDC apps (Keycloak clients)** exposed through a dedicated service layer,  
So that **IdentiKey can manage client applications consistently and MCP/CLI can consume the same API**.

---

## Acceptance Criteria

### AC1: List Apps
- [ ] `AppService.list(options?)` returns apps (OIDC clients) with pagination
- [ ] Supports `max` and `offset` (first) per existing `ListOptions` pattern
- [ ] Results are IdentiKey domain type `App[]`, not raw Keycloak representation
- [ ] Optional filter by `clientId` (Keycloak `clientId` field) when provided

### AC2: Get App by ID
- [ ] `AppService.get(id)` returns a single app by Keycloak client UUID
- [ ] Throws typed error (e.g. `APP_NOT_FOUND`) when client does not exist
- [ ] Returns domain type `App` with fields needed for admin use (id, clientId, name, enabled, protocol, redirectUris, etc.)

### AC3: Create App
- [ ] `AppService.create(data: CreateAppInput)` creates an OIDC client in Keycloak
- [ ] Required: `clientId` (unique logical ID). Optional: name, description, enabled, protocol, redirectUris, webOrigins, publicClient, standardFlowEnabled, directAccessGrantsEnabled, etc.
- [ ] Returns created `App` including Keycloak-generated UUID
- [ ] Throws on duplicate `clientId` or invalid input with appropriate error code

### AC4: Update App
- [ ] `AppService.update(id, data: UpdateAppInput)` updates an existing client
- [ ] All update fields optional (partial update). No overwriting of unspecified fields with null unless explicitly provided
- [ ] Throws `APP_NOT_FOUND` if id does not exist

### AC5: Delete App
- [ ] `AppService.delete(id)` removes the client from the realm
- [ ] Throws `APP_NOT_FOUND` if id does not exist
- [ ] Idempotent: no error if already deleted (or document one-time behaviour per Keycloak API)

### AC6: Client Secret (Confidential Clients)
- [ ] `AppService.getSecret(id)` returns the client secret for confidential clients (if any)
- [ ] Throws or returns null/undefined for public clients or when no secret (per product decision)
- [ ] `AppService.regenerateSecret(id)` generates a new client secret and returns it (Keycloak `generateNewClientSecret`)
- [ ] Secrets never logged; use existing credential-handling patterns from UserService

---

## Tasks / Subtasks

- [ ] **Task 1: Domain types and errors** (AC: all)
  - [ ] Add `App`, `CreateAppInput`, `UpdateAppInput` to `src/lib/keycloak/types.ts` (or dedicated types file)
  - [ ] Add `APP_NOT_FOUND`, `INVALID_INPUT` (if not already) to `ErrorCodes` in `src/lib/keycloak/errors.ts`

- [ ] **Task 2: Client mapper** (AC: 1, 2, 3, 4)
  - [ ] Create `src/lib/keycloak/mappers/clients.ts`: `mapKeycloakClient` (ClientRepresentation → App), `toKeycloakCreate`, `toKeycloakUpdate`

- [ ] **Task 3: AppService implementation** (AC: 1–6)
  - [ ] Create `src/lib/keycloak/services/clients.ts` (or `apps.ts`) implementing list, get, create, update, delete, getSecret, regenerateSecret using `this.client.clients.*`
  - [ ] Use Keycloak `ClientQuery` (clientId, first, max) for list; wrap all KC errors in `IdentiKeyError`

- [ ] **Task 4: Wire into service index** (AC: all)
  - [ ] Export `AppService` and `getAppService()` from `src/lib/keycloak/services/index.ts` (same pattern as UserService, AuthFlowService)

- [ ] **Task 5: Unit tests** (AC: all)
  - [ ] Add `src/lib/keycloak/services/clients.spec.ts` (or apps.spec.ts): list, get, create, update, delete, getSecret, regenerateSecret with mocked Keycloak client

---

## Dev Notes

### Architecture Constraints
- **ADR-002:** Expose IdentiKey domain concepts; map Keycloak "Client" to "App" in API and types. Internal code may still use Keycloak client terminology where it clarifies (e.g. clientId).
- **Service-first:** AppService is the single source of truth; no direct `client.clients.*` calls from MCP or CLI. MCP and CLI (stories 3.2, 3.3) will call AppService only.
- **Realm:** Operations use the configured realm (e.g. `identikey`); no realm parameter in public API unless we explicitly add multi-realm later.
- **Errors:** Use `IdentiKeyError` and existing logger; never log secrets.

### Keycloak API Reference
- List: `client.clients.find({ first, max, clientId?, search?, q? })` → `ClientRepresentation[]`
- Get: `client.clients.findOne({ id })` → `ClientRepresentation | undefined`
- Create: `client.clients.create(payload)` → `{ id: string }` then findOne to return full App
- Update: `client.clients.update({ id }, payload)`
- Delete: `client.clients.del({ id })`
- Secret: `client.clients.getClientSecret({ id })`, `client.clients.generateNewClientSecret({ id })` → `CredentialRepresentation` (e.g. `value`)

### Project Structure Notes
- Mirror `UserService` and `AuthFlowService`: same directory `src/lib/keycloak/services/`, same client injection, same error wrapping.
- Types: either extend `src/lib/keycloak/types.ts` or add `src/lib/keycloak/types/clients.ts` and re-export from types index.
- Mappers: same pattern as `mappers/users.ts`; keep Keycloak field names in mapper, domain names in App/CreateAppInput/UpdateAppInput.

### Developer Context (Guardrails)
- **Do not** add new transport layers (MCP/CLI) in this story; those are 3.2 and 3.3. Only the service layer and types/mappers.
- **Do not** expose Keycloak-specific types (`ClientRepresentation`) outside the mapper. Public API uses `App`, `CreateAppInput`, `UpdateAppInput`.
- **Do not** log or serialize client secrets; follow the same discipline as UserService credential handling.
- **Reuse** `ListOptions` from `src/lib/keycloak/types.ts`; reuse `IdentiKeyError` and `ErrorCodes` from `src/lib/keycloak/errors.ts`. Add only `APP_NOT_FOUND` (and `INVALID_INPUT` if missing).
- Keycloak `client.clients` is the only backend; no REST calls or alternate clients.

### Testing Requirements
- Unit tests with mocked `KcAdminClient`: stub `client.clients.find`, `findOne`, `create`, `update`, `del`, `getClientSecret`, `generateNewClientSecret`.
- Cover: list (empty + pagination), get (found / not found), create (success + duplicate clientId), update (success / not found), delete (success / not found), getSecret / regenerateSecret for confidential client.
- No integration tests required in this story (no live Keycloak). Follow existing pattern from `users.spec.ts` and `auth-flows.spec.ts`.

### Project Context Reference
- **project_context:** See `**/project-context.md` if present; otherwise architecture.md + tech-spec-epic-2.md define patterns.
- **Realm:** IdentiKey uses realm `identikey` (config-driven). AppService uses the same Keycloak client singleton as UserService (realm set at client init).

### Story Completion Status
- **Status:** ready-for-dev  
- **Completion note:** Ultimate context engine analysis completed — comprehensive developer guide created. Epic 3 (App Management) first story; no previous story in this epic. Pattern mirrors Epic 2 UserService.

---

## Dev Agent Record

### Agent Model Used

{{agent_model_name_version}}

### Debug Log References

### Completion Notes List

### File List
