# Story 8.4: Bootstrap User Provisioning

**Status:** ready-for-dev
**Epic:** 8 - Bootstrap Verification
**FR Coverage:** FR100, FR104, FR105, FR109
**Story Key:** 8-4-bootstrap-user-provisioning

---

## Story

As a **new user**,
I want **my IdentiKey account created from social sign in**,
So that **I can use the app** and proceed to passkey enrollment (Epic 9) via provision endpoints (Epic 10).

---

## Acceptance Criteria

### AC1: Find Existing User by Provider Sub
- On receiving a verified Apple or Google token payload, search Keycloak for an existing user by the provider's `sub` identifier stored as a user attribute.
- For Apple: search by attribute `apple_sub` matching the payload's `sub`.
- For Google: search by attribute `google_sub` matching the payload's `sub`.
- Use `client.users.find({ q: 'apple_sub:<value>', exact: true })` (Keycloak Admin API `q` parameter for attribute search).
- If found, return the existing user's ID. Do not create a duplicate.

### AC2: Create New User in Keycloak
- If no existing user is found, create a new user in Keycloak via the Admin API.
- Set user fields: `username` (generated from provider + sub), `email` (from payload, if available), `firstName` (from Google's `name` or omit for Apple), `enabled: true`, `emailVerified` (from payload, if available).
- Store the provider `sub` as a user attribute: `attributes: { apple_sub: [payload.sub] }` or `attributes: { google_sub: [payload.sub] }`.
- Return the newly created user's ID.

### AC3: Handle Apple Private Relay Emails
- If `is_private_email` is true in the Apple payload, store the relay email as-is (format: `random@privaterelay.appleid.com`). It is the user's valid contact method through Apple's relay.
- If email is absent (Apple subsequent auth), do not overwrite an existing user's email.

### AC4: Idempotent Provisioning
- Re-provisioning with the same provider `sub` returns the same user ID — no new user created.
- If a user was previously provisioned via Apple and later provisions via Google (same email), these are treated as separate lookup paths. A user can have both `apple_sub` and `google_sub` attributes.
- If an existing user is found but is missing email/name (e.g., Apple first-auth was interrupted), update the user's profile with newly available data from the token payload.

### AC5: Structured Result Type
- Return a typed `ProvisionResult` containing: `userId: string`, `isNewUser: boolean`, `email?: string`, `provider: 'apple' | 'google'`.
- Callers (Epic 10 endpoints) use `userId` to generate WebAuthn challenges and `isNewUser` for flow decisions.

### AC6: Error Handling
- On Keycloak connection failure: throw `IdentiKeyError` with `CONNECTION_FAILED`.
- On 409 conflict (race condition creating duplicate): retry lookup by attribute before failing.
- On token payload missing `sub`: throw descriptive error (should not happen if 8.2/8.3 verified successfully, but guard defensively).
- All errors are typed (`IdentiKeyError` or `BootstrapProvisionError`).

---

## Tasks / Subtasks

- [ ] **Task 1: BootstrapService module** (AC: 1-6)
  - [ ] Create `src/lib/auth/bootstrap/provision.ts`.
  - [ ] Define `ProvisionResult` interface: `{ userId: string; isNewUser: boolean; email?: string; provider: 'apple' | 'google' }`.
  - [ ] Define `BootstrapProvisionError` class extending `Error` with a `code` field (e.g., `PROVISION_FAILED`, `USER_LOOKUP_FAILED`, `USER_CREATE_FAILED`).
  - [ ] Implement `provisionUser(provider: 'apple' | 'google', payload: AppleTokenPayload | GoogleTokenPayload): Promise<ProvisionResult>`.
  - [ ] Get the Keycloak Admin Client via `getKeycloakClient()` from `src/lib/keycloak/client.ts`.

- [ ] **Task 2: User lookup by attribute** (AC: 1, 4)
  - [ ] Implement `findUserByProviderSub(client: KcAdminClient, provider: 'apple' | 'google', sub: string): Promise<UserRepresentation | null>`.
  - [ ] Use `client.users.find({ q: '${attributeKey}:${sub}', exact: true })` where `attributeKey` is `apple_sub` or `google_sub`.
  - [ ] If multiple users returned (should not happen), log a warning and use the first result.
  - [ ] Return `null` if no user found.

- [ ] **Task 3: User creation with attributes** (AC: 2, 3)
  - [ ] Implement `createProvisionedUser(client: KcAdminClient, provider: 'apple' | 'google', payload: AppleTokenPayload | GoogleTokenPayload): Promise<string>` (returns user ID).
  - [ ] Generate username: `${provider}_${payload.sub.substring(0, 20)}` (provider prefix ensures uniqueness across providers; truncate sub for readability).
  - [ ] Call `client.users.create({ username, email, firstName, enabled: true, emailVerified, attributes: { [attributeKey]: [payload.sub] } })`.
  - [ ] Extract user ID from create response (Keycloak returns it in the `Location` header, parsed by the admin client).
  - [ ] On 409 conflict: retry `findUserByProviderSub` (race condition — another request created the user first). If found, return that user's ID. If still not found, throw `BootstrapProvisionError`.

- [ ] **Task 4: Profile update for existing users** (AC: 3, 4)
  - [ ] If existing user found and payload has email but user doesn't → update email via `client.users.update()`.
  - [ ] If existing user found and payload has name but user doesn't → update firstName.
  - [ ] Do NOT overwrite existing email/name with empty/undefined values.
  - [ ] If existing user was provisioned via Apple and now provisions via Google (different provider), add the new provider's `sub` as an additional attribute.

- [ ] **Task 5: Barrel exports** (AC: all)
  - [ ] Create `src/lib/auth/bootstrap/index.ts` — export `provisionUser`, `ProvisionResult`, `BootstrapProvisionError`.
  - [ ] Update `src/lib/auth/index.ts` — add re-exports for bootstrap provisioning.

- [ ] **Task 6: Tests** (AC: all)
  - [ ] Create `src/lib/auth/bootstrap/provision.spec.ts`.
  - [ ] Mock `getKeycloakClient()` to return a mock `KcAdminClient` with `users.find`, `users.create`, `users.update`, `users.findOne` mocks.
  - [ ] **New user tests:** (1) Apple new user creates with `apple_sub` attribute. (2) Google new user creates with `google_sub` attribute and name. (3) Verify `isNewUser: true` returned. (4) Verify username format.
  - [ ] **Existing user tests:** (5) Apple returning user found by attribute, returns same ID. (6) Google returning user found, returns same ID. (7) Verify `isNewUser: false` returned.
  - [ ] **Profile update tests:** (8) Existing user missing email gets updated. (9) Existing user WITH email is NOT overwritten. (10) Apple user who also has Google adds `google_sub` attribute.
  - [ ] **Apple private relay tests:** (11) Private relay email stored as-is. (12) Missing email on subsequent auth doesn't clear existing email.
  - [ ] **Error tests:** (13) Keycloak connection failure throws appropriate error. (14) 409 conflict triggers retry and succeeds. (15) Missing `sub` in payload throws error.
  - [ ] **Idempotency tests:** (16) Multiple provisions with same sub return same user ID.

---

## Dev Notes

### Architecture Constraints
- **Bootstrap only:** This story provisions users — it does NOT generate WebAuthn challenges (that's Epic 9) or issue tokens (that's Epic 10). The `/apple-provision` and `/google-provision` endpoints in Epic 10 will orchestrate: verify token (8.2/8.3) → provision user (8.4) → generate challenge (9.2).
- **Keycloak as user store:** Per ADR-005, users are stored in Keycloak via Admin API. Do NOT create a separate user database.
- **Social login is NOT a Keycloak IDP:** Per ADR-008, we verify social tokens directly and create users via Admin API. Do NOT configure Apple/Google as Keycloak Identity Providers.
- **Service-first architecture:** Per ADR-001, create a reusable service layer function. The function should be usable from both future HTTP endpoints (Epic 10) and potentially from CLI/MCP tools.

### Keycloak User Attributes — Critical Implementation Details
- **Storage format:** Attributes are `Record<string, string[]>` — values are ALWAYS arrays, even for single values. Use `{ apple_sub: [payload.sub] }` not `{ apple_sub: payload.sub }`.
- **Attribute search API:** Use the `q` query parameter: `client.users.find({ q: 'apple_sub:value', exact: true })`. The `q` parameter searches custom attributes. Available since Keycloak 15+.
- **Case insensitivity:** Keycloak attribute search is case-insensitive even with `exact: true`. Since provider `sub` values are case-sensitive identifiers, this should work fine (Apple subs are unique strings, Google subs are numeric).
- **Reading attributes:** When you call `client.users.find()` or `client.users.findOne()`, the returned `UserRepresentation` includes `attributes: Record<string, string[]>`. Access via `user.attributes?.apple_sub?.[0]`.
- **Performance:** Attribute search uses the Keycloak `USER_ATTRIBUTE` table. Fine for this use case — bootstrap provisioning is an infrequent operation (once per user per provider).

### Previous Stories Intelligence

#### Story 8.2 (Apple Token Verification) — done
- Delivers: `verifyAppleToken()` returning `AppleTokenPayload { sub, email?, email_verified?, is_private_email? }`
- Apple `sub` is stable, unique per user per app
- Email only on first auth — `email` may be `undefined` on subsequent tokens
- `is_private_email` indicates Apple private relay
- Import from `src/lib/auth/apple`

#### Story 8.3 (Google Token Verification) — ready-for-dev
- Delivers: `verifyGoogleToken()` returning `GoogleTokenPayload { sub, email?, email_verified?, name?, picture? }`
- Google `sub` is stable, unique per user
- Google provides profile claims on EVERY token (unlike Apple)
- Import from `src/lib/auth/google`

#### Story 8.1 (Provider JWKS) — done
- Delivers: `getAppleJwkSet()`, `getGoogleJwkSet()` — consumed by 8.2/8.3, not directly by 8.4

### Existing UserService API (from Epic 2)
- **Location:** `src/lib/keycloak/services/users.ts`
- **`UserService.create(data: CreateUserInput)`** — Creates user but does NOT support attributes. The `CreateUserInput` type only has `username`, `email`, `firstName`, `lastName`, `enabled`.
- **`UserService.search(query: string)`** — Searches by username/email/name. Does NOT support attribute search.
- **`UserService.get(id: string)`** — Gets user by ID. Returns `User` domain type (no attributes exposed).
- **Conclusion:** Do NOT use `UserService` for 8.4. Use the raw `KcAdminClient` directly from `getKeycloakClient()` because 8.4 needs attribute-aware create and search. The existing `UserService` is designed for admin tooling (Epic 2) and doesn't expose attributes.

### Keycloak Client Access Pattern
- **Factory:** `getKeycloakClient()` from `src/lib/keycloak/client.ts` — returns singleton `KcAdminClient`.
- **Auth:** Uses `client_credentials` grant. Client is created once and cached.
- **User operations:**
  - `client.users.find({ q: '...', exact: true })` — returns `UserRepresentation[]`
  - `client.users.create({ username, email, ..., attributes })` — returns `{ id: string }`
  - `client.users.update({ id }, { attributes, email, ... })` — void
  - `client.users.findOne({ id })` — returns `UserRepresentation | undefined`

### Error Handling Patterns
- **Keycloak errors:** Use `IdentiKeyError` from `src/lib/keycloak/errors.ts` with `ErrorCodes` (CONNECTION_FAILED, UNAUTHORIZED, INVALID_INPUT).
- **Auth errors:** `TokenVerificationError` from `src/lib/auth/errors.ts` — for token-related failures (not used in 8.4 directly; 8.2/8.3 handle verification).
- **New for 8.4:** Create `BootstrapProvisionError` in `src/lib/auth/bootstrap/provision.ts` or in `src/lib/auth/errors.ts`. Keep it simple — `code` field with provision-specific codes.
- **Pattern:** Try operation → catch → check if already domain error (rethrow) → wrap with descriptive message.

### Failure Handling (from Architecture Doc)
- **Provision success, passkey failure:** User exists in Keycloak with `apple_sub`/`google_sub` attribute but no passkey. Recovery: user retries social sign-in → finds existing user → returns fresh challenge. This is why idempotency is critical.
- **Idempotent endpoints:** The provision functions are designed to be safe to call multiple times with the same social identity.

### Project Structure Notes
- **New files:**
  - `src/lib/auth/bootstrap/provision.ts` — Main provisioning service
  - `src/lib/auth/bootstrap/provision.spec.ts` — Tests
  - `src/lib/auth/bootstrap/index.ts` — Barrel exports
- **Modified files:**
  - `src/lib/auth/index.ts` — Add bootstrap re-exports
- **No HTTP endpoints.** This is a library consumed by Epic 10 provision endpoints.

### Username Generation Strategy
- Format: `${provider}_${sub.substring(0, 20)}` — e.g., `apple_001234.abcdef12345` or `google_12345678901234567890`
- Provider prefix ensures uniqueness across providers
- Truncation for readability (full `sub` is in attributes)
- Must be unique — Keycloak enforces unique usernames
- If 409 conflict on create, retry attribute lookup (race condition)

### References
- [Source: _bmad-output/planning-artifacts/epics.md#8.4] — AC and technical notes
- [Source: _bmad-output/planning-artifacts/architecture.md#Failure Handling] — idempotent provisioning, partial failure recovery
- [Source: _bmad-output/planning-artifacts/architecture.md#Bootstrap Flow Pattern] — verify → create/find → challenge → passkey
- [Source: _bmad-output/planning-artifacts/architecture.md#Integration Points: Keycloak Admin API] — user CRUD, attributes
- [Source: _bmad-output/planning-artifacts/architecture.md#ADR-005] — Keycloak as user store
- [Source: _bmad-output/planning-artifacts/architecture.md#ADR-008] — social login as bootstrap only
- [Source: src/lib/keycloak/client.ts] — getKeycloakClient() singleton
- [Source: src/lib/keycloak/services/users.ts] — UserService (for reference, not used directly)
- [Source: src/lib/keycloak/errors.ts] — IdentiKeyError, ErrorCodes
- [Source: src/lib/keycloak/types.ts] — User, CreateUserInput domain types
- [Source: src/lib/auth/apple/verify.ts] — AppleTokenPayload type
- [Source: src/lib/auth/google/verify.ts] — GoogleTokenPayload type
- [Source: Keycloak Admin API Docs] — `q` parameter for attribute search, `attributes` field on UserRepresentation

### Developer Context (Guardrails)
- **Do not** use `UserService` from `src/lib/keycloak/services/users.ts`. It doesn't support attributes. Use `getKeycloakClient()` directly.
- **Do not** generate WebAuthn challenges. That's Epic 9 (not built yet). Return `userId` and `isNewUser` only.
- **Do not** issue tokens. That's Epic 10's responsibility.
- **Do not** add HTTP endpoints. This is a library function consumed by Epic 10 endpoints.
- **Do not** configure Apple/Google as Keycloak IDPs. We verify tokens directly (ADR-008).
- **Do** handle the 409 conflict race condition gracefully (retry lookup after failed create).
- **Do** store attributes as arrays: `{ apple_sub: [value] }` not `{ apple_sub: value }`.
- **Do** handle missing email gracefully (Apple subsequent auth). Never overwrite existing email with undefined.
- **Run tests with:** `bun vitest` (per CLAUDE.md).

### Testing Requirements
- Unit tests with mocked `KcAdminClient`. Mock `users.find`, `users.create`, `users.update`, `users.findOne`.
- Cover: new Apple user, new Google user, existing Apple user, existing Google user, profile update, private relay, 409 conflict retry, idempotency, missing sub, connection failure.
- Expected: ~16 tests.

### Story Completion Status
- **Status:** ready-for-dev
- **Completion note:** Ultimate context engine analysis completed. Consumes 8.2 (Apple verification) and 8.3 (Google verification). Uses `getKeycloakClient()` for direct Keycloak Admin API attribute operations. Feeds Epic 10 (provision endpoints) and Epic 9 (WebAuthn challenge generation on the provisioned user).

---

## Dev Agent Record

### Agent Model Used

{{agent_model_name_version}}

### Debug Log References

### Completion Notes List

### File List
