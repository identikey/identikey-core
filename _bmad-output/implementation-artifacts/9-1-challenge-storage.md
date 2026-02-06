# Story 9.1: Challenge Storage

**Status:** done
**Epic:** 9 - Passkey Management
**FR Coverage:** FR110–118 (WebAuthn flow foundation)
**Story Key:** 9-1-challenge-storage

---

## Story

As the **auth system**,
I want **to store WebAuthn challenges temporarily**,
So that **I can validate registration and authentication responses** in Epic 9.2–9.5 and Epic 10 passkey endpoints.

---

## Acceptance Criteria

### AC1: PostgreSQL-Backed Challenge Table
- Add a `challenges` table to the Drizzle schema in `src/lib/server/db/schema.ts`.
- Columns: `id` (UUID primary key, default gen_random_uuid()), `user_id` (UUID/text, nullable — NULL for discoverable-credential auth flow), `challenge` (TEXT NOT NULL UNIQUE, base64-encoded), `type` (TEXT NOT NULL: `'registration'` or `'authentication'`), `expires_at` (TIMESTAMPTZ NOT NULL), `created_at` (TIMESTAMPTZ NOT NULL default now()).
- Use Drizzle types: `uuid()`, `text()`, `timestamp(..., { withTimezone: true, mode: 'date' })`. Match architecture doc schema; `user_id` stores Keycloak user ID (string).

### AC2: 5-Minute TTL
- When creating a challenge, set `expires_at = now() + 5 minutes`. No configurable TTL required in this story; 5 minutes is the product requirement (architecture: "WebAuthn challenges expire after 5 minutes").

### AC3: Create and Lookup by Challenge Value
- Provide a way to **create** a challenge: `createChallenge(params: { userId: string | null; challenge: string; type: 'registration' | 'authentication' })`. Insert row, return id or full row.
- Provide a way to **look up** a challenge by its raw `challenge` value (e.g. `getChallengeByValue(challenge: string)`). Return the row (id, user_id, challenge, type, expires_at, created_at) or null. Used by 9.3 and 9.5 to verify that the client response matches a challenge we issued.

### AC4: Delete After Use
- Provide a way to **delete** a challenge by id or by challenge value (e.g. `deleteChallenge(id: string)` or `deleteChallengeByValue(challenge: string)`). Registration (9.3) and authentication (9.5) must delete the challenge after successful verification so it cannot be reused.

### AC5: Clean Up Expired Challenges
- Expired challenges must not be returned from lookup (filter `expires_at > now()`). Option A: **on-read cleanup** — when returning a challenge from lookup, if it is expired, treat as not found (and optionally delete it in the same flow). Option B: **scheduled cleanup** — periodic job that deletes rows where `expires_at < now()`. Implementing **on-read** (expired = not found, optionally delete expired row when encountered) is sufficient for 9.1; document that a scheduled cleanup can be added later if needed for storage hygiene.
- Add an index on `expires_at` to support efficient cleanup queries (architecture: `idx_challenges_expires_at`).

### AC6: Migration
- Generate and apply a Drizzle migration for the new table and index. Use project scripts: `bun run db:generate`, then `bun run db:migrate` (or equivalent). Document in dev notes.

---

## Tasks / Subtasks

- [x] **Task 1: Drizzle schema** (AC: 1, 2)
  - [x] In `src/lib/server/db/schema.ts`, add `challenges` table with columns above. Use `pgTable`, `uuid`, `text`, `timestamp` from `drizzle-orm/pg-core`. Export inferred type, e.g. `Challenge`.
  - [x] Ensure `challenge` has unique constraint; set `expires_at` in application code on insert (now + 5 min).

- [x] **Task 2: Challenge service / repository** (AC: 3, 4, 5)
  - [x] Create `src/lib/server/challenges.ts` (or `src/lib/server/db/challenges.ts`) with: `createChallenge({ userId, challenge, type })`, `getChallengeByValue(challenge)`, `deleteChallenge(id)` and/or `deleteChallengeByValue(challenge)`.
  - [x] In `getChallengeByValue`: only return row where `expires_at > now()`. If row exists but expired, optionally delete it and return null (on-read cleanup).
  - [x] In `createChallenge`: compute `expires_at` as `new Date(Date.now() + 5 * 60 * 1000)`.

- [x] **Task 3: Index for cleanup** (AC: 5)
  - [x] Add index on `challenges.expires_at` in schema (Drizzle index definition) so future scheduled deletes are efficient. Include in same migration as table.

- [x] **Task 4: Migration** (AC: 6)
  - [x] Run `bun run db:generate` to generate migration for `challenges` table and index.
  - [x] Run `bun run db:migrate` (or apply migration) and verify table exists. Document in story/completion that migration was generated and applied.

- [x] **Task 5: Tests** (AC: all)
  - [x] Unit tests for challenge service: create then getByValue returns same row; getByValue returns null for unknown challenge; getByValue returns null for expired challenge (create with expires_at in past, or mock time); deleteByValue removes row; create enforces unique challenge (duplicate insert fails or is handled).

---

## Dev Notes

### Architecture Constraints
- **Challenges in PostgreSQL only:** Architecture states "No Redis needed — DB is fine for this volume." Use existing Drizzle + PostgreSQL setup.
- **Passkeys in Keycloak:** Passkey credentials (credentialId, publicKey, signCount) are stored in Keycloak via Admin API (Epic 9.3, 9.5, 9.6). This story is only about **challenge** storage, not credentials.
- **Same schema as architecture:** Align with `_bmad-output/planning-artifacts/architecture.md` "Database Schema" section (challenges table and idx_challenges_expires_at).

### Existing DB Setup
- **Schema:** `src/lib/server/db/schema.ts` — currently has `user` and `session` tables. Add `challenges` alongside; no need to change existing tables.
- **DB client:** `src/lib/server/db/index.ts` — exports `db` (Drizzle) and imports schema. New challenge functions can use `db` from here or receive it as dependency.
- **Config:** `drizzle.config.ts` uses `DATABASE_URL`. Migrations: `bun run db:generate`, `bun run db:migrate` (see package.json).

### Drizzle Conventions
- Use `uuid()` with `.defaultRandom()` for `id`. For `user_id` (Keycloak ID string), use `text('user_id')` and allow null.
- Timestamps: `timestamp('expires_at', { withTimezone: true, mode: 'date' }).notNull()`.
- Unique: `.unique()` on challenge column or unique constraint in table def.

### Downstream Consumption
- **9.2:** Registration challenge generation will call `createChallenge({ userId, challenge, type: 'registration' })` after generating the challenge bytes.
- **9.3:** After verifying attestation, will call `getChallengeByValue(challenge)` to confirm challenge matches, then `deleteChallenge(id)` or `deleteChallengeByValue(challenge)`.
- **9.4:** Auth challenge generation will call `createChallenge({ userId: null | string, challenge, type: 'authentication' })`.
- **9.5:** After verifying assertion, lookup and delete challenge same as 9.3.

### Project Structure Notes
- **New/updated:** `src/lib/server/db/schema.ts` (add challenges table + index), `src/lib/server/challenges.ts` or `src/lib/server/db/challenges.ts` (create/get/delete), migration file under project migration dir (e.g. `drizzle/`).
- **No** Keycloak or WebAuthn logic in this story — only persistence.

### References
- [Source: _bmad-output/planning-artifacts/epics.md#9.1] — AC and technical notes (Drizzle, 5 min TTL, no Redis).
- [Source: _bmad-output/planning-artifacts/architecture.md#Database Schema] — challenges table and idx_challenges_expires_at.
- [Source: src/lib/server/db/schema.ts] — existing Drizzle schema pattern.
- [Source: src/lib/server/db/index.ts] — db client.
- [Source: drizzle.config.ts] — Drizzle config and migrations.

### Developer Context (Guardrails)
- **Do not** implement WebAuthn option generation or verification (9.2–9.5). Only store and retrieve challenges.
- **Do not** add Redis or another store. PostgreSQL only.
- **Do** enforce unique challenge value (one active challenge per value).
- **Do** treat expired challenges as "not found" in lookup and optionally delete on read.
- **Run tests with:** `bun vitest` (per CLAUDE.md).

### Testing Requirements
- Tests for create, getByValue (hit and miss), expired challenge not returned, delete, unique constraint. Use test DB or in-memory SQLite if project supports it; otherwise mock db. No WebAuthn or Keycloak.

### Story Completion Status
- **Status:** done
- **Completion note:** Challenge storage for WebAuthn: Drizzle schema, 5-min TTL, create/get/delete and on-read expiry handling. Foundation for 9.2–9.5 and Epic 10 passkey endpoints.

---

## Dev Agent Record

### Agent Model Used

Claude Opus 4.5

### Debug Log References

- Test DB required manual migration: `bun run db:test:migrate` was broken; fixed script to use `export $(grep -v '^#' .env | xargs) && DATABASE_URL=$DATABASE_URL_TEST drizzle-kit migrate`

### Completion Notes List

- Schema already implemented in `src/lib/server/db/schema.ts`: `challenges` table with UUID id, nullable userId, unique challenge text, type, expiresAt (timestamptz), createdAt with `idx_challenges_expires_at` index
- Challenge service implemented in `src/lib/server/challenges.ts`: `createChallenge()` with 5-min TTL, `getChallengeByValue()` with expiry filter and on-read cleanup, `deleteChallenge()`, `deleteChallengeByValue()`
- Migration generated in `drizzle/0000_brown_donald_blake.sql` includes challenges table, unique constraint, and expires_at index
- Fixed `src/lib/server/db/test-utils.ts` to use drizzle transaction pattern instead of deprecated reserve() API
- 10 unit tests in `challenges.spec.ts`: create returns row, 5-min TTL verified, null userId allowed, unique constraint enforced, getByValue hit/miss, expired cleanup, delete by id/value, graceful handling of non-existent
- All 292 server tests pass (10 new + 282 existing)

### File List

- `src/lib/server/db/schema.ts` (modified - challenges table added)
- `src/lib/server/challenges.ts` (new - challenge service)
- `src/lib/server/challenges.spec.ts` (new - 10 unit tests)
- `src/lib/server/db/test-utils.ts` (modified - fixed drizzle transaction pattern)
- `drizzle/0000_brown_donald_blake.sql` (existing - includes challenges table)
- `package.json` (modified - fixed db:test:migrate script)
