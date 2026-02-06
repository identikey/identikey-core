# Story 7.1: Key Generation & Storage

**Status:** review
**Epic:** 7 - JWT Infrastructure  
**FR Coverage:** FR120, FR121  
**Story Key:** 7-1-key-generation-storage

---

## Story

As a **developer**,  
I want **to generate and store EdDSA Ed25519 signing keys**,  
So that **IdentiKey can sign JWTs**.

---

## Acceptance Criteria

### AC1: Generate EdDSA Ed25519 Key Pair
- [ ] Function `generateSigningKeyPair()` creates a valid EdDSA Ed25519 key pair
- [ ] Private key is exportable in JWK format
- [ ] Public key is exportable in JWK format
- [ ] Key ID (kid) is computed as SHA-256 thumbprint of public key

### AC2: Load Key from Environment
- [ ] `loadSigningKey()` reads private key JWK from `IDENTIKEY_SIGNING_KEY` env var
- [ ] Function validates the key format (must be OKP Ed25519)
- [ ] Throws typed error `InvalidSigningKeyError` if key is malformed or wrong curve
- [ ] Returns structured key object with `privateKey`, `publicKey`, `kid`

### AC3: Export Public Key as JWK
- [ ] `getPublicKeyJwk()` returns the public key in JWK format
- [ ] JWK includes required fields: `kty`, `crv`, `x`, `y`, `kid`, `use`, `alg`
- [ ] Format matches JWKS requirements (for `/.well-known/jwks.json` in story 7.2)

### AC4: Startup Validation
- [ ] On service startup, key is loaded and validated
- [ ] If `IDENTIKEY_SIGNING_KEY` is not set, log error and exit gracefully
- [ ] If key is invalid, log detailed error (without exposing key material) and exit

---

## Tasks / Subtasks

- [x] **Task 1: Add jose dependency** (AC: all)
  - [x] `bun add jose`
  - [x] Verify no version conflicts with existing deps

- [x] **Task 2: Create auth/jwt directory structure** (AC: all)
  - [x] Create `src/lib/auth/jwt/` folder
  - [x] Create `keys.ts` for key management
  - [x] Create `index.ts` for exports

- [x] **Task 3: Implement key generation** (AC: #1)
  - [x] Implement `generateSigningKeyPair()` using `jose.generateKeyPair`
  - [x] Implement `computeKeyId()` using SHA-256 thumbprint
  - [x] Write unit tests in `keys.spec.ts`

- [x] **Task 4: Implement key loading from env** (AC: #2)
  - [x] Implement `loadSigningKey()` to read from `IDENTIKEY_SIGNING_KEY`
  - [x] Parse JWK JSON, validate curve is Ed25519
  - [x] Create `InvalidSigningKeyError` in `src/lib/auth/errors.ts`
  - [x] Write unit tests with valid/invalid key fixtures

- [x] **Task 5: Implement JWK export** (AC: #3)
  - [x] Implement `getPublicKeyJwk()` using `jose.exportJWK`
  - [x] Add required fields: `use: "sig"`, `alg: "EdDSA"`
  - [x] Write unit tests

- [x] **Task 6: Startup validation** (AC: #4)
  - [x] Create initialization function that loads and validates key
  - [x] Log success/failure appropriately (use existing pino logger)
  - [x] Integration test: app starts with valid key, fails gracefully without

---

## Dev Notes

### Architecture Constraints

From `docs/architecture.md`:

- **Signing Algorithm:** EdDSA with Ed25519 curve (~128-bit security) — **NO EXCEPTIONS**
- **Key ID (kid):** SHA-256 thumbprint of public key JWK
- **Phase 1 Storage:** Private key as JWK JSON in `IDENTIKEY_SIGNING_KEY` env var
- **File Location:** `src/lib/auth/jwt/keys.ts`

### Library Requirements

| Library | Version | Purpose | Notes |
|---------|---------|---------|-------|
| `jose` | latest | JWT/JWK operations | Add as new dependency |

**jose API to use:**
- `generateKeyPair('EdDSA', { crv: 'Ed25519' })` — key generation
- `importJWK(jwk, 'EdDSA')` — import private key from JWK
- `exportJWK(key)` — export public key as JWK
- `calculateJwkThumbprint(jwk, 'sha256')` — compute kid

### Project Structure Notes

Create new directory structure:

```
src/lib/
├── auth/                    # NEW: Auth infrastructure
│   ├── jwt/
│   │   ├── keys.ts          # THIS STORY
│   │   └── index.ts
│   └── errors.ts            # Auth-specific errors
└── keycloak/                # Existing
```

### Testing Standards

From existing patterns (e.g., `client.spec.ts`, `config.spec.ts`):
- Use Vitest (`*.spec.ts` naming)
- Co-locate tests with source files
- Use `describe`/`it` blocks
- Mock environment variables where needed

### Error Handling Pattern

Follow existing pattern from `src/lib/keycloak/errors.ts`:

```typescript
export class InvalidSigningKeyError extends Error {
  constructor(message: string, public readonly cause?: Error) {
    super(message);
    this.name = 'InvalidSigningKeyError';
  }
}
```

### Environment Variable

```bash
# Generate a test key (dev only):
# Generate via: bun run generate-key

IDENTIKEY_SIGNING_KEY='{"kty":"OKP","crv":"Ed25519","d":"...","x":"...","kid":"...","use":"sig","alg":"EdDSA"}'
```

### Security Considerations

- **NEVER log the private key** or any portion of it
- **DO log** the kid (public key thumbprint) for debugging
- JWK must include `d` (private key) and `x` (public key) fields
- Reject keys with wrong curve (Ed448, P-256, etc.)

---

### References

- [Source: docs/architecture.md#Key Management] — Phase approach, storage options
- [Source: docs/architecture.md#Technology Stack] — `jose` library choice
- [Source: docs/architecture.md#Security Architecture] — EdDSA Ed25519, kid computation
- [Source: docs/epics.md#Story 7.1] — Original story definition

---

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6

### Completion Notes

- Task 1: Added jose@6.1.3 via `bun add jose`. No version conflicts.
- Task 2: Created `src/lib/auth/jwt/` directory, `keys.ts`, `index.ts`, `errors.ts`, barrel exports.
- Task 3: Implemented `generateSigningKeyPair()` and `computeKeyId()` using jose EdDSA Ed25519. 7 unit tests passing.
- Task 4: Implemented `loadSigningKey()` with JWK import, curve validation, and `InvalidSigningKeyError`. Required `{ extractable: true }` for bun WebCrypto compatibility. 6 unit tests passing.
- Task 5: Implemented `getPublicKeyJwk()` with required JWKS fields (kty, crv, x, kid, use, alg). 3 unit tests passing.
- Task 6: Created `initializeSigningKey()` in `init.ts` with pino logging and `process.exit(1)` on failure. `getSigningKey()` accessor for singleton. 5 integration tests passing.
- Added `bun run generate-key` script for key generation.
- Pre-existing failure in `errors.spec.ts` (stale error code set) unrelated to this story.

### Files Created/Modified

- [x] `src/lib/auth/jwt/keys.ts` — key generation, loading, JWK export
- [x] `src/lib/auth/jwt/keys.spec.ts` — 16 unit tests
- [x] `src/lib/auth/jwt/init.ts` — startup validation
- [x] `src/lib/auth/jwt/init.spec.ts` — 5 integration tests
- [x] `src/lib/auth/jwt/index.ts` — barrel exports
- [x] `src/lib/auth/errors.ts` — InvalidSigningKeyError
- [x] `src/lib/auth/index.ts` — barrel exports
- [x] `scripts/generate-signing-key.ts` — key generation script
- [x] `package.json` — added jose dep + generate-key script
