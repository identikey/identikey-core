# Story 7.1: Key Generation & Storage

**Status:** ready-for-dev  
**Epic:** 7 - JWT Infrastructure  
**FR Coverage:** FR120, FR121  
**Story Key:** 7-1-key-generation-storage

---

## Story

As a **developer**,  
I want **to generate and store ES256 signing keys**,  
So that **IdentiKey can sign JWTs**.

---

## Acceptance Criteria

### AC1: Generate ECDSA P-256 Key Pair
- [ ] Function `generateSigningKeyPair()` creates a valid ECDSA P-256 key pair
- [ ] Private key is exportable in PEM format
- [ ] Public key is exportable in JWK format
- [ ] Key ID (kid) is computed as SHA-256 thumbprint of public key

### AC2: Load Key from Environment
- [ ] `loadSigningKey()` reads private key PEM from `IDENTIKEY_SIGNING_KEY` env var
- [ ] Function validates the key format (must be EC P-256)
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

- [ ] **Task 1: Add jose dependency** (AC: all)
  - [ ] `bun add jose`
  - [ ] Verify no version conflicts with existing deps

- [ ] **Task 2: Create auth/jwt directory structure** (AC: all)
  - [ ] Create `src/lib/auth/jwt/` folder
  - [ ] Create `keys.ts` for key management
  - [ ] Create `index.ts` for exports

- [ ] **Task 3: Implement key generation** (AC: #1)
  - [ ] Implement `generateSigningKeyPair()` using `jose.generateKeyPair`
  - [ ] Implement `computeKeyId()` using SHA-256 thumbprint
  - [ ] Write unit tests in `keys.spec.ts`

- [ ] **Task 4: Implement key loading from env** (AC: #2)
  - [ ] Implement `loadSigningKey()` to read from `IDENTIKEY_SIGNING_KEY`
  - [ ] Parse PEM, validate curve is P-256
  - [ ] Create `InvalidSigningKeyError` in `src/lib/auth/errors.ts`
  - [ ] Write unit tests with valid/invalid key fixtures

- [ ] **Task 5: Implement JWK export** (AC: #3)
  - [ ] Implement `getPublicKeyJwk()` using `jose.exportJWK`
  - [ ] Add required fields: `use: "sig"`, `alg: "ES256"`
  - [ ] Write unit tests

- [ ] **Task 6: Startup validation** (AC: #4)
  - [ ] Create initialization function that loads and validates key
  - [ ] Log success/failure appropriately (use existing pino logger)
  - [ ] Integration test: app starts with valid key, fails gracefully without

---

## Dev Notes

### Architecture Constraints

From `docs/architecture.md`:

- **Signing Algorithm:** ES256 (ECDSA with P-256 curve) — **NO EXCEPTIONS**
- **Key ID (kid):** SHA-256 thumbprint of public key JWK
- **Phase 1 Storage:** Private key as PEM in `IDENTIKEY_SIGNING_KEY` env var
- **File Location:** `src/lib/auth/jwt/keys.ts`

### Library Requirements

| Library | Version | Purpose | Notes |
|---------|---------|---------|-------|
| `jose` | latest | JWT/JWK operations | Add as new dependency |

**jose API to use:**
- `generateKeyPair('ES256')` — key generation
- `importPKCS8(pem, 'ES256')` — import private key from PEM
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
# openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt

IDENTIKEY_SIGNING_KEY="-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
-----END PRIVATE KEY-----"
```

### Security Considerations

- **NEVER log the private key** or any portion of it
- **DO log** the kid (public key thumbprint) for debugging
- PEM must be PKCS#8 format (not SEC1)
- Reject keys with wrong curve (P-384, P-521, etc.)

---

### References

- [Source: docs/architecture.md#Key Management] — Phase approach, storage options
- [Source: docs/architecture.md#Technology Stack] — `jose` library choice
- [Source: docs/architecture.md#Security Architecture] — ES256, kid computation
- [Source: docs/epics.md#Story 7.1] — Original story definition

---

## Dev Agent Record

### Agent Model Used

_To be filled by dev agent_

### Completion Notes

_To be filled after implementation_

### Files Created/Modified

- [ ] `src/lib/auth/jwt/keys.ts`
- [ ] `src/lib/auth/jwt/keys.spec.ts`
- [ ] `src/lib/auth/jwt/index.ts`
- [ ] `src/lib/auth/errors.ts`
- [ ] `src/lib/auth/index.ts`
- [ ] `package.json` (add jose)
