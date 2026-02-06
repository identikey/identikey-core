# Story 7.3: Token Signing Service

**Status:** ready-for-dev  
**Epic:** 7 - JWT Infrastructure  
**FR Coverage:** FR123, FR124, FR125, FR126, FR127, FR128  
**Story Key:** 7-3-token-signing-service

---

## Story

As the **auth system**,  
I want **a service that signs JWTs** with a consistent structure,  
So that **tokens can be issued for access, refresh, and ID** and validated by resource servers.

---

## Acceptance Criteria

### AC1: signAccessToken(claims)
- [ ] `signAccessToken(claims)` returns a signed JWT string (compact form)
- [ ] Token includes standard claims: `iss`, `sub`, `aud`, `exp`, `iat`, `jti` (unique per token)
- [ ] Access token includes: `device_id`, `device_trust`, `auth_method` (per architecture)
- [ ] Optional: `scope`, `email`, `email_verified` when provided in claims
- [ ] Expiry: 15 minutes from `iat` (per architecture)
- [ ] JWT header includes `alg: "EdDSA"` and `kid` (from current signing key)
- [ ] Signed with the key from `getSigningKey()` (EdDSA Ed25519)

### AC2: signRefreshToken(claims)
- [ ] `signRefreshToken(claims)` returns a signed JWT string
- [ ] Token includes: `iss`, `sub`, `aud`, `exp`, `iat`, `jti`; plus `device_id` for device binding
- [ ] Expiry: 30 days from `iat` (per architecture)
- [ ] Same header (alg, kid) and signing key

### AC3: signIdToken(claims)
- [ ] `signIdToken(claims)` returns a signed JWT string
- [ ] Token includes: `iss`, `sub`, `aud`, `exp`, `iat`, `jti`; plus user profile claims (e.g. `email`, `email_verified`, `name`) when provided
- [ ] Expiry: 1 hour from `iat` (per architecture)
- [ ] Same header and signing key

### AC4: Claims and Configuration
- [ ] Issuer (`iss`) and default audience (`aud`) are configurable (e.g. env `IDENTIKEY_ISSUER`, `IDENTIKEY_AUDIENCE` or passed per call). Document expected values (e.g. `https://connect.identikey.io`, `morphist-mobile`).
- [ ] `jti` is a cryptographically random UUID or equivalent (no reuse)
- [ ] All three functions throw if signing key is not initialized (e.g. call `getSigningKey()` at sign time)

---

## Tasks / Subtasks

- [ ] **Task 1: Signing module** (AC: 1–4)
  - [ ] Create `src/lib/auth/jwt/signing.ts`
  - [ ] Implement `signAccessToken(claims)`, `signRefreshToken(claims)`, `signIdToken(claims)` using `jose.SignJWT`
  - [ ] Use `getSigningKey()` to obtain private key and kid; set header `{ alg: 'EdDSA', kid }`
  - [ ] Set exp from iat + lifetime (15m / 30d / 1h). Generate `jti` (e.g. `crypto.randomUUID()`)
  - [ ] Define claims types (e.g. `AccessTokenClaims`, `RefreshTokenClaims`, `IdTokenClaims`) with required vs optional fields

- [ ] **Task 2: Issuer and audience** (AC: 4)
  - [ ] Read issuer/audience from env (e.g. `IDENTIKEY_ISSUER`, `IDENTIKEY_AUDIENCE`) or accept as optional params with env fallback
  - [ ] Document in README or story; default/example values per architecture

- [ ] **Task 3: Exports and integration** (AC: all)
  - [ ] Export signing functions (and claim types if public) from `src/lib/auth/jwt/index.ts`
  - [ ] No change to init or keys; signing uses existing `getSigningKey()`

- [ ] **Task 4: Tests** (AC: all)
  - [ ] Unit tests in `src/lib/auth/jwt/signing.spec.ts`: mock or initialize key, call each sign function, decode with jose (no verify) and assert claims (iss, sub, aud, exp, iat, jti, device_id, device_trust, auth_method for access). Assert exp delta (15m, 30d, 1h). Assert header alg and kid.
  - [ ] Test: uninitialized key throws when signing

---

## Dev Notes

### Architecture Constraints
- **Algorithm:** EdDSA Ed25519 only. Use `jose.SignJWT` with the private key from `getSigningKey()`.
- **Lifetimes (non-negotiable):** Access 15 min, Refresh 30 days, ID 1 hour (architecture + FR126).
- **File location:** Architecture specifies `src/lib/auth/jwt/signing.ts`.

### Previous Stories (7.1, 7.2) Intelligence
- **7.1:** `getSigningKey()` returns `SigningKeyPair` (privateKey, publicKey, kid). Key is loaded at startup via `initializeSigningKey()`. Use `privateKey` for signing.
- **7.2:** JWKS endpoint serves the public key; resource servers will validate these tokens via that key. Ensure `kid` in token header matches JWKS so validators can select the key.
- **jose:** Already in use. `SignJWT` from `jose`: build payload with `.setPayload()`, set issuer/audience/expiration, then `.sign(privateKey)`. Header can be set (e.g. `.setProtectedHeader({ alg: 'EdDSA', kid })`).

### Token Structure (from architecture)
- **Access:** iss, sub, aud, exp, iat, jti, scope, device_id, device_trust, auth_method, email, email_verified.
- **Refresh:** iss, sub, aud, exp, iat, jti, device_id (device binding).
- **ID:** iss, sub, aud, exp, iat, jti, plus profile claims (email, name, etc.).

### Security
- **jti:** Must be unique per token (replay / revocation binding). Use `crypto.randomUUID()` or equivalent.
- **No sensitive data in payload** beyond what’s required (sub, device_id, etc.). Do not put raw secrets in tokens.
- Issuer and audience must be set so validators can enforce them (7.4 verification story).

### References
- [Source: _bmad-output/planning-artifacts/epics.md#7.3] — AC and technical notes
- [Source: _bmad-output/planning-artifacts/architecture.md#Token Structure] — claim names and example
- [Source: _bmad-output/planning-artifacts/architecture.md#Token Lifetimes] — 15m, 30d, 1h
- [Source: src/lib/auth/jwt/init.ts] — getSigningKey()
- [Source: src/lib/auth/jwt/keys.ts] — SigningKeyPair type

### Developer Context (Guardrails)
- **Do not** add token verification in this story; that is 7.4. Only signing.
- **Do not** add HTTP endpoints or routes; only the library API. Endpoints that issue tokens (e.g. passkey-auth/finish) will call this service later.
- **Do not** change key loading or JWKS; reuse getSigningKey() as-is.

### Testing Requirements
- Unit tests with real or mocked signing key. Decode signed JWT (e.g. `jose.decodeJwt` or split and base64decode payload) and assert claim presence and exp/iat deltas. Optionally verify with `jose.jwtVerify` and getPublicKeyJwk to ensure round-trip.

### Story Completion Status
- **Status:** ready-for-dev  
- **Completion note:** Ultimate context engine analysis completed. Builds on 7.1 (key) and 7.2 (JWKS); 7.4 (verification) will consume these tokens.

---

## Dev Agent Record

### Agent Model Used

{{agent_model_name_version}}

### Debug Log References

### Completion Notes List

### File List
