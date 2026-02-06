# IdentiKey Core — Epic Breakdown

**Author:** Master Dorje  
**Date:** 2025-11-30 (Updated: 2026-02-05)  
**Version:** 2.1 — Architecture Alignment

---

## Overview

This document breaks down IdentiKey Core into implementable epics across two tracks:

1. **Admin Tooling** ✅ Complete — CLI + MCP for Keycloak management
2. **Native Mobile Auth** 🔥 ACTIVE — Bootstrap verification, Passkeys, JWT issuance

### Epic Summary

| Epic | Name | Difficulty | Stories | Status | Value |
|------|------|------------|---------|--------|-------|
| 1 | Foundation | Easy | 5 | ✅ Done | Keycloak connection, config, errors |
| 2 | User Administration | Easy | 6 | ✅ Done | User CRUD via MCP + CLI |
| 3 | App Management | Easy | 4 | 💤 Backlog | Client/App CRUD |
| 4 | Guild & Role Management | Medium | 6 | 💤 Backlog | Groups, roles |
| 5 | Login Flow Administration | Medium | 5 | ⏸️ Partial | Auth flow debugging (3/5 done) |
| 6 | Sessions & Events | Medium | 4 | 💤 Backlog | Session/event queries |
| **7** | **JWT Infrastructure** | **Medium** | **5** | **🔥 Active** | **Key management, signing, JWKS** |
| **8** | **Bootstrap Verification** | **Medium** | **5** | **🔥 Active** | **Apple + Google token verification** |
| **9** | **Passkey Management** | **Medium-Hard** | **6** | **🔥 Active** | **WebAuthn registration/auth** |
| **10** | **Auth Endpoints** | **Medium** | **6** | **🔥 Active** | **REST endpoints for mobile** |
| **11** | **Device Trust** | **Medium** | **4** | **🔥 Active** | **Master/temp device model** |
| **12** | **Token Refresh & Revocation** | **Medium** | **4** | **🔥 Active** | **Refresh flow, revocation** |
| **13** | **Production Hardening** | **Hard** | **7** | **📋 Planned** | **Key rotation, recovery, more bootstraps** |

**Active Work:** Epics 7-12 = 30 stories  
**Difficulty Assessment:** Medium overall, with Passkey Management being the trickiest part

---

## Difficulty Assessment

### Active Work Breakdown

| Epic | Difficulty | Estimate | Risk | Notes |
|------|------------|----------|------|-------|
| 7: JWT Infrastructure | Medium | 2-3 days | Low | Well-documented, use `jose` library |
| 8: Bootstrap Verification | Medium | 2 days | Low | Apple + Google JWKS verification |
| 9: Passkey Management | Medium-Hard | 4-5 days | Medium | WebAuthn fiddly, but `@simplewebauthn/server` helps |
| 10: Auth Endpoints | Medium | 2-3 days | Low | SvelteKit API routes, wiring |
| 11: Device Trust | Medium | 2-3 days | Low | Database + token claims |
| 12: Token Refresh | Medium | 2 days | Low | Standard pattern |

**Total estimate:** 14-18 days of focused work

### Why This Is Achievable

1. **Libraries exist:** `jose` for JWT, `@simplewebauthn/server` for WebAuthn
2. **Keycloak integration done:** User storage layer already works
3. **Clear architecture:** Analysis doc is thorough, ADRs are solid
4. **Incremental:** Each epic delivers testable value
5. **Passkeys in Keycloak:** No separate credential store to manage

### Where It Gets Tricky

1. **WebAuthn edge cases:** Different attestation formats, platform quirks
2. **Keycloak credential API:** Storing passkeys via Admin API needs exploration
3. **Mobile integration:** Testing requires actual iOS/Android builds
4. **Error handling:** Auth failures need excellent diagnostics

---

## Admin Tooling Epics ✅ Complete

### Epic 1: Foundation ✅ Done

- 1.1: Project Structure & Dependencies ✅
- 1.2: Configuration Loading ✅
- 1.3: Keycloak Client Wrapper ✅
- 1.4: Error Types & Logging Setup ✅
- 1.5: Connection Validation ✅

### Epic 2: User Administration ✅ Done

- 2.1: UserService Core Operations ✅
- 2.2: User MCP Tools ✅
- 2.3: User CLI Commands ✅
- 2.4: User Search Integration ✅
- 2.5: Pagination Support ✅
- 2.6: Credential Management ✅

### Epic 5: Login Flow Administration ⏸️ Partial

- 5.1: AuthFlowService Core Operations ✅
- 5.2: Login Flow MCP Tools ✅
- 5.3: Login Flow CLI Commands ✅
- 5.4: Execution Modification 💤
- 5.5: Flow Copy & Defaults 💤

### Epics 3, 4, 6: Future Backlog 💤

App management, guilds/roles, and sessions/events are in backlog. They will be prioritized after native auth is complete.

---

## Native Mobile Auth Epics 🔥 ACTIVE

### Epic 7: JWT Infrastructure

**Goal:** Establish token signing and JWKS infrastructure.

**Difficulty:** Medium (2-3 days)

**Stories:**

#### 7.1: Key Generation & Storage

As a **developer**,
I want **to generate and store ES256 signing keys**,
So that **IdentiKey can sign JWTs**.

**Acceptance Criteria:**
- Generate ECDSA P-256 key pair
- Store private key in environment or secret manager
- Load key on startup, validate format
- Export public key in JWK format

**Technical Notes:**
- Use Node `crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })`
- Or use `jose` library's `generateKeyPair`
- Private key as PEM in `IDENTIKEY_SIGNING_KEY` env var

---

#### 7.2: JWKS Endpoint

As a **resource server**,
I want **to fetch IdentiKey's public keys**,
So that **I can validate access tokens**.

**Acceptance Criteria:**
- `GET /.well-known/jwks.json` returns JWKS
- Keys include `kid`, `kty`, `crv`, `x`, `y`, `use: "sig"`, `alg: "ES256"`
- Response is cacheable (appropriate headers)

**Technical Notes:**
- SvelteKit route: `src/routes/.well-known/jwks.json/+server.ts`
- Use `jose.exportJWK` to convert public key

---

#### 7.3: Token Signing Service

As the **auth system**,
I want **a service that signs JWTs**,
So that **tokens can be issued with consistent structure**.

**Acceptance Criteria:**
- `signAccessToken(claims)` returns signed JWT
- `signRefreshToken(claims)` returns signed JWT
- `signIdToken(claims)` returns signed JWT
- Tokens include: `iss`, `sub`, `aud`, `exp`, `iat`, `jti`
- Access tokens include: `device_id`, `device_trust`, `auth_method`

**Technical Notes:**
- Use `jose.SignJWT` for signing
- Set `kid` in header for key identification

---

#### 7.4: Token Verification Service

As the **auth system**,
I want **to verify tokens issued by IdentiKey**,
So that **token refresh and introspection work**.

**Acceptance Criteria:**
- `verifyToken(token)` returns decoded payload or throws
- Verifies signature against known public key
- Validates `exp`, `iat`, `iss`
- Returns structured error on failure

**Technical Notes:**
- Use `jose.jwtVerify` with JWKS

---

#### 7.5: OIDC Discovery Endpoint

As a **client application**,
I want **OIDC discovery metadata**,
So that **I can auto-configure token validation**.

**Acceptance Criteria:**
- `GET /.well-known/openid-configuration` returns metadata
- Includes: `issuer`, `jwks_uri`, `token_endpoint`, `introspection_endpoint`
- Response is cacheable

---

### Epic 8: Bootstrap Verification

**Goal:** Verify identity tokens from social providers (Apple, Google) for user provisioning.

**Difficulty:** Medium (2 days)

**Architecture Note:** Social providers are used as *bootstrap mechanisms only*, not as Keycloak IDPs. See ADR-008.

**Stories:**

#### 8.1: Provider JWKS Service

As the **auth system**,
I want **to fetch and cache provider public keys**,
So that **I can verify identity tokens from Apple and Google**.

**Acceptance Criteria:**
- Fetch Apple JWKS from `https://appleid.apple.com/auth/keys`
- Fetch Google JWKS from `https://www.googleapis.com/oauth2/v3/certs`
- Cache keys with TTL (1 hour recommended)
- Refresh on cache miss or expiry
- Handle fetch failures gracefully

**Technical Notes:**
- Use `jose.createRemoteJWKSet` for automatic caching
- Abstract provider logic for easy addition of future providers

---

#### 8.2: Apple Token Verification

As the **auth system**,
I want **to verify Apple identity tokens**,
So that **I can trust the user's identity**.

**Acceptance Criteria:**
- Verify signature against Apple JWKS
- Validate claims:
  - `iss` = `https://appleid.apple.com`
  - `aud` = configured Services ID
  - `exp` > now
- Extract: `sub`, `email`, `email_verified`, `is_private_email`
- Return structured result or throw typed error

**Technical Notes:**
- Apple `sub` is stable user identifier (not email)
- Email/name only provided on FIRST auth — must capture immediately

---

#### 8.3: Google Token Verification

As the **auth system**,
I want **to verify Google identity tokens**,
So that **Android users can bootstrap their accounts**.

**Acceptance Criteria:**
- Verify signature against Google JWKS
- Validate claims:
  - `iss` = `https://accounts.google.com`
  - `aud` = configured OAuth client ID
  - `exp` > now
- Extract: `sub`, `email`, `email_verified`, `name`, `picture`
- Return structured result or throw typed error

**Technical Notes:**
- Google `sub` is stable user identifier
- Google provides profile info on every auth (unlike Apple)

---

#### 8.4: Bootstrap User Provisioning

As a **new user**,
I want **my IdentiKey account created from social sign in**,
So that **I can use the app**.

**Acceptance Criteria:**
- On verified token (Apple or Google):
  - Check if user exists (by `apple_sub` or `google_sub` attribute)
  - If not, create user in Keycloak with email, name
  - Store provider `sub` as user attribute
  - Return user ID and WebAuthn registration challenge
- Handle Apple private relay emails correctly
- Idempotent: re-provisioning existing user returns same user ID

**Technical Notes:**
- Use existing `UserService` for Keycloak CRUD
- Store `apple_sub` or `google_sub` in Keycloak user attributes
- See architecture doc "Failure Handling" for partial failure scenarios

---

#### 8.5: Bootstrap Endpoint Abstraction

As a **developer**,
I want **a consistent pattern for bootstrap endpoints**,
So that **adding new providers is straightforward**.

**Acceptance Criteria:**
- Common interface for bootstrap verification
- Provider-specific implementations (Apple, Google)
- Shared user provisioning logic
- Easy to add email/SMS bootstrap later

**Technical Notes:**
- Strategy pattern or similar for provider abstraction
- Prepares for Epic 13 bootstrap expansion

---

### Epic 9: Passkey Management

**Goal:** WebAuthn passkey registration and authentication.

**Difficulty:** Medium-Hard (4-5 days)

**This is the trickiest epic** — WebAuthn has edge cases.

**Architecture Note:** Passkeys are stored in Keycloak's user credential store (via Admin API), not a separate database. This enables both mobile and web passkey auth. See ADR-007.

**Stories:**

#### 9.1: Challenge Storage

As the **auth system**,
I want **to store WebAuthn challenges temporarily**,
So that **I can validate registration and authentication responses**.

**Acceptance Criteria:**
- Store challenges in PostgreSQL with 5-minute TTL
- Schema: `id`, `user_id`, `challenge`, `type`, `expires_at`
- Clean up expired challenges (scheduled job or on-read)
- Lookup by challenge value

**Technical Notes:**
- Drizzle schema in `src/lib/server/db/schema.ts`
- No Redis needed — DB is fine for this volume

---

#### 9.2: Registration Challenge Generation

As a **user enrolling a passkey**,
I want **to receive a registration challenge**,
So that **my device can create a credential**.

**Acceptance Criteria:**
- Generate random challenge (32 bytes)
- Return: `challenge`, `rp` (id, name), `user` (id, name, displayName)
- Include: `pubKeyCredParams` (ES256, RS256)
- Include: `authenticatorSelection` (platform, residentKey)
- Store challenge in DB with 5-minute TTL

**Technical Notes:**
- Use `@simplewebauthn/server` `generateRegistrationOptions`

---

#### 9.3: Attestation Validation & Storage

As the **auth system**,
I want **to validate passkey attestation and store the credential**,
So that **the passkey can be used for authentication**.

**Acceptance Criteria:**
- Validate attestation response format
- Verify challenge matches stored challenge
- Extract: `credentialId`, `publicKey`, `signCount`, `transports`
- Support attestation formats: `none`, `packed`, `fido-u2f`
- Store credential in Keycloak via Admin API
- Support multiple passkeys per user
- Delete used challenge

**Technical Notes:**
- Use `@simplewebauthn/server` `verifyRegistrationResponse`
- Be permissive on attestation (most are "none")
- Keycloak Admin API: `POST /users/{id}/credentials` with WebAuthn type
- Investigate Keycloak credential format for WebAuthn

---

#### 9.4: Authentication Challenge Generation

As a **returning user**,
I want **to receive an authentication challenge**,
So that **I can prove I own my passkey**.

**Acceptance Criteria:**
- Generate random challenge
- Optionally include `allowCredentials` if user known
- Store challenge in DB with 5-minute TTL
- Return: `challenge`, `rpId`, `timeout`, `userVerification`

**Technical Notes:**
- Use `@simplewebauthn/server` `generateAuthenticationOptions`
- For discoverable credentials, `allowCredentials` can be empty

---

#### 9.5: Assertion Verification

As the **auth system**,
I want **to verify passkey assertions**,
So that **I can authenticate users**.

**Acceptance Criteria:**
- Look up passkey in Keycloak by `credential_id`
- Verify signature against stored `public_key`
- Validate `authenticatorData` flags
- Check `signCount` >= stored (replay protection)
- Update `signCount` in Keycloak on success
- Delete used challenge
- Return user ID on success

**Technical Notes:**
- Use `@simplewebauthn/server` `verifyAuthenticationResponse`
- Keycloak Admin API for credential lookup and update

---

#### 9.6: Passkey Management (CRUD)

As a **user**,
I want **to manage my passkeys**,
So that **I can add/remove credentials**.

**Acceptance Criteria:**
- List passkeys for user (via MCP/CLI)
- Delete passkey by ID (Keycloak Admin API)
- Prevent deleting last passkey (unless other auth method exists)
- Show passkey metadata: created, last used, device info

---

### Epic 10: Auth Endpoints

**Goal:** REST endpoints for mobile auth flows.

**Difficulty:** Medium (2-3 days)

**Stories:**

#### 10.1: Apple Provision Endpoint

As a **mobile app**,
I want **POST /api/apple-provision**,
So that **I can start the Apple → Passkey flow**.

**Acceptance Criteria:**
- Input: `{ apple_token, device_info? }`
- Verify Apple token (Epic 8)
- Create/find user in Keycloak
- Generate WebAuthn registration challenge
- Output: `{ user_id, challenge, rp_id, ... }`

---

#### 10.2: Google Provision Endpoint

As a **mobile app**,
I want **POST /api/google-provision**,
So that **Android users can start the Google → Passkey flow**.

**Acceptance Criteria:**
- Input: `{ google_token, device_info? }`
- Verify Google token (Epic 8)
- Create/find user in Keycloak
- Generate WebAuthn registration challenge
- Output: `{ user_id, challenge, rp_id, ... }`

---

#### 10.3: Passkey Register Endpoint

As a **mobile app**,
I want **POST /api/passkey-register**,
So that **I can complete passkey enrollment**.

**Acceptance Criteria:**
- Input: `{ user_id, attestation_response, device_info }`
- Validate attestation (Epic 9)
- Store passkey in Keycloak
- Register device as master (Epic 11)
- Issue tokens (access, refresh, id)
- Output: `{ access_token, refresh_token, id_token }`

---

#### 10.4: Passkey Auth Start Endpoint

As a **mobile app**,
I want **POST /api/passkey-auth/start**,
So that **I can get an authentication challenge**.

**Acceptance Criteria:**
- Input: `{ user_id? }` (optional — for discoverable credentials)
- Generate authentication challenge
- Output: `{ challenge, rpId, timeout, ... }`

---

#### 10.5: Passkey Auth Finish Endpoint

As a **mobile app**,
I want **POST /api/passkey-auth/finish**,
So that **I can complete authentication**.

**Acceptance Criteria:**
- Input: `{ assertion_response, device_info }`
- Verify assertion (Epic 9)
- Update device last_seen
- Issue tokens
- Output: `{ access_token, refresh_token, id_token }`

---

#### 10.6: Token Introspection Endpoint

As a **resource server**,
I want **POST /api/introspect**,
So that **I can validate access tokens**.

**Acceptance Criteria:**
- Input: `{ token }`
- Verify token signature and claims
- Check revocation status for refresh tokens
- Output: `{ active, sub, exp, device_trust, ... }` or `{ active: false }`

---

### Epic 11: Device Trust

**Goal:** Master vs temporary device management.

**Difficulty:** Medium (2-3 days)

**Stories:**

#### 11.1: Device Registration

As the **auth system**,
I want **to register devices**,
So that **I can track and manage them**.

**Acceptance Criteria:**
- On passkey registration: create device record with `is_master: true`
- Store: `device_fingerprint`, `device_name`, timestamps
- Device ID included in token claims

---

#### 11.2: Device Trust Claims

As a **resource server**,
I want **device_trust claim in tokens**,
So that **I can make authorization decisions**.

**Acceptance Criteria:**
- Master device tokens: `device_trust: "master"`
- Temporary device tokens: `device_trust: "temporary"`
- Tokens include `device_id` for tracking

---

#### 11.3: Device Listing

As a **user**,
I want **to see my registered devices**,
So that **I know where I'm logged in**.

**Acceptance Criteria:**
- MCP tool: `list_user_devices({ user_id })`
- CLI: `kc devices list <user_id>`
- Return: device ID, name, is_master, last_seen

---

#### 11.4: Device Revocation

As a **user**,
I want **to remove a device**,
So that **I can revoke access**.

**Acceptance Criteria:**
- MCP tool: `revoke_device({ device_id })`
- CLI: `kc devices revoke <device_id>`
- Revokes all refresh tokens for that device

---

### Epic 12: Token Refresh & Revocation

**Goal:** Token lifecycle management.

**Difficulty:** Medium (2 days)

**Stories:**

#### 12.1: Refresh Token Storage

As the **auth system**,
I want **to track refresh tokens**,
So that **I can revoke them**.

**Acceptance Criteria:**
- Store token hash (SHA-256), not raw token
- Link to user_id and device_id
- Track expiry and revocation status

---

#### 12.2: Token Refresh Endpoint

As a **mobile app**,
I want **POST /api/token/refresh**,
So that **I can get new access tokens**.

**Acceptance Criteria:**
- Input: `{ refresh_token }`
- Verify signature and check not revoked
- Issue new access token
- Optionally rotate refresh token
- Output: `{ access_token, refresh_token? }`

---

#### 12.3: Token Revocation Endpoint

As a **user or admin**,
I want **POST /api/token/revoke**,
So that **I can invalidate tokens**.

**Acceptance Criteria:**
- Input: `{ token }` or `{ user_id, all: true }`
- Mark token(s) as revoked
- Output: `{ success: true }`

---

#### 12.4: Revocation in Verification

As the **auth system**,
I want **refresh verification to check revocation**,
So that **revoked tokens are rejected**.

**Acceptance Criteria:**
- On refresh: check token hash against revocation table
- If revoked: reject with clear error
- Introspection also checks revocation

---

### Epic 13: Production Hardening 📋 Planned

**Goal:** Production-ready security, recovery flows, and additional bootstrap methods.

**Difficulty:** Hard (ongoing)

**Stories (outline):**

#### Security & Operations
- 13.1: Key Rotation — Add new key, transition, retire old (see architecture Security section)
- 13.2: Security Audit & Penetration Testing

#### Additional Bootstrap Methods
- 13.3: Email Magic Link Bootstrap — Send link → verify → passkey enrollment
- 13.4: SMS OTP Bootstrap — Send code → verify → passkey enrollment

#### Recovery Flows
- 13.5: Apple/Google Re-verification Recovery — Re-verify social identity to recover account
- 13.6: Email Magic Link Recovery — Fallback for users who lose passkey access

#### Device Features
- 13.7: Temporary Device QR Flow — Full QR-based temp device authorization

---

## Recommended Implementation Order

### Sprint 1: JWT + Bootstrap (Epics 7 + 8)

Get token infrastructure working and Apple/Google verification done.

**Deliverable:** Can verify Apple/Google tokens and sign JWTs.

**Key Risk:** Keycloak credential API for passkey storage — research early.

### Sprint 2: Passkeys (Epic 9)

Implement WebAuthn registration and authentication with Keycloak storage.

**Deliverable:** Can register and authenticate with passkeys.

**Key Risk:** WebAuthn edge cases, Keycloak Admin API credential format.

### Sprint 3: Endpoints + Device Trust (Epics 10 + 11)

Wire up REST endpoints and device tracking.

**Deliverable:** Mobile app can complete full auth flow (Apple → Passkey → Tokens).

### Sprint 4: Token Lifecycle (Epic 12)

Implement refresh and revocation.

**Deliverable:** Production-ready token management.

### Sprint 5+: Hardening (Epic 13)

Key rotation, recovery flows, additional bootstrap methods, security review.

---

## FR Coverage Matrix

| FR | Description | Epic | Story |
|----|-------------|------|-------|
| FR100-104 | Apple token verification | 8 | 8.1-8.2, 8.4 |
| FR105-109 | Google token verification | 8 | 8.1, 8.3, 8.4 |
| FR110-118 | Passkey management | 9 | 9.1-9.6 |
| FR120-130 | JWT issuance | 7 | 7.1-7.5 |
| FR135-138 | Token refresh | 12 | 12.1-12.4 |
| FR140-148 | Device trust | 11 | 11.1-11.4 |
| FR150-160 | Auth endpoints | 10 | 10.1-10.6 |

---

## Document Status

| Field | Value |
|-------|-------|
| **Status** | ✅ Reviewed |
| **Version** | 2.1 — Architecture Alignment |
| **Last Updated** | 2026-02-05 |
| **Active Stories** | 30 (Epics 7-12) |
| **Planned Stories** | 7 (Epic 13) |

---

_This epic breakdown covers admin tooling (complete) and native mobile auth infrastructure (active) for IdentiKey Core._
