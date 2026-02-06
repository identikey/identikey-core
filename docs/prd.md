# IdentiKey Core — Product Requirements Document

**Author:** Master Dorje
**Date:** 2025-11-30 (Updated: 2026-02-05)
**Version:** 2.0

---

## Executive Summary

IdentiKey Core is the **identity platform backend** for IdentiKey. It provides:

1. **Native Mobile Authentication** — Apple Sign In → Passkey enrollment → JWT token issuance
2. **Token Management** — IdentiKey-signed JWTs with device trust claims
3. **Admin Tooling** — CLI and MCP for user management and debugging
4. **Keycloak Integration** — User storage, permissions, and standard OIDC for web apps

### What Changed (v2.0)

The original scope was a Keycloak admin wrapper (CLI + MCP + future Web UI). The new scope expands IdentiKey into a **token-issuing identity layer** that:

- Uses Apple Sign In as one-time identity verification
- Enrolls passkeys for ongoing authentication
- Issues its own JWTs (not relying on Keycloak's token issuance for mobile)
- Supports device trust levels (master vs temporary)
- Keeps Keycloak for user storage and standard OIDC

This positions IdentiKey as a true identity platform, not just a Keycloak wrapper.

---

## Project Classification

**Technical Type:** Identity Platform / Auth Backend
**Domain:** Identity & Access Management
**Complexity:** Medium-High
**Security Sensitivity:** High

---

## Success Criteria

### Phase 1: Admin Tooling (✅ Complete)
1. ✅ MCP server works for user management
2. ✅ CLI covers user and auth flow operations
3. ✅ Foundation is solid (services, error handling, logging)

### Phase 2: Native Mobile Auth (Current Focus)
1. Apple Sign In verification works
2. Passkey registration and authentication work
3. IdentiKey issues valid JWTs
4. Tokens are validated by resource servers
5. Device trust model implemented

### Phase 3: Production Hardening
1. Key rotation implemented
2. Token revocation works
3. Temporary device authorization flow works
4. Recovery flows implemented

### Phase 4: Web UI & Delegated Admin (Future)
1. Guild admins can self-serve via web UI
2. Standard OIDC flow works for web apps via Keycloak

---

## Product Scope

### Phase 1 — Admin Tooling (Complete)

| Domain | Capabilities | Status |
|--------|--------------|--------|
| **Users** | List, search, get, create, update, delete, reset password, credentials | ✅ Done |
| **Auth Flows** | List, get, list executions, copy | ✅ Done |
| **MCP Server** | All user/auth-flow operations exposed | ✅ Done |
| **CLI** | All user/auth-flow operations | ✅ Done |

### Phase 2 — Native Mobile Auth (New)

| Domain | Capabilities |
|--------|--------------|
| **Apple Verification** | Verify Apple identity tokens, extract claims, handle private relay emails |
| **Passkey Management** | WebAuthn registration, store credentials, validate assertions |
| **JWT Issuance** | Sign tokens with ES256, issue access/refresh/id tokens |
| **JWKS Endpoint** | Publish public keys for token validation |
| **Token Refresh** | Validate refresh tokens, issue new access tokens |
| **Device Trust** | Track master vs temporary devices, scope tokens accordingly |

### Phase 3 — Production Hardening

| Domain | Capabilities |
|--------|--------------|
| **Key Rotation** | Generate new keys, transition gracefully, retire old keys |
| **Token Revocation** | Revoke individual tokens, revoke all tokens for user/device |
| **Temporary Devices** | QR-based authorization, time-limited tokens |
| **Recovery Flows** | Apple re-verification, email magic links |

### Phase 4 — Web UI & Extended Admin

| Domain | Capabilities |
|--------|--------------|
| **Web UI** | SvelteKit admin dashboard |
| **Delegated Admin** | Guild admins manage their scope |
| **Apps (Clients)** | CRUD for OIDC clients |
| **Guilds (Groups)** | CRUD, member management |
| **Roles** | Assignment to users/guilds |
| **Sessions/Events** | View, force logout, query events |

---

## Functional Requirements

### Authentication & Connection (FR1-4) ✅ Complete

- FR1: ✅ Authenticate to Keycloak Admin API using service account credentials
- FR2: ✅ Authenticate using admin username/password
- FR3: ✅ Configuration via environment variables
- FR4: ✅ Validate connection on startup with clear errors

### User Management (FR5-13) ✅ Complete

- FR5: ✅ List users with pagination
- FR6: ✅ Search users by username, email, name
- FR7: ✅ Get user details
- FR8: ✅ Create users
- FR9: ✅ Update users
- FR10: ✅ Delete users
- FR11: ✅ Reset password
- FR12: ✅ View credentials
- FR13: ✅ Delete credentials

### Apple Token Verification (FR100-104) — NEW

- FR100: Fetch and cache Apple JWKS from `https://appleid.apple.com/auth/keys`
- FR101: Verify Apple identity token signature (RS256)
- FR102: Validate Apple token claims (iss, aud, exp, sub)
- FR103: Extract user identity (sub, email, is_private_email)
- FR104: Handle first-time vs returning Apple users (email/name only on first auth)

### Passkey Management (FR110-118) — NEW

- FR110: Generate WebAuthn registration challenge
- FR111: Validate attestation response
- FR112: Store passkey credential (credentialId, publicKey, signCount)
- FR113: Generate WebAuthn authentication challenge
- FR114: Validate assertion response against stored public key
- FR115: Update sign count on successful auth
- FR116: Support multiple passkeys per user
- FR117: Delete passkey credential
- FR118: List user's passkeys

### JWT Token Issuance (FR120-130) — NEW

- FR120: Generate ES256 signing key pair
- FR121: Store private key securely (vault or encrypted env)
- FR122: Publish JWKS at `/.well-known/jwks.json`
- FR123: Sign access tokens with custom claims (sub, device_id, device_trust)
- FR124: Sign refresh tokens (long-lived, device-bound)
- FR125: Sign ID tokens (user profile claims)
- FR126: Token expiry: access (15min), refresh (30 days), id (1 hour)
- FR127: Include `device_trust` claim ("master" or "temporary")
- FR128: Include `auth_method` claim ("passkey" or "apple_provision")
- FR129: Publish OIDC discovery at `/.well-known/openid-configuration`
- FR130: Token introspection endpoint for resource servers

### Token Refresh (FR135-138) — NEW

- FR135: Validate refresh token signature
- FR136: Check refresh token not revoked
- FR137: Issue new access token with same claims
- FR138: Optionally rotate refresh token on use

### Device Trust (FR140-148) — NEW

- FR140: Register device as "master" on passkey enrollment
- FR141: Track device metadata (fingerprint, last seen, created)
- FR142: Issue tokens with device_trust="master" for master devices
- FR143: Temporary device authorization via QR code
- FR144: Issue tokens with device_trust="temporary" for temp devices
- FR145: Temporary tokens: short expiry, no refresh, limited scope
- FR146: Master device can revoke temporary device access
- FR147: List user's devices
- FR148: Remove device (revokes associated tokens)

### Auth Endpoints (FR150-160) — NEW

- FR150: `POST /apple-provision` — verify Apple token, create/find user, return WebAuthn challenge
- FR151: `POST /passkey-register` — validate attestation, store passkey, issue tokens
- FR152: `POST /passkey-auth/start` — return authentication challenge
- FR153: `POST /passkey-auth/finish` — verify assertion, issue tokens
- FR154: `POST /token/refresh` — refresh access token
- FR155: `POST /token/revoke` — revoke token(s)
- FR156: `POST /device-authorize` — initiate QR-based temp device auth
- FR157: `POST /device-authorize/confirm` — master device confirms temp access
- FR158: `GET /.well-known/jwks.json` — JWKS endpoint
- FR159: `GET /.well-known/openid-configuration` — OIDC discovery
- FR160: `POST /introspect` — token introspection

### MCP Interface (FR49-51) ✅ Complete

- FR49: ✅ All user operations exposed as MCP tools
- FR50: ✅ MCP responses include structured data
- FR51: ✅ MCP errors include actionable information

### CLI Interface (FR52-55) ✅ Complete

- FR52: ✅ All user operations exposed as CLI commands
- FR53: ✅ CLI supports JSON output
- FR54: ✅ CLI supports table output
- FR55: ✅ CLI provides help text

---

## Non-Functional Requirements

### Security

- NFR1: ✅ Credentials never logged
- NFR2: ✅ MCP server uses stdio only (no network exposure)
- NFR3: ✅ CLI reads credentials from env vars
- NFR4: ✅ All Keycloak API calls over HTTPS
- NFR10: (NEW) Private signing keys stored in secure vault or encrypted
- NFR11: (NEW) Apple token verified server-side only
- NFR12: (NEW) Rate limiting on all auth endpoints
- NFR13: (NEW) Passkey attestation validated
- NFR14: (NEW) Refresh token rotation on use
- NFR15: (NEW) Immediate token revocation capability

### Reliability

- NFR5: ✅ Operations are idempotent where possible
- NFR6: ✅ Clear error messages with details
- NFR7: ✅ Connection failures handled gracefully

### Developer Experience

- NFR8: ✅ MCP tools have descriptive documentation
- NFR9: ✅ CLI commands follow consistent naming

---

## Technical Constraints

- **Keycloak Version:** 26.x (IdentiKey production instance)
- **Realm:** `identikey` (master reserved for KC admin)
- **Runtime:** Bun / Node.js / TypeScript
- **Database:** PostgreSQL (passkeys, devices, tokens)
- **Signing Algorithm:** ES256 (ECDSA with P-256)

---

## Out of Scope (Current)

- Realm creation/deletion
- Multi-realm support
- Keycloak deployment/operations
- User self-service (Keycloak account console)
- Guardian-based recovery (future phase)
- Cross-platform passkey sync (platform limitation)

---

## Document Status

**Status:** ✅ Updated
**Updated By:** AI Assistant
**Updated Date:** 2026-02-05
**PRD Version:** 2.0
**FR Count:** 68 (13 original complete + 55 new)
**NFR Count:** 15

---

_This PRD captures IdentiKey Core — the identity platform backend for native mobile auth and Keycloak integration._
