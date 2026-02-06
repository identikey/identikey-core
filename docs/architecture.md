# Architecture — IdentiKey Core

**Author:** Master Dorje
**Date:** 2025-11-30 (Updated: 2026-02-05)
**Version:** 2.0

---

## Executive Summary

IdentiKey Core is the identity platform backend that:

1. **Issues its own JWTs** for native mobile authentication
2. **Manages passkeys** (WebAuthn/FIDO2) for secure, phishing-resistant auth
3. **Verifies Apple Sign In** as a bootstrap mechanism for identity
4. **Uses Keycloak** as user storage and for standard OIDC (web apps)
5. **Provides admin tooling** via CLI and MCP for debugging and management

This architecture enables fully native mobile UX without browser redirects while maintaining compatibility with standard OIDC for web applications.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CLIENT APPLICATIONS                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────┐              ┌──────────────────────┐         │
│  │   Mobile Apps        │              │     Web Apps         │         │
│  │   (iOS/Android)      │              │     (Browser)        │         │
│  │                      │              │                      │         │
│  │  • Apple Sign In SDK │              │  • Standard OIDC     │         │
│  │  • Native Passkeys   │              │  • Browser redirect  │         │
│  │  • Direct HTTP calls │              │  • Keycloak login    │         │
│  └──────────┬───────────┘              └──────────┬───────────┘         │
│             │                                     │                      │
└─────────────┼─────────────────────────────────────┼──────────────────────┘
              │                                     │
              ▼                                     ▼
┌─────────────────────────────────────┐  ┌─────────────────────────────────┐
│       IDENTIKEY CORE                │  │         KEYCLOAK                │
│       (This Repo)                   │  │         (User Store + OIDC)     │
├─────────────────────────────────────┤  ├─────────────────────────────────┤
│                                     │  │                                 │
│  Auth Endpoints:                    │  │  • User storage (Admin API)    │
│  • POST /apple-provision            │  │  • Groups/Guilds               │
│  • POST /passkey-register           │  │  • Roles & Permissions         │
│  • POST /passkey-auth/*             │  │  • Standard OIDC flows         │
│  • POST /token/refresh              │  │  • Session management          │
│  • GET /.well-known/jwks.json       │  │  • Event logging               │
│                                     │  │                                 │
│  Admin Layer:                       │  │                                 │
│  • CLI (kc users, kc auth-flows)    │◄─┼─► Admin REST API               │
│  • MCP Server (AI agents)           │  │                                 │
│                                     │  │                                 │
│  Data (PostgreSQL):                 │  │                                 │
│  • Passkeys                         │  │                                 │
│  • Devices                          │  │                                 │
│  • Refresh Tokens                   │  │                                 │
│                                     │  │                                 │
└─────────────────────────────────────┘  └─────────────────────────────────┘
              │                                     ▲
              │                                     │
              └─────────────────────────────────────┘
                        Keycloak Admin API
                        (User CRUD, Groups, Roles)
```

---

## Authentication Flows

### Flow 1: First-Time Apple Sign In → Passkey Enrollment

```
┌─────────────────────────────────────────────────────────────────┐
│ FIRST LOGIN (Apple → Passkey)                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. User taps "Sign in with Apple" in mobile app               │
│                                                                 │
│  2. iOS presents Apple Sign In (FaceID) → Apple identity token │
│                                                                 │
│  3. App calls: POST /apple-provision                            │
│     Request: { apple_token }                                    │
│     IdentiKey:                                                  │
│       - Verifies Apple token (JWKS validation)                 │
│       - Creates user in Keycloak (Admin API) if new            │
│       - Stores apple_sub as user attribute                     │
│     Response: { user_id, webauthn_challenge, rp_id }           │
│                                                                 │
│  4. App triggers native passkey creation (FaceID again)        │
│     Uses ASAuthorizationController (iOS)                        │
│                                                                 │
│  5. App calls: POST /passkey-register                           │
│     Request: { user_id, attestation }                          │
│     IdentiKey:                                                  │
│       - Validates attestation                                   │
│       - Stores passkey (credentialId, publicKey, signCount)    │
│       - Registers device as "master"                            │
│       - Signs and issues tokens                                 │
│     Response: { access_token, refresh_token, id_token }        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Flow 2: Subsequent Logins (Passkey Only)

```
┌─────────────────────────────────────────────────────────────────┐
│ SUBSEQUENT LOGINS (Passkey only)                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. App calls: POST /passkey-auth/start                         │
│     Response: { challenge }                                     │
│                                                                 │
│  2. App triggers native passkey auth (FaceID)                  │
│     ASAuthorizationController presents available passkeys       │
│                                                                 │
│  3. App calls: POST /passkey-auth/finish                        │
│     Request: { credential_id, authenticator_data, signature }  │
│     IdentiKey:                                                  │
│       - Looks up passkey by credential_id                      │
│       - Verifies signature against stored public key           │
│       - Updates sign count                                      │
│       - Issues tokens                                           │
│     Response: { access_token, refresh_token, id_token }        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Flow 3: Temporary Device Authorization

```
┌─────────────────────────────────────────────────────────────────┐
│ TEMPORARY DEVICE (QR-based)                                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  FRIEND'S DEVICE                     YOUR PHONE (MASTER)        │
│                                                                 │
│  1. Opens app, taps "Use                                        │
│     another device to log in"                                   │
│                                                                 │
│  2. Shows QR code:                   3. Scan QR with master     │
│     { session_id, device_info }         device camera           │
│                                                                 │
│                                      4. "Allow temporary access │
│                                         on [device]?"           │
│                                         [1hr] [4hr] [Deny]      │
│                                                                 │
│                                      5. FaceID to confirm       │
│                                         (passkey auth)          │
│                                                                 │
│  6. Receives temporary token         ← Pushed from IdentiKey    │
│     (scoped, time-limited,                                      │
│     no refresh token)                                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Token Structure

### Access Token (IdentiKey-signed)

```json
{
  "iss": "https://connect.identikey.io",
  "sub": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "aud": "morphist-mobile",
  "exp": 1738800000,
  "iat": 1738796400,
  "scope": "openid profile email",
  "device_id": "device_abc123",
  "device_trust": "master",
  "auth_method": "passkey",
  "email": "user@example.com",
  "email_verified": true
}
```

### Token Lifetimes

| Token | Lifetime | Notes |
|-------|----------|-------|
| Access Token | 15 minutes | Short-lived, stateless validation |
| Refresh Token | 30 days | Device-bound, rotated on use |
| ID Token | 1 hour | User profile claims |
| Temporary Access | 1-4 hours | No refresh, limited scope |

---

## Project Structure

```
identikey-core/
├── src/
│   ├── lib/
│   │   ├── keycloak/                 # Keycloak Admin API (existing)
│   │   │   ├── client.ts             # Authenticated client
│   │   │   ├── config.ts             # Configuration
│   │   │   ├── errors.ts             # Error types
│   │   │   ├── logger.ts             # Pino logging
│   │   │   ├── types.ts              # IdentiKey domain types
│   │   │   ├── mappers/              # KC → IdentiKey mapping
│   │   │   └── services/             # Domain services
│   │   │       ├── users.ts          # User operations
│   │   │       ├── auth-flows.ts     # Auth flow operations
│   │   │       └── index.ts
│   │   │
│   │   ├── auth/                     # NEW: Auth infrastructure
│   │   │   ├── jwt/
│   │   │   │   ├── signing.ts        # Token signing (ES256)
│   │   │   │   ├── verification.ts   # Token verification
│   │   │   │   ├── jwks.ts           # JWKS generation/serving
│   │   │   │   └── keys.ts           # Key management
│   │   │   ├── apple/
│   │   │   │   ├── verify.ts         # Apple token verification
│   │   │   │   └── jwks-cache.ts     # Apple JWKS caching
│   │   │   ├── webauthn/
│   │   │   │   ├── registration.ts   # Passkey registration
│   │   │   │   ├── authentication.ts # Passkey auth
│   │   │   │   └── attestation.ts    # Attestation validation
│   │   │   ├── devices/
│   │   │   │   ├── trust.ts          # Device trust management
│   │   │   │   └── temporary.ts      # Temp device auth
│   │   │   └── tokens/
│   │   │       ├── issue.ts          # Token issuance
│   │   │       ├── refresh.ts        # Token refresh
│   │   │       └── revoke.ts         # Token revocation
│   │   │
│   │   └── server/
│   │       ├── auth.ts
│   │       └── db/
│   │           ├── index.ts
│   │           └── schema.ts         # Drizzle schema
│   │
│   ├── mcp/                          # MCP server (existing)
│   │   ├── index.ts
│   │   └── tools/
│   │
│   ├── cli/                          # CLI (existing)
│   │   ├── index.ts
│   │   └── commands/
│   │
│   └── routes/                       # SvelteKit routes
│       ├── api/
│       │   ├── apple-provision/
│       │   │   └── +server.ts
│       │   ├── passkey-register/
│       │   │   └── +server.ts
│       │   ├── passkey-auth/
│       │   │   ├── start/+server.ts
│       │   │   └── finish/+server.ts
│       │   ├── token/
│       │   │   ├── refresh/+server.ts
│       │   │   └── revoke/+server.ts
│       │   └── introspect/
│       │       └── +server.ts
│       ├── .well-known/
│       │   ├── jwks.json/+server.ts
│       │   └── openid-configuration/+server.ts
│       └── +page.svelte              # Future web UI
│
├── docs/
└── ...
```

---

## Database Schema

```sql
-- Passkey credentials (WebAuthn)
CREATE TABLE passkeys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,           -- Keycloak user ID
  credential_id TEXT NOT NULL UNIQUE,
  public_key BYTEA NOT NULL,       -- COSE format
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports TEXT[],               -- ['internal', 'hybrid', etc.]
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ
);

-- Device registry
CREATE TABLE devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  device_fingerprint TEXT,
  device_name TEXT,
  is_master BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ
);

-- Refresh tokens (for revocation tracking)
CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash TEXT NOT NULL UNIQUE,  -- SHA-256 of token
  user_id UUID NOT NULL,
  device_id UUID REFERENCES devices(id),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_passkeys_user_id ON passkeys(user_id);
CREATE INDEX idx_passkeys_credential_id ON passkeys(credential_id);
CREATE INDEX idx_devices_user_id ON devices(user_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
```

---

## Technology Stack

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| Runtime | Bun | latest | Fast JS runtime |
| Framework | SvelteKit | 2.x | API routes + future web UI |
| Language | TypeScript | 5.x | Type safety |
| Keycloak Client | @keycloak/keycloak-admin-client | 25.x | User storage |
| MCP | @modelcontextprotocol/sdk | 1.x | AI agent integration |
| CLI | citty | 0.1.x | CLI framework |
| Validation | zod | 3.x | Schema validation |
| Logging | pino | 9.x | Structured logging |
| Database | PostgreSQL + Drizzle | latest | Passkeys, devices, tokens |
| Crypto | Node crypto / jose | native | JWT signing |
| WebAuthn | @simplewebauthn/server | latest | Passkey validation |

---

## Security Architecture

### Key Management

- **Signing Keys:** ES256 (ECDSA with P-256 curve)
- **Storage:** Environment variable (dev) or secret manager (prod)
- **Rotation:** Add new key to JWKS, sign with new key, retire old after expiry
- **Key ID (kid):** SHA-256 thumbprint of public key

### Token Security

- **Access Tokens:** Short-lived (15min), stateless validation via JWKS
- **Refresh Tokens:** Device-bound, stored hash for revocation check
- **Token Binding:** `device_id` claim ties token to specific device

### API Security

- **Rate Limiting:** All auth endpoints rate-limited
- **Apple Verification:** Always server-side, never trust client claims
- **Passkey Attestation:** Validate attestation format and signature
- **HTTPS Only:** All endpoints require TLS

---

## Integration Points

### Keycloak Admin API

Used for:
- User CRUD (create on Apple provision, lookup, update)
- Storing `apple_sub` as user attribute
- Group/guild membership
- Role assignments

Not used for:
- Token issuance (mobile)
- Session management (mobile)
- Auth flow execution (mobile)

### Apple Identity Services

- JWKS endpoint: `https://appleid.apple.com/auth/keys`
- Token issuer: `https://appleid.apple.com`
- Audience: Your Services ID (e.g., `ai.morphist.app`)

### Resource Servers (Morphist API, etc.)

- Validate tokens via JWKS at `/.well-known/jwks.json`
- Or use introspection endpoint at `/introspect`
- Check `device_trust` claim for authorization decisions

---

## Architecture Decision Records

### ADR-001: Service-First Architecture ✅ (Existing)

Core service layer independent of interfaces — enables code reuse.

### ADR-002: IdentiKey Abstraction Over Keycloak ✅ (Existing)

Hide Keycloak terminology, expose IdentiKey domain concepts.

### ADR-003: IdentiKey as Token Issuer (NEW)

**Decision:** IdentiKey signs its own JWTs rather than using Keycloak token issuance.

**Rationale:**
1. No Keycloak preview features needed
2. Full control over token claims and structure
3. Required for device trust model
4. Foundation for advanced identity features

**Trade-off:** Must manage signing keys (table stakes for identity platform).

### ADR-004: Apple as Bootstrap Mechanism (NEW)

**Decision:** Use Apple Sign In only for initial identity verification, immediately enroll passkey.

**Rationale:**
1. No vendor lock-in for ongoing auth
2. Passkeys are phishing-resistant, device-bound
3. Standards-based (FIDO2/WebAuthn)
4. User owns their credential

**Trade-off:** Two biometric prompts on first login (both feel natural).

### ADR-005: Keycloak as User Store (NEW)

**Decision:** Keep Keycloak for user storage via Admin API, bypass auth flows for mobile.

**Rationale:**
1. Admin UI for user management
2. Existing infrastructure
3. Standard OIDC still works for web apps
4. Gradual migration path if needed

### ADR-006: Device Trust Model (NEW)

**Decision:** Implement master vs temporary device distinction from the start.

**Rationale:**
1. Security: limits access on untrusted devices
2. UX: users can safely use friend's phone
3. Architecture: foundation for device management

---

## Document Status

**Status:** ✅ Updated
**Version:** 2.0
**Updated:** 2026-02-05

---

_This architecture enables IdentiKey to be a true identity platform with native mobile auth while maintaining Keycloak integration for user storage and web OIDC._
