# IdentiKey Apple Authentication Architecture Analysis

**Date**: February 5, 2026
**Status**: Analysis Complete, Ready for Architecture Design
**Authors**: Duke Jones, AI Assistant

---

## Executive Summary

This document captures the analysis and architectural decisions for implementing Apple Sign In integration with IdentiKey for the Morphist mobile application. After evaluating multiple approaches—including Keycloak's native token exchange, community plugins, and custom implementations—we've arrived at a hybrid architecture that:

1. Uses Apple Sign In as a **one-time identity verification** mechanism
2. Immediately provisions a **passkey credential** for ongoing authentication
3. Has IdentiKey issue its own **JWT tokens** (not relying on Keycloak's token issuance)
4. Supports **device trust levels** (master vs temporary devices)
5. Uses **stable, non-preview Keycloak features** only

This approach positions IdentiKey as a true identity layer rather than a Keycloak wrapper, while providing a seamless native mobile UX with no browser or WebView requirements.

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Options Evaluated](#options-evaluated)
3. [Chosen Architecture](#chosen-architecture)
4. [Key Design Decisions](#key-design-decisions)
5. [Technical Background](#technical-background)
6. [Implementation Considerations](#implementation-considerations)
7. [Open Questions](#open-questions)
8. [References](#references)

---

## Problem Statement

### Current State

Morphist mobile app supports two authentication methods:
- **IdentiKey** (Keycloak-based OIDC): Full-featured accounts with email/password
- **Apple Sign In**: Required for iOS App Store compliance

These currently create **separate user identities**, causing:
- Two different user IDs for the same person
- Two separate databases per user
- No way to "upgrade" Apple users to full IdentiKey accounts
- Fragmented user experience

### Constraints

1. **App Store Compliance**: Apple requires native Sign In with Apple SDK; cannot redirect through IdentiKey's hosted login
2. **UX Requirements**: Fully native experience; no browser redirects or WebViews
3. **Security**: Production identity system with growing user base
4. **Future-Proofing**: IdentiKey is building toward guardian-based recovery and advanced identity features

### Goal

Create a unified identity system where:
- Apple Sign In users get IdentiKey accounts automatically
- Single `sub` (user ID) regardless of auth method
- Native mobile UX throughout
- Foundation for IdentiKey's product roadmap (device trust, guardian recovery, etc.)

---

## Options Evaluated

### Option 1: Keycloak V1 Token Exchange + klausbetz Plugin

**Description**: Use Keycloak's legacy token exchange feature with the [klausbetz/apple-identity-provider-keycloak](https://github.com/klausbetz/apple-identity-provider-keycloak) plugin.

**How it works**:
```
Apple token → Keycloak token endpoint → V1 exchange → Plugin validates → User provisioned → Tokens issued
```

**Requirements**:
- Enable preview features: `--features=token-exchange,admin-fine-grained-authz`
- Install klausbetz plugin JAR (v1.15.0-1.16.0 for KC 26.4.7)
- Configure Apple IDP and token exchange permissions

**Pros**:
- Minimal code (~20 lines in mobile app)
- Native Keycloak user provisioning and session management
- Plugin is battle-tested (261 stars, active maintenance)
- Works now

**Cons**:
- Requires **preview features** (may break on upgrades)
- Tied to **FGAP V1** (legacy permission model being phased out)
- External plugin dependency (must track compatibility)
- Keycloak explicitly warns: "may not be backwards compatible"
- CVE-2022-1245 history (fixed, but indicates architectural issues)

**Testing Results**:
```bash
# Without preview features enabled:
curl -X POST ".../token" -d "subject_issuer=apple" ...
# Error: "Parameter 'subject_issuer' is not supported for standard token exchange"

# Confirms V1 features are required for external IDP token exchange
```

**Verdict**: Pragmatic for startups, but not suitable for IdentiKey's positioning as an identity company.

---

### Option 2: Keycloak V2 Token Exchange (Standard)

**Description**: Use Keycloak 26.2+'s RFC 8693-compliant standard token exchange.

**Status**: V2 is officially supported and enabled by default.

**Limitation**: V2 only supports **internal-to-internal** token exchange (Keycloak token → Keycloak token). It does **not** support external identity provider tokens.

| Capability | V2 (Standard) | V1 (Legacy) |
|------------|---------------|-------------|
| Internal → Internal | ✅ | ✅ |
| External → Internal | ❌ | ✅ |
| Apple token exchange | ❌ | ✅ |
| Preview feature | No | Yes |

**Verdict**: Not viable for Apple Sign In integration.

---

### Option 3: JWT Authorization Grant (RFC 7523)

**Description**: Use Keycloak 26.5's new JWT Authorization Grant to exchange external JWTs for Keycloak tokens.

**How it works**:
```
Apple JWT → Keycloak token endpoint → JWT Authorization Grant → Tokens issued
```

**Critical Limitation**: Requires user to be **pre-linked** to the identity provider:
> "The Keycloak user should be previously linked to the Identity Provider."

This means JWT Authorization Grant cannot handle **first-time user provisioning**—the exact use case we need.

**Also**: Still requires preview features (`--features=jwt-authorization-grant`).

**Verdict**: Not viable for first-time Apple Sign In users.

---

### Option 4: Custom Endpoint with Keycloak Admin API

**Description**: Build a custom endpoint that verifies Apple tokens, manages users via Admin API, and somehow issues tokens.

**The Token Issuance Problem**:

Keycloak Admin API is for **management**, not authentication. It cannot issue user tokens.

| Token Issuance Method | Preview Feature? | Works for Apple? |
|-----------------------|------------------|------------------|
| Direct Access Grant | No | ❌ Requires password |
| Service Account + V1 Exchange | Yes | ⚠️ Back to V1 |
| JWT Authorization Grant | Yes | ❌ Needs pre-linked user |
| Custom Keycloak SPI | No | ✅ But requires Java |

**Verdict**: Viable, but requires either preview features or custom SPI development.

---

### Option 5: Custom Keycloak SPI (Java/Kotlin)

**Description**: Write a custom Keycloak authenticator/provider that handles Apple tokens natively.

**What it does**:
- Registers custom grant type or authenticator
- Validates Apple tokens
- Creates/links users via Keycloak's internal APIs
- Issues tokens via Keycloak's TokenManager

**Pros**:
- No preview features
- No external plugin dependency
- Full control

**Cons**:
- Significant development (~500-1000 lines of Java/Kotlin)
- Deep Keycloak internals knowledge required
- Same SPI stability concerns as klausbetz plugin
- "Who wants to do Java SPI development?"

**Verdict**: This is essentially reimplementing klausbetz. Not worth the effort.

---

### Option 6: Hybrid Apple → Passkey Flow (CHOSEN)

**Description**: Use Apple Sign In as a one-time identity verification, immediately enroll a passkey, have IdentiKey issue its own tokens.

**How it works**:
```
1. Apple Sign In → Get verified identity (email, name, Apple sub)
2. Custom endpoint creates user, returns WebAuthn challenge
3. Native passkey registration (FaceID prompt)
4. Custom endpoint stores passkey, signs and issues IdentiKey tokens
5. Subsequent logins use passkey only (no Apple dependency)
```

**Key insight**: Apple becomes a **bootstrap mechanism**, not an ongoing auth provider.

**Pros**:
- No preview features (passkeys are fully supported in KC 26)
- No plugin dependencies
- Fully native UX (no browser/WebView)
- User ends up with standards-based credential (FIDO2/WebAuthn)
- Positions IdentiKey as a real identity layer
- Foundation for device trust, guardian recovery, etc.

**Cons**:
- More upfront development
- IdentiKey becomes a token issuer (key management responsibility)
- Two-step first-time UX (Apple + passkey, both biometric)

**Verdict**: Best long-term architecture for IdentiKey's product vision.

---

## Chosen Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ FIRST LOGIN (Apple → Passkey)                                   │
├─────────────────────────────────────────────────────────────────┤
│ 1. User taps "Sign in with Apple"                               │
│ 2. iOS presents Apple Sign In (FaceID) → Apple identity token   │
│                                                                 │
│ 3. App calls: POST /identikey/apple-provision                   │
│    - IdentiKey verifies Apple token (JWKS validation)           │
│    - Creates/finds user in Keycloak (Admin API)                 │
│    - Returns: { user_id, webauthn_challenge, rp_id }            │
│                                                                 │
│ 4. App triggers native passkey creation (FaceID again)          │
│    - Uses ASAuthorizationController (iOS) / CredentialManager   │
│                                                                 │
│ 5. App calls: POST /identikey/passkey-register                  │
│    - IdentiKey validates attestation, stores passkey            │
│    - Registers device as "master"                               │
│    - Signs tokens with IdentiKey private key                    │
│    - Returns: { access_token, refresh_token, id_token }         │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ SUBSEQUENT LOGINS (Passkey only)                                │
├─────────────────────────────────────────────────────────────────┤
│ 1. App calls: POST /identikey/passkey-auth/start                │
│    - Returns: { challenge }                                     │
│                                                                 │
│ 2. App triggers native passkey auth (FaceID)                    │
│                                                                 │
│ 3. App calls: POST /identikey/passkey-auth/finish               │
│    - Validates signature against stored public key              │
│    - Returns: { access_token, refresh_token }                   │
└─────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

```
┌─────────────────────────────────────────────────────────────────┐
│ IDENTIKEY (New Responsibilities)                                │
├─────────────────────────────────────────────────────────────────┤
│ JWT Signing & Validation                                        │
│ ├── Generate/rotate signing keys (EdDSA Ed25519)                 │
│ ├── Publish JWKS at /.well-known/jwks.json                      │
│ ├── Sign access_token, refresh_token, id_token                  │
│ └── Token introspection endpoint                                │
│                                                                 │
│ Auth Endpoints                                                  │
│ ├── POST /apple-provision                                       │
│ ├── POST /passkey-register                                      │
│ ├── POST /passkey-auth/start                                    │
│ ├── POST /passkey-auth/finish                                   │
│ ├── POST /token/refresh                                         │
│ └── POST /device-authorize (temporary device flow)              │
│                                                                 │
│ Apple Token Verification                                        │
│ ├── Fetch Apple JWKS (https://appleid.apple.com/auth/keys)      │
│ ├── Validate JWT signature                                      │
│ └── Verify claims (iss, aud, exp, sub)                          │
│                                                                 │
│ WebAuthn/Passkey Management                                     │
│ ├── Generate registration challenges                            │
│ ├── Validate attestations                                       │
│ ├── Store credentials                                           │
│ └── Validate authentication assertions                          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ KEYCLOAK (Reduced Role)                                         │
├─────────────────────────────────────────────────────────────────┤
│ User Storage                                                    │
│ ├── CRUD via Admin API                                          │
│ ├── User attributes (apple_sub, email, etc.)                    │
│ └── Admin UI for user management                                │
│                                                                 │
│ Standard OIDC (for web apps if needed)                          │
│ ├── Browser-based login flows                                   │
│ └── Traditional IdP federation                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ MORPHIST APP                                                    │
├─────────────────────────────────────────────────────────────────┤
│ Native Auth UI                                                  │
│ ├── Apple Sign In button                                        │
│ ├── Passkey prompts (ASAuthorizationController)                 │
│ └── Device authorization UI                                     │
│                                                                 │
│ Token Management                                                │
│ ├── Store tokens securely (Keychain)                            │
│ ├── Refresh tokens before expiry                                │
│ └── Validate device_trust claims                                │
└─────────────────────────────────────────────────────────────────┘
```

### Device Trust Model

```
┌─────────────────────────────────────────────────────────────────┐
│ DEVICE TYPES                                                    │
├─────────────────────────────────────────────────────────────────┤
│ MASTER DEVICE                                                   │
│ ├── Has passkey in secure enclave                               │
│ ├── Has refresh token (long-lived)                              │
│ ├── Can authorize temporary devices                             │
│ ├── Can register new master devices                             │
│ └── Full database sync                                          │
│                                                                 │
│ TEMPORARY DEVICE                                                │
│ ├── No passkey stored                                           │
│ ├── Short-lived access token only (no refresh)                  │
│ ├── Limited scope (configurable)                                │
│ ├── Session expires automatically                               │
│ └── Read-only or no database sync                               │
└─────────────────────────────────────────────────────────────────┘

TEMPORARY DEVICE AUTHORIZATION FLOW:
┌─────────────────────────────────────────────────────────────────┐
│ FRIEND'S DEVICE                     YOUR PHONE (MASTER)         │
│                                                                 │
│ 1. "Use another device to log in"                               │
│                                                                 │
│ 2. Shows QR code:                   3. Scan QR                  │
│    { session_id, device_info }                                  │
│                                                                 │
│                                     4. "Allow temporary access  │
│                                        on [device]?"            │
│                                        [1hr] [4hr] [Deny]       │
│                                                                 │
│                                     5. FaceID to confirm        │
│                                                                 │
│ 6. Receives temporary token         ← Pushed from IdentiKey     │
│    (scoped, time-limited)                                       │
└─────────────────────────────────────────────────────────────────┘
```

### Token Structure

```json
// Access Token (signed by IdentiKey)
{
  "iss": "https://connect.identikey.io",
  "sub": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "aud": "morphist-mobile",
  "exp": 1738800000,
  "iat": 1738796400,
  "scope": "openid profile email",
  "device_id": "device_abc123",
  "device_trust": "master",      // or "temporary"
  "auth_method": "passkey",      // or "apple_provision"
  "email": "user@example.com",
  "email_verified": true
}
```

---

## Key Design Decisions

### Decision 1: Apple as Bootstrap, Not Ongoing Auth

**Choice**: Use Apple Sign In only for initial identity verification, then immediately enroll a passkey.

**Alternatives Considered**:
- Apple as federated IDP (ongoing dependency on Apple)
- Apple token stored/refreshed (security concerns, Apple rate limits)

**Rationale**:
1. **No vendor lock-in**: User isn't dependent on Apple for ongoing access
2. **Stronger security**: Passkeys are phishing-resistant, device-bound
3. **Standards-based**: FIDO2/WebAuthn is open standard
4. **Future-proof**: Passkeys are the industry direction
5. **IdentiKey positioning**: "We verify who you are, then you own your identity"

**Trade-off**: Slightly more complex first-time UX (two biometric prompts), but both feel like "just logging in."

---

### Decision 2: IdentiKey Issues Its Own Tokens

**Choice**: IdentiKey signs JWTs with its own keys rather than using Keycloak's token issuance.

**Alternatives Considered**:
- Keycloak V1 token exchange (preview features, legacy)
- Keycloak custom SPI (Java development, maintenance burden)
- Keycloak service account impersonation (hacky)

**Rationale**:
1. **No preview features**: Avoids "may not be backwards compatible" risk
2. **Full control**: Custom claims, token structure, expiry policies
3. **Product foundation**: Needed for device trust, guardian recovery, advanced features
4. **Simpler architecture**: Direct path from auth → tokens, no Keycloak auth flow gymnastics

**Trade-off**: Must manage signing keys (generation, rotation, secure storage). This is table stakes for an identity company.

---

### Decision 3: Keycloak as User Store (Not Auth Provider for Mobile)

**Choice**: Keep Keycloak for user storage via Admin API, but bypass its auth flows for mobile.

**Alternatives Considered**:
- Full custom user database (more work, lose admin UI)
- Keep Keycloak auth flows (requires browser/WebView or preview features)

**Rationale**:
1. **Admin UI**: Keycloak provides user management, audit logs, etc.
2. **Existing infrastructure**: IdentiKey already runs Keycloak
3. **Web compatibility**: Standard OIDC still works for web apps
4. **Gradual migration**: Can phase out Keycloak later if needed

**Trade-off**: Dependency on Keycloak Admin API for user CRUD. Acceptable.

---

### Decision 4: Fully Native Mobile UX (No Browser/WebView)

**Choice**: All auth flows happen via native APIs and direct HTTP calls.

**Alternatives Considered**:
- System browser redirect (standard OIDC)
- WebView embedded auth (common but problematic)

**Rationale**:
1. **UX**: Browser redirects are jarring on mobile
2. **WebView issues**: Credential manager access is unreliable
3. **Passkey compatibility**: Native APIs (ASAuthorizationController) work best
4. **Brand consistency**: Auth feels like part of the app

**Trade-off**: More custom code, but better user experience.

---

### Decision 5: Handle Apple Private Relay Email

**Choice**: Support Apple's "Hide My Email" feature where users get addresses like `abc123@privaterelay.appleid.com`.

**Implementation**:
- Use `apple_sub` (stable user ID) as primary identifier, not email
- Store both `apple_sub` and `email`
- Register IdentiKey's sending domain in Apple Developer portal for email forwarding
- Support "Sign in with Apple" as recovery method (matches on `apple_sub`)

**Rationale**:
1. **Privacy respect**: Users choose private relay for a reason
2. **Email still works**: Magic links forward through relay
3. **Recovery path**: Apple Sign In re-verification as alternative to magic link

---

### Decision 6: Device Trust Levels

**Choice**: Implement master device vs temporary device distinction from the start.

**Implementation**:
- `device_trust` claim in tokens ("master" or "temporary")
- Master devices have passkeys and refresh tokens
- Temporary devices get short-lived access tokens only
- Master device authorizes temporary access via QR scan

**Rationale**:
1. **Security**: Prevents full account access on untrusted devices
2. **UX**: Users can safely use friend's phone
3. **Architecture**: Builds foundation for device management features
4. **Database sync**: Can limit sync scope based on trust level

---

## Technical Background

### Keycloak Token Exchange History

Keycloak has two token exchange implementations:

**V1 (Legacy) - Preview Feature**
- Enabled via `--features=token-exchange,admin-fine-grained-authz`
- Supports external IDP token exchange (`subject_issuer` parameter)
- Required for Apple token → Keycloak token
- Tied to FGAP V1 (legacy permission model)
- CVE-2022-1245 history (privilege escalation, fixed in 18.0.0)
- Explicitly warned: "may not be backwards compatible"

**V2 (Standard) - Supported**
- Enabled by default in Keycloak 26.2+
- RFC 8693 compliant
- Only supports internal-to-internal exchange
- Cannot exchange external IDP tokens

**Future Direction**:
- JWT Authorization Grant (RFC 7523) for external tokens
- Requires pre-linked users (no first-time provisioning)
- Also a preview feature currently

### klausbetz Apple Identity Provider Plugin

- **Repository**: https://github.com/klausbetz/apple-identity-provider-keycloak
- **Stars**: 261 (actively maintained)
- **Keycloak 26.4.7 compatibility**: v1.15.0 - v1.16.0
- **What it does**: Adds Apple as IDP, handles token exchange via V1
- **Requires**: V1 preview features enabled
- **Listed on**: Official Keycloak extensions page

### WebAuthn/Passkey Support

- **Keycloak 26**: Full WebAuthn support (not preview)
- **iOS**: ASAuthorizationController, ASAuthorizationPlatformPublicKeyCredentialProvider
- **Android**: FIDO2 API, Credential Manager (Android 14+)
- **Sync**: iOS Keychain syncs via iCloud, Android via Google Password Manager
- **Cross-platform**: Users switching iOS ↔ Android need re-enrollment or recovery

### Apple Identity Token

Apple Sign In returns an identity token (JWT) with:
```json
{
  "iss": "https://appleid.apple.com",
  "aud": "ai.morphist.app",  // Your Services ID
  "exp": 1738800000,
  "iat": 1738796400,
  "sub": "001234.abcdef123456.7890",  // Stable user ID
  "email": "user@example.com",        // Or private relay
  "email_verified": true,
  "is_private_email": false,          // True if relay
  "auth_time": 1738796400
}
```

**Verification**:
1. Fetch JWKS from `https://appleid.apple.com/auth/keys`
2. Verify signature (RS256)
3. Check `iss` = `https://appleid.apple.com`
4. Check `aud` = your Services ID
5. Check `exp` > now

**First sign-in only**: `email`, `given_name`, `family_name` are only provided on first auth. Must be captured and stored.

---

## Implementation Considerations

### IdentiKey Backend Requirements

**New Endpoints**:
| Endpoint | Purpose |
|----------|---------|
| `POST /apple-provision` | Verify Apple token, create user, return WebAuthn challenge |
| `POST /passkey-register` | Store passkey credential, issue tokens |
| `POST /passkey-auth/start` | Return authentication challenge |
| `POST /passkey-auth/finish` | Verify assertion, issue tokens |
| `POST /token/refresh` | Refresh access token |
| `POST /device-authorize` | QR-based temporary device auth |
| `GET /.well-known/jwks.json` | Public keys for token validation |
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `POST /introspect` | Token validation for resource servers |

**Key Management**:
- Generate EdDSA Ed25519 key pair
- Store private key in secure vault (AWS Secrets Manager, HashiCorp Vault)
- Implement key rotation (add new key, sign with new, remove old after expiry)
- Cache Apple JWKS with TTL

**Data Models**:
```
Users (via Keycloak Admin API)
├── id (UUID)
├── email
├── email_verified
├── apple_sub (indexed)
├── given_name
├── family_name
└── created_at

Passkeys (IdentiKey DB or Keycloak)
├── id
├── user_id
├── credential_id (base64)
├── public_key (COSE)
├── sign_count
├── created_at
└── last_used_at

Devices
├── id
├── user_id
├── device_fingerprint
├── is_master
├── created_at
└── last_seen_at

Refresh Tokens
├── token_hash
├── user_id
├── device_id
├── expires_at
└── revoked
```

### Morphist App Requirements

**Dependencies**:
- `expo-apple-authentication` (Apple Sign In)
- Native passkey APIs via bridge (or expo module)
- Secure storage (Keychain/Keystore)

**Flows to Implement**:
1. First-time Apple Sign In → Passkey registration
2. Subsequent passkey authentication
3. Token refresh
4. Temporary device authorization (QR scan)
5. Recovery via Apple re-verification
6. Recovery via email magic link

### Security Considerations

1. **Apple token verification**: Always verify server-side, never trust client claims
2. **Passkey attestation**: Validate attestation format and signature
3. **Rate limiting**: Apply to all auth endpoints
4. **Device fingerprinting**: Reasonable heuristics, not tracking
5. **Refresh token rotation**: Issue new refresh token on each use
6. **Token revocation**: Support immediate revocation for all device's tokens

---

## Open Questions

### For Immediate Design Phase

1. **Passkey storage location**: Store in Keycloak user credentials (via Admin API) or IdentiKey's own DB?
   - Keycloak: Unified user data, but complex Admin API calls
   - Own DB: Simpler, more control, but separate data store

2. **Refresh token strategy**: Single long-lived token or rotating tokens?
   - Rotating is more secure but adds complexity

3. **Magic link implementation**: Use Keycloak's existing flow or build custom?
   - Keycloak: Proven, but requires browser redirect
   - Custom: Fits native UX, more work

### For Future Phases

1. **Guardian recovery**: How do guardians authorize recovery? What do they hold?
2. **Cross-platform passkey sync**: Support for users switching iOS ↔ Android?
3. **Multiple passkeys per user**: Allow backup passkeys on different devices?
4. **Biometric change detection**: What happens if user re-enrolls FaceID?

---

## References

### Keycloak Documentation
- [Token Exchange](https://www.keycloak.org/securing-apps/token-exchange)
- [JWT Authorization Grant](https://www.keycloak.org/securing-apps/jwt-authorization-grant)
- [Fine-Grained Admin Permissions](https://www.keycloak.org/2025/05/fgap-kc-26-2)
- [Standard Token Exchange in KC 26.2](https://keycloak.org/2025/05/standard-token-exchange-kc-26-2)

### Apple Documentation
- [Sign In with Apple REST API](https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api)
- [Verifying a User](https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/verifying_a_user)
- [Apple JWKS Endpoint](https://appleid.apple.com/auth/keys)

### WebAuthn/Passkey
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [Apple Passkeys](https://developer.apple.com/documentation/authenticationservices/public-private_key_authentication)
- [Android Credential Manager](https://developer.android.com/training/sign-in/credential-manager)

### RFCs
- [RFC 8693 - OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 7523 - JWT Authorization Grant](https://rfc-editor.org/rfc/rfc7523.html)
- [RFC 7521 - Assertion Framework](https://datatracker.ietf.org/doc/html/rfc7521)

### Plugins
- [klausbetz/apple-identity-provider-keycloak](https://github.com/klausbetz/apple-identity-provider-keycloak)
- [Keycloak Extensions Page](https://www.keycloak.org/extensions)

---

## Next Steps

1. **Architecture Document**: Break this into formal architecture with diagrams
2. **API Specification**: OpenAPI spec for all IdentiKey endpoints
3. **Data Model Design**: Final schema for passkeys, devices, tokens
4. **Security Review**: Threat modeling for the auth flows
5. **Implementation Tasks**: Epic and stories for development
6. **Keycloak Configuration**: Document Admin API usage patterns

---

## Appendix: Original Spec Reference

The original spec (`identikey-apple-provision-spec-1f5cc5.md`) proposed a custom `/auth/apple/provision` endpoint. This analysis validates that approach while expanding it to include:

- Passkey enrollment (not just token issuance)
- IdentiKey as token issuer (not relying on Keycloak token exchange)
- Device trust model
- Recovery flows

The core insight remains: Apple Sign In requires native SDK, so we must handle it outside Keycloak's standard flows.
