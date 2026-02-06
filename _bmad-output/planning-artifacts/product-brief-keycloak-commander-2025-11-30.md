# Product Brief: IdentiKey Core

**Date:** 2025-11-30 (Updated: 2026-02-05)
**Author:** Master Dorje
**Context:** Identity Platform Backend

---

## Executive Summary

**IdentiKey Core** is the identity platform backend for IdentiKey. Originally scoped as a Keycloak admin wrapper, it has evolved into a **full identity layer** that:

1. **Issues its own JWTs** for native mobile authentication
2. **Manages passkeys** (WebAuthn/FIDO2) as the primary credential
3. **Verifies Apple Sign In** as a bootstrap mechanism
4. **Uses Keycloak** for user storage and standard OIDC (web apps)
5. **Provides admin tooling** via CLI and MCP

### Key Insight

Mobile apps can't use browser-based OIDC redirects elegantly. Apple Sign In requires native SDK. Keycloak's token exchange for external IDPs requires preview features. Solution: **IdentiKey becomes the token issuer** for mobile, using Keycloak only as a user store.

---

## Core Vision

### Problem Statement

IdentiKey needs to support native mobile authentication with:

- Apple Sign In (required for iOS App Store)
- No browser redirects or WebViews
- Passkey-based ongoing auth (phishing-resistant)
- Device trust levels (master vs temporary)
- Foundation for guardian-based recovery (future)

Keycloak alone can't provide this without preview features or custom SPIs.

### Solution

**Hybrid Architecture:**

```
Mobile App → IdentiKey Core → Keycloak (user store)
                ↓
         Issues JWTs directly
```

- Apple Sign In verifies identity once
- Passkey enrolled immediately for ongoing auth
- IdentiKey signs tokens with its own keys
- Keycloak stores users, groups, roles
- Standard OIDC via Keycloak still works for web apps

---

## Target Users

### Primary Users (Now)

**Master Dorje** — Building the IdentiKey platform. Uses:
- CLI + MCP for debugging and user management
- Auth endpoints for Morphist mobile app

**Morphist Mobile App** — First client application. Uses:
- Apple Sign In → Passkey flow
- IdentiKey-issued JWTs for API access

### Future Users

**Guild Administrators** — Will use web UI for delegated user management.

**Resource Servers** — Will validate IdentiKey JWTs via JWKS.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     MOBILE APPS                                  │
│  • Apple Sign In SDK       • Native Passkeys                    │
│  • Direct HTTP calls       • IdentiKey JWTs                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    IDENTIKEY CORE                                │
├─────────────────────────────────────────────────────────────────┤
│  Auth Endpoints:                                                 │
│  • POST /apple-provision    → Verify Apple, create user         │
│  • POST /passkey-register   → Enroll passkey, issue tokens      │
│  • POST /passkey-auth/*     → Authenticate with passkey         │
│  • POST /token/refresh      → Refresh access token              │
│  • GET /.well-known/jwks    → Public keys for validation        │
│                                                                  │
│  Admin Layer:                                                    │
│  • CLI (kc users, kc auth-flows)                                │
│  • MCP Server (AI agents)                                       │
│                                                                  │
│  Data (PostgreSQL):                                             │
│  • Passkeys, Devices, Refresh Tokens                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       KEYCLOAK                                   │
│  • User storage (Admin API)    • Groups/Guilds                  │
│  • Roles & Permissions         • Standard OIDC (web apps)       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Scope

### Phase 1: Admin Tooling ✅ Complete

| Feature | Status |
|---------|--------|
| Keycloak connection, config, errors | ✅ Done |
| User CRUD (list, get, create, update, delete) | ✅ Done |
| Password reset, credential management | ✅ Done |
| Auth flow inspection | ✅ Done |
| MCP server for AI agents | ✅ Done |
| CLI for human testing | ✅ Done |

### Phase 2: Native Mobile Auth (Current)

| Feature | Status |
|---------|--------|
| JWT signing infrastructure | 🔲 New |
| JWKS + OIDC discovery endpoints | 🔲 New |
| Apple token verification | 🔲 New |
| Passkey registration (WebAuthn) | 🔲 New |
| Passkey authentication | 🔲 New |
| Auth REST endpoints | 🔲 New |
| Device trust model | 🔲 New |
| Token refresh + revocation | 🔲 New |

### Phase 3: Production Hardening (Future)

- Key rotation
- Temporary device authorization (QR flow)
- Recovery flows (Apple re-verification, email magic link)
- Security audit

### Phase 4: Web UI (Future)

- SvelteKit admin dashboard
- Delegated administration for guild admins

---

## Technical Preferences

- **Runtime:** Bun
- **Framework:** SvelteKit (API routes + future web UI)
- **Language:** TypeScript
- **Database:** PostgreSQL + Drizzle ORM
- **JWT:** EdDSA with Ed25519 (~128-bit security)
- **WebAuthn:** `@simplewebauthn/server`
- **Keycloak:** Admin API for user storage

### IdentiKey Terminology

| Keycloak Term | IdentiKey Term |
|---------------|----------------|
| Realm | _(hidden — always identikey)_ |
| Client | App |
| Group | Guild |
| Authentication Flow | Login Flow |

---

## Success Metrics

### Phase 1 ✅
- [x] CLI can list/create/update users
- [x] MCP tools work in Cursor
- [x] Auth flows can be inspected

### Phase 2 (Target)
- [ ] Morphist app can Sign In with Apple → Passkey → Get tokens
- [ ] Tokens validate via JWKS
- [ ] Device trust reflected in token claims
- [ ] Refresh flow works

### Phase 3 (Target)
- [ ] Keys can be rotated without downtime
- [ ] Temporary device authorization works
- [ ] At least one recovery flow implemented

---

## Difficulty Assessment

| Epic | Difficulty | Estimate |
|------|------------|----------|
| JWT Infrastructure | Medium | 2-3 days |
| Apple Verification | Easy | 1 day |
| Passkey Management | Medium-Hard | 4-5 days |
| Auth Endpoints | Medium | 2-3 days |
| Device Trust | Medium | 2-3 days |
| Token Refresh | Medium | 2 days |

**Total:** ~13-17 days of focused work

This is achievable bc:
1. Good libraries exist (`jose`, `@simplewebauthn/server`)
2. Keycloak user storage layer already works
3. Architecture is well-documented
4. Incremental — each epic delivers testable value

---

## Out of Scope (Current)

- Multi-realm support
- Guardian-based recovery (future phase)
- Cross-platform passkey sync (platform limitation)
- Keycloak deployment/operations
- Web UI (future phase)

---

## Document Status

**Status:** ✅ Updated
**Updated By:** AI Assistant
**Updated Date:** 2026-02-05

---

_This Product Brief captures IdentiKey Core — the identity platform backend for native mobile auth and Keycloak integration._

_Related:_
- [PRD](./prd.md) — Detailed requirements
- [Architecture](./architecture.md) — Technical design
- [Epics](./epics.md) — Implementation breakdown
- [Apple Auth Analysis](./identikey-apple-auth-architecture-analysis.md) — Native auth deep dive
