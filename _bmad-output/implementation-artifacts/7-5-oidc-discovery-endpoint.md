# Story 7.5: OIDC Discovery Endpoint

**Status:** ready-for-dev  
**Epic:** 7 - JWT Infrastructure  
**FR Coverage:** FR129  
**Story Key:** 7-5-oidc-discovery-endpoint

---

## Story

As a **client application**,  
I want **OIDC discovery metadata** at a well-known URL,  
So that **I can auto-configure token validation** (JWKS URI, introspection, etc.) without hardcoding endpoints.

---

## Acceptance Criteria

### AC1: GET /.well-known/openid-configuration Returns Metadata
- [ ] `GET /.well-known/openid-configuration` returns HTTP 200 with JSON body
- [ ] Content-Type: `application/json`
- [ ] Body is valid OIDC discovery metadata (RFC 8414 / OpenID Connect Discovery). Required fields for this story:
  - [ ] `issuer` — IdentiKey issuer URL (e.g. `https://connect.identikey.io`). From env `IDENTIKEY_ISSUER` or derived from request (e.g. request origin) when not set.
  - [ ] `jwks_uri` — URL to fetch JWKS. Must be `{issuer}/.well-known/jwks.json` (same as 7.2; no trailing slash on issuer when concatenating).
  - [ ] `token_endpoint` — URL for token requests (e.g. refresh). Use `{issuer}/api/token/refresh` or `{issuer}/api/token` per architecture. Endpoint may be implemented in Epic 12.
  - [ ] `introspection_endpoint` — URL for token introspection. Use `{issuer}/api/introspect` per architecture. Endpoint may be implemented in Epic 10/12.
- [ ] Additional standard discovery fields (e.g. `response_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported`) may be included for interoperability; document or implement minimal set that clients need for validation.

### AC2: Response is Cacheable
- [ ] Response includes `Cache-Control` with `max-age` (e.g. 3600). Metadata changes rarely (issuer/base URL); same pattern as JWKS endpoint.

### AC3: No Dependency on Signing Key for Discovery
- [ ] Discovery document does **not** require the signing key to be loaded. Return metadata even if key is unavailable (unlike JWKS, which returns 503 when key is missing). Issuer and endpoint URLs are configuration, not key-dependent.

---

## Tasks / Subtasks

- [ ] **Task 1: SvelteKit route** (AC: 1, 2)
  - [ ] Create `src/routes/.well-known/openid-configuration/+server.ts`
  - [ ] In GET handler: resolve issuer from `IDENTIKEY_ISSUER` env or from request URL (e.g. `url.origin`). Ensure no trailing slash.
  - [ ] Build object: `issuer`, `jwks_uri: `${issuer}/.well-known/jwks.json``, `token_endpoint: `${issuer}/api/token/refresh``, `introspection_endpoint: `${issuer}/api/introspect``
  - [ ] Return JSON with `Cache-Control: public, max-age=3600` (or similar)

- [ ] **Task 2: Optional OIDC fields** (AC: 1)
  - [ ] Add at least `id_token_signing_alg_values_supported: ["EdDSA"]` so clients know our signing alg. Other optional fields (e.g. `scopes_supported`, `token_endpoint_auth_methods_supported`) as needed for minimal compliance.

- [ ] **Task 3: Tests** (AC: all)
  - [ ] Unit or route test: GET returns 200, body has `issuer`, `jwks_uri`, `token_endpoint`, `introspection_endpoint`; `jwks_uri` ends with `/.well-known/jwks.json`
  - [ ] Test: response has Cache-Control header
  - [ ] Test: discovery works without signing key initialized (no 503)

---

## Dev Notes

### Architecture Constraints
- **Route location:** `src/routes/.well-known/openid-configuration/+server.ts` (SvelteKit convention; path is `/.well-known/openid-configuration`).
- **Endpoint URLs:** Architecture and epics reference `/api/token/refresh`, `/api/introspect`. Use these paths relative to issuer. Exact SvelteKit route layout (e.g. `src/routes/api/token/refresh/+server.ts`) is for later stories; discovery only advertises the URLs.

### Previous Stories (7.1–7.4) Intelligence
- **7.2:** JWKS at `/.well-known/jwks.json`. Same origin as this app; so `jwks_uri = issuer + /.well-known/jwks.json`.
- **7.3/7.4:** Issuer and audience from env (IDENTIKEY_ISSUER, IDENTIKEY_AUDIENCE). Use same IDENTIKEY_ISSUER for discovery so clients and server agree.
- **No key needed:** Discovery is static metadata; do not call getSigningKey() or getPublicKeyJwk() in this route.

### OIDC Discovery (RFC 8414)
- Clients fetch `/.well-known/openid-configuration` to get `jwks_uri`, `issuer`, etc. Required for many OIDC/OAuth libraries.
- Issuer must have no trailing slash (RFC 8414). Normalize when building.

### References
- [Source: _bmad-output/planning-artifacts/epics.md#7.5] — AC and technical notes
- [Source: _bmad-output/planning-artifacts/architecture.md] — introspect, token endpoints
- [Source: src/routes/.well-known/jwks.json/+server.ts] — same .well-known pattern, Cache-Control, json()

### Developer Context (Guardrails)
- **Do not** implement token or introspection logic in this story; only the discovery document. Those are Epic 10/12.
- **Do not** require signing key to be loaded; discovery must always return 200 when the app is up (config-only).
- **Do not** change JWKS route; only add openid-configuration route.

### Testing Requirements
- Call GET /.well-known/openid-configuration (e.g. fetch in test or SvelteKit test utils). Assert JSON shape and Cache-Control. Mock or omit env to test request-origin fallback if implemented.

### Story Completion Status
- **Status:** ready-for-dev  
- **Completion note:** Ultimate context engine analysis completed. Final story in Epic 7 (JWT Infrastructure). Enables clients to discover JWKS and endpoints for token validation.

---

## Dev Agent Record

### Agent Model Used

{{agent_model_name_version}}

### Debug Log References

### Completion Notes List

### File List
