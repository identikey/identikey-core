# add-refresh-lifecycle

> **ACTIVE BUILD**

Activated from `nod-refresh-lifecycle` (`identikey-core-ccf.8`).

**Rigor:** change

## Why

`/revoke` and `/introspect` are theater unless refresh tokens are
hashed, rotated on use, and checked for revocation on every use.
RFC 9700 §2.2.2: public-client refresh MUST be sender-constrained
or rotated. We rotate.

## What

- Store SHA-256 of the refresh token, never the raw value
- Rotate on use; old token dies
- Revoked token fails at `/token` (refresh) and `/introspect`
- Capability `oidc-provider` (ADDED)

## Impact

- Capabilities: ADDED requirements on `oidc-provider`
- ADRs: none (RFC 9700)

## User journey & surfaces

No new UI because this is token plumbing. The app’s refresh call is
the surface.

## Out of scope

- Device binding / sender-constrain beyond rotation
- Token claims `device_id` — `ccf`
- Minting the first refresh — `add-oidc-endpoints`
