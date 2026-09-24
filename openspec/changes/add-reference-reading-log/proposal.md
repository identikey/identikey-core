# add-reference-reading-log

> **ACTIVE BUILD**

**Rigor:** change
**Capability:** oidc-provider (ADDED)

## Why

The OIDC provider was built from the spec. The remaining open
questions may consult Apache-2.0 and MIT reference implementations,
but nothing in the tree records the rule that those notes must not
become a copy. Kanidm is MPL-2.0 and must not be checked out beside
this code.

## What

- Add `docs/oidc/reference-reading.md`.
- Name ory/fosite, panva/node-oidc-provider, and zitadel/oidc as
  readable, never pasted.
- Name kanidm as read-only at a distance. No checkout.
- Do not vendor or clone any of them into this repository.

## Impact

- Capabilities: ADDED on `oidc-provider`
- ADRs: none

## User journey & surfaces

No new UI because this is a reading note for the people changing
the provider, not a page a user sees.

## Preparation — 2026-09-24

Outcome: still valid. Authority: user said "decide for me & activate."
Bounds: the document and the never-paste rule. No port. No Keycloak.
Kanidm is named and not checked out. Bead `identikey-core-ccf.2`.

## Out of scope

- Social bootstrap — `identikey-core-ccf.6`
- JWKS rotation — `identikey-core-ccf.9`
- openssl versus rustls — `identikey-core-ccf.10`
- Cloning the reference repositories anywhere in this git tree
