# add-oidf-conformance

> **ACTIVE BUILD**

Activated from `nod-oidf-ci` (`identikey-core-ccf.3`). Licence half
is already decided (MIT, Docker runner OK).

**Rigor:** instrument

Amended 2026-08-18 after advise send-back
(`reviews/2026-08-18-advise.md`). The invalidated assumption was
on this instrument, not on the folded OP: OIDF **Basic OP**
assumes confidential clients; this OP advertises
`token_endpoint_auth_methods_supported: ["none"]` and requires
PKCE for every client (`docs/oidc-implementation-checklist.md`).
Those SHALLs stay. This change no longer asks Basic OP to referee
them.

## Why

Unit tests cannot referee “did we read discovery right.” The OpenID
Foundation **Config OP** plan can. It GETs
`/.well-known/openid-configuration` and checks the document we
already serve.

## What

- Documented local Docker command using
  `gitlab.com/openid/conformance-suite` `scripts/run-test-plan.py`
  and the prebuilt compose
  (`docker-compose-prebuilt.yml`)
- CI job runs **`oidcc-config-certification-test-plan`** against a
  local `identikey-server`
- Suite is a runner, not a Cargo dependency
- A red Config OP plan fails the build
- Capability `oidc-provider` (ADDED)

## Impact

- Capabilities: ADDED requirements on `oidc-provider`
- ADRs: none

## User journey & surfaces

No new UI because this is CI. The suite is an HTTP client of
discovery, not a logged-in user and not a token client.

## Out of scope

- Official certification / the OpenID mark (paid)
- FAPI / CIBA / eKYC plans
- **OIDC Basic OP** — blocked on a future confidential-client
  change (`client_secret_basic` + `client_secret_post`). Not this
  node; not a rewrite of folded `add-oidc-endpoints`
- Completing `/authorize` — Config OP does not log in.
  `IDENTIKEY_DEV_LOGIN` and a seeded C2 user are not required here
- Implementing or widening endpoints — folded
