# add-oidf-conformance

> **ACTIVE BUILD**

Activated from `nod-oidf-ci` (`identikey-core-ccf.3`). Licence half
is already decided (MIT, Docker runner OK).

**Rigor:** instrument

## Why

Our unit tests cannot referee “did we read OIDC right.” The OpenID
Foundation Basic OP + Config OP plans can. They stay red until the
code-flow path is real.

## What

- Documented local Docker command using
  `gitlab.com/openid/conformance-suite` `scripts/run-test-plan.py`
- CI job runs **OIDC Basic OP** and **OIDC Config OP** against a
  local `identikey-server` with `IDENTIKEY_DEV_LOGIN=1`
- Suite is a runner, not a Cargo dependency
- Capability `oidc-provider` (ADDED)

## Impact

- Capabilities: ADDED requirements on `oidc-provider`
- ADRs: none

## User journey & surfaces

No new UI because this is CI. The suite acts as a confidential/public
client against our OP.

## Out of scope

- Official certification / the OpenID mark (paid)
- FAPI / CIBA / eKYC plans
- Implementing endpoints — `add-oidc-endpoints` + `add-dev-authorize`
