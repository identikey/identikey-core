# Tasks

- [x] Decide the instrument: Config OP only. Basic OP waits on a
      confidential-client change (out of scope here).
- [x] Name exact `run-test-plan.py` plan id:
      `oidcc-config-certification-test-plan`. Sample config in
      `design.md`.
- [x] Login: Config OP does not complete `/authorize`. No form
      driver, no `IDENTIKEY_DEV_LOGIN`.
- [x] Image: `registry.gitlab.com/openid/conformance-suite` +
      `/nginx`; pin tag **and** digest at act (no `latest`).
- [x] Seed: not required for Config OP.
- [x] Network: suite must fetch discovery via
      `host.docker.internal` (or host network), not container
      localhost. No suite redirect URIs.
- [x] Red Config OP fails the GitHub job. `continue-on-error`
      forbidden. That is in-scope property-red.
- [x] Documented Docker / `run-test-plan.py` command in-repo
- [x] CI runs `oidcc-config-certification-test-plan` against
      local identikey-server
- [x] Suite is not a Cargo dependency
- [x] Job fails the build when Config OP is red
- [x] Tag + sha256 digest of suite and nginx images committed

Not owed here (bullets, not boxes):

- Paying for certification
- FAPI plans
- Licence research (done 2026-08-18, MIT)
- OIDC Basic OP / confidential clients
- Dev-login automation
- Rewriting folded `add-oidc-endpoints` / `add-dev-authorize`
