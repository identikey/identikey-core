## ADDED Requirements

### Requirement: Basic OP and Config OP are CI-gated

CI SHALL run the OpenID Foundation **OIDC Basic OP** and **OIDC
Config OP** plans against a local `identikey-server`. The suite SHALL
NOT be a Rust crate dependency. A failing plan SHALL fail the build.

#### Scenario: Config OP hits discovery

- GIVEN CI of this repository
- WHEN the conformance job runs
- THEN the Config OP plan executes against the server’s
  `/.well-known/openid-configuration`

#### Scenario: A red plan fails the build

- GIVEN a Basic OP test failure
- WHEN the job finishes
- THEN the workflow is failed
