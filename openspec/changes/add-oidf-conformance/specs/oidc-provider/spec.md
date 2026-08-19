## ADDED Requirements

### Requirement: Config OP is CI-gated

CI SHALL run the OpenID Foundation **OIDC Config OP** plan
(`oidcc-config-certification-test-plan`) against a local
`identikey-server`. The suite SHALL NOT be a Rust crate
dependency. A failing Config OP plan SHALL fail the build. CI
SHALL NOT run OIDC Basic OP until confidential-client
authentication exists.

#### Scenario: Config OP hits discovery

- GIVEN CI of this repository
- WHEN the conformance job runs
- THEN the Config OP plan GETs the server’s
  `/.well-known/openid-configuration` from a URL reachable
  inside the suite container

#### Scenario: A red Config OP plan fails the build

- GIVEN a Config OP test failure
- WHEN the job finishes
- THEN the workflow is failed
