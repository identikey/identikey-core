# Design — Config OP as the instrument

Property: **Config OP is green** against a locally booted
`identikey-server`. Discovery already exists; a red Config plan
means we advertised a lie. That is a real fail of `main`.

Send-back 2026-08-18 classified the dead assumption: “Basic OP can
referee this OP.” It cannot. Folded SHALLs (code + PKCE, `none`
auth, flag-gated dev login) stay. Do not un-fold.

## Plan

`run-test-plan.py` argument:

```
oidcc-config-certification-test-plan
```

No `client_registration` / `response_type` variants. Config OP
reads server metadata.

Sample config (committed next to the job; issuer host must be
reachable from the suite container, not `127.0.0.1` of the
container itself):

```json
{
  "alias": "identikey",
  "description": "IdentiKey Core Config OP",
  "server": {
    "discoveryUrl": "http://host.docker.internal:8080/.well-known/openid-configuration"
  }
}
```

`IDENTIKEY_ISSUER` on the server under test MUST equal the origin
in that URL (`http://host.docker.internal:8080` in CI) so the
document’s `issuer` matches what the suite fetched.

## Image

Prebuilt compose:
https://gitlab.com/openid/conformance-suite/-/blob/master/docker-compose-prebuilt.yml

Images:

- `registry.gitlab.com/openid/conformance-suite:${TAG}`
- `registry.gitlab.com/openid/conformance-suite/nginx:${TAG}`
- Mongo as in that compose (`mongo:6.0.13` or whatever the
  pinned compose specifies)

Do not vendor the Java tree. Do not use `latest`. Act pins a
release tag (example currently in the wild: `release-v5.1.43`)
**and** the sha256 digest of both suite and nginx images into the
workflow or a lock file in-repo. Re-pin is a deliberate commit.

Local command (shape; exact tag/digest from the lock file):

```
docker compose -f docker-compose-prebuilt.yml up -d
python3 scripts/run-test-plan.py oidcc-config-certification-test-plan docs/oidc/config-op.json
```

Document that command in-repo (README or `docs/oidc/`). The
`run-test-plan.py` copy is from the suite checkout or image, not
a Cargo dep.

## Network

The suite GETs `discoveryUrl` from inside Docker. `127.0.0.1:8080`
inside that network is not `identikey-server`.

CI:

- Boot `identikey-server` on the runner, bind `0.0.0.0:8080`
- Point `discoveryUrl` at `host.docker.internal:8080` (Docker
  Desktop / GHA `extra_hosts: host.docker.internal:host-gateway`)
  or `--network host` if that is simpler on `ubuntu-latest`
- Postgres is already a service in `.github/workflows/rust.yml`

Redirect URIs: none. Config OP does not authorize.

## Login and seed

Not used. Do not register `/authorize/dev`. Do not seed a C2
user. `/health` stays liveness-only.

## Red job

`continue-on-error` is forbidden. A failing Config OP test fails
the GitHub job. That is the instrument working on an in-scope
plan, not a stand-in for Basic OP.

Expected skips/warnings: only if the suite’s own skip file names
a test we do not claim (document the file). Do not skip “issuer
mismatch” or “missing S256” — those are ours.

## Basic OP later

A new change, after confidential clients exist. It does not amend
this design’s property.
