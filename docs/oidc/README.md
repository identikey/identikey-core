# OIDC Config OP (local + CI)

Instrument: OpenID Foundation **Config OP** against a locally booted
`identikey-server`. Plan id `oidcc-config-certification-test-plan`.
The suite is a Docker runner, not a Cargo dependency.

Basic OP is out of scope until confidential clients exist.

## Pin

`images.lock` holds the release tag and sha256 digests. Re-pin is a
commit. Do not use `latest`.

## Local

Postgres must already be up (`DATABASE_URL`). From the repo root:

```
export DATABASE_URL=postgres://$USER@localhost:5432/identikey-core-sqlx
export IDENTIKEY_BIND=0.0.0.0:8080
export IDENTIKEY_ISSUER=http://host.docker.internal:8080
export IDENTIKEY_DATA_DIR=$(mktemp -d)

cargo build -p identikey-server
./target/debug/identikey-server &

docker compose -f docs/oidc/docker-compose.yml up -d

git clone --depth 1 --branch release-v5.1.43 \
  https://gitlab.com/openid/conformance-suite.git /tmp/conformance-suite
python3 -m pip install -r /tmp/conformance-suite/scripts/requirements.txt

export CONFORMANCE_DEV_MODE=1
export CONFORMANCE_SERVER=https://127.0.0.1:8443
export CONFORMANCE_SERVER_MTLS=https://127.0.0.1:8444
export DISABLE_SSL_VERIFY=1

python3 /tmp/conformance-suite/scripts/run-test-plan.py \
  oidcc-config-certification-test-plan \
  docs/oidc/config-op.json
```

`IDENTIKEY_ISSUER` must match the origin in `config-op.json`.
`127.0.0.1:8080` inside the suite container is not this process.

Do not set `IDENTIKEY_DEV_LOGIN`. Config OP does not log in.

## CI

`.github/workflows/oidf-config-op.yml` is a separate job. A red
Config OP plan fails the workflow. No `continue-on-error`.
