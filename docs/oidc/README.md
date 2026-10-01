# OIDC Config OP (local + CI)

Instrument: OpenID Foundation **Config OP** against a locally booted
`identikey-server`. Plan id `oidcc-config-certification-test-plan`.
The suite is a Docker runner, not a Cargo dependency.

Basic OP (`oidcc-basic-certification-test-plan`) can be run locally
once confidential clients are registered. It is **not** a required
CI job.

## Saved sessions

Production stores refresh-session hashes in `oidc_refresh_sessions` in the
existing `DATABASE_URL` database (migration 0005). Sessions survive OP restarts
and replacement service VMs. Each successful refresh atomically replaces the
old hash; revocation deletes it. Raw refresh tokens never enter the database.
The one-hour API token lifetime is unchanged. Short-lived authorization codes
and access-token introspection state remain in memory.

`Provider::new` keeps an in-memory store for isolated consumers and tests;
`identikey-server` always attaches `store.pool()` using `with_refresh_pool`.
Storage failures fail token issuance rather than returning an unsaved session.
Existing sessions issued before this fix live only in the old process and
normally require one new login after rollout.

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

## Basic OP (local only, not CI)

Plan id `oidcc-basic-certification-test-plan`. Config:
`docs/oidc/basic-op.json`. Do not add this as a required GitHub job
until the plan is green on this machine.

Register two `client_secret_basic` clients and one
`client_secret_post` client (secrets hashed at boot; never log them):

```
export IDENTIKEY_DEV_LOGIN=1
export IDENTIKEY_CLIENT_ID=smoke
export IDENTIKEY_CLIENT_REDIRECT=http://127.0.0.1:9999/cb
export IDENTIKEY_CLIENT_SECTOR=127.0.0.1
export IDENTIKEY_CLIENTS='[
  {"id":"basic-1","redirect":"https://127.0.0.1:8443/test/a/identikey-basic/callback","sector":"127.0.0.1","secret":"basic-1-secret","auth":"client_secret_basic"},
  {"id":"basic-2","redirect":"https://127.0.0.1:8443/test/a/identikey-basic/callback","sector":"127.0.0.1","secret":"basic-2-secret","auth":"client_secret_basic"},
  {"id":"post-1","redirect":"https://127.0.0.1:8443/test/a/identikey-basic/callback","sector":"127.0.0.1","secret":"post-1-secret","auth":"client_secret_post"}
]'
```

Pairwise clients (including the default subject type) require `sector` in
`IDENTIKEY_CLIENTS`, or `IDENTIKEY_CLIENT_SECTOR` for the primary client. Pins
are opaque and passed to subject derivation verbatim. Before rollout, run
`identikey-server check-clients`; it reports each configured pin beside the
legacy redirect-derived sector and exits non-zero on a mismatch. The command
needs no database, network, signing key, or pairwise salt. Public clients may
omit `sector`.

The suite will not paste a XID into `/authorize/dev` by itself.

Login automation:

1. Create the test user in `KeysStore` first (no implicit signup).
2. `IDENTIKEY_DEV_LOGIN` must be exactly `1`. `/authorize` then
   redirects to `/authorize/dev`.
3. The form field is `name="xid"` (base58btc of the 32-byte XID). Submit
   completes the code+PKCE request.
4. Without a browser: `GET /authorize/dev` with the same query string
   `/authorize` used, plus `xid=<base58btc>`, completes login (the GET
   handler already does this when `xid` is present).
5. PKCE `S256` is still required when a client secret is presented.

Then the same compose + `run-test-plan.py` as Config OP, with the
plan id and `docs/oidc/basic-op.json`. Redirect URIs in
`IDENTIKEY_CLIENTS` must exactly match the suite callback for the
chosen alias (`identikey-basic` in the sample file). If the suite
prints a different callback host (for example
`localhost.emobix.co.uk`), register that URI instead.

## CI

`.github/workflows/oidf-config-op.yml` is a separate job. A red
Config OP plan fails the workflow. No `continue-on-error`.
