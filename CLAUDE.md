When running vitest tests, always use `bun vitest`.

Rust schema tests (`cargo test -p identikey-keys`) need real Postgres
(ADR-006). Point `DATABASE_URL` at a Postgres you can `CREATE DATABASE`
from and set `PGUSER` (or put a username in the URL). A URL of the form
`postgres://localhost/…` makes sqlx 0.9 ask the `whoami` crate for a user,
which can come back as `anonymous` and fail the test setup.

Do not run `sqlx migrate` against `identikey-core-test` as it stands: that
database still has the old Drizzle schema (`challenges` already exists).
`#[sqlx::test]` can still *use* it as a maintenance DB. For migrate /
`cargo sqlx prepare`, use a clean database (`identikey-core-sqlx`).

After changing any `sqlx::query!` / `query_as!` / `query_scalar!` (or the
schema in `crates/identikey-keys/migrations/`), regenerate the offline
cache against a database that has those migrations applied:

    DATABASE_URL=postgres://$USER@localhost:5432/identikey-core-sqlx \
      cargo sqlx prepare --workspace -- --all-targets

Commit the updated `.sqlx/` directory. CI runs `cargo sqlx prepare --check`
and fails if you forget.

Local OIDC (code+PKCE) for hooking an app, after `add-oidc-endpoints`
and `add-dev-authorize`:

    IDENTIKEY_DEV_LOGIN=1
    IDENTIKEY_CLIENT_ID=smoke
    IDENTIKEY_CLIENT_REDIRECT=http://127.0.0.1:9999/cb
    IDENTIKEY_CLIENT_AUTH_METHOD=none
    IDENTIKEY_ISSUER=http://127.0.0.1:8080
    WEBAUTHN_RP_ID=localhost
    WEBAUTHN_EXPECTED_ORIGIN=http://localhost
    DATABASE_URL=postgres://$USER@localhost:5432/identikey-core-sqlx

Confidential clients (optional extra registrations, secrets hashed at boot):

    IDENTIKEY_CLIENT_SECRET=...                 # with IDENTIKEY_CLIENT_ID
    IDENTIKEY_CLIENT_AUTH_METHOD=client_secret_basic
    IDENTIKEY_CLIENTS='[{"id":"basic-1","redirect":"https://127.0.0.1:8443/test/a/identikey-basic/callback","secret":"...","auth":"client_secret_basic"}]'

See `docs/oidc/README.md` for `oidcc-basic-certification-test-plan`. That
plan is not a required CI job.

The flag must be exactly `1`. `/authorize/dev` is unregistered without
it. `/health` does not report the flag. The test user must already exist
in `KeysStore` (no implicit signup). Pairwise salt and the EdDSA signing
JWK are created under `IDENTIKEY_DATA_DIR` on first boot. Boot fails
closed without `WEBAUTHN_RP_ID` / `WEBAUTHN_EXPECTED_ORIGIN` (no
wildcards). Config OP CI is `.github/workflows/oidf-config-op.yml`.

Production OP origin (ADR-004): `https://auth.identikey.me`
(issuer, WebAuthn RP ID, `WEBAUTHN_EXPECTED_ORIGIN`). Discovery:
`https://auth.identikey.me/.well-known/openid-configuration`.
`connect.identikey.io` is the Keycloak-era leftover, not this OP.
Client redirects are env-registered exact match:
`IDENTIKEY_CLIENT_ID` + `IDENTIKEY_CLIENT_REDIRECT` (https except
loopback). Extra clients: `IDENTIKEY_CLIENTS` JSON.

Mjolnir managed deploy (`mjolnir.toml`), first live 2026-08-27:

    mix mjolnir.pg.tenant ensure identikey --slug identikey   # on the host
    # secrets file /var/lib/mjolnir/deploy/secrets/identikey.json
    # (mj secrets set 404s until the app is in the registry)
    mj deploy . --name identikey --memory 2048 --domain auth.identikey.me

`mj deploy` currently boots a `deploy-node-bun` build VM, which misses
the 30s await_boot window. First ship used rpc
`base_image: "ubuntu-24.04"`. That image's June guest agent cannot
unlock managed secrets — copy a current `mjolnir-agent` (the one on
the taskmaster VM, Aug 22) into the release snapshot before
Runtime.start. Mask `serial-getty@ttyS0` or systemd waits 90s.

Apex `identikey.me` must be in **both** `MJOLNIR_GATEWAY_APEXES`
(`/etc/mjolnir/env`, put_env is not durable) **and**
`/etc/mjolnir/gateway.toml` `[[domain]]` (else HTTP 400 "Invalid
domain"). Bind is `0.0.0.0:8080` in `start_command` — `PORT` is
ignored. Do not set `IDENTIKEY_DEV_LOGIN`. Host: `root@45.76.77.97`.

Live (2026-08-27): app `identikey`, snapshot
`deploy-2e6187d237ffb69bb6727c5122325ad4ff6e9547020403e94582957ddfca4af3`,
service VM `2a39456f-b93e-4dcd-a0e2-b0a358a3ffd9`. Public
`https://auth.identikey.me` — DNS A `45.76.77.97` (grey-cloud), HTTP-01
cert SAN `auth.identikey.me` until 2026-11-25, `/health` 200, discovery
200, JWKS EdDSA kid `JZnOxfXDaklXwH9yyeEbqi6AMkD68zE74w3mv7_A3yk`.
Bare `/authorize` is 400 (client_id required). `/signup` 200.

First production RP (taskmaster-web ADR 0001): two confidential
clients, never one. Pairwise sector is the redirect *host*.

| client | redirect (exact) | sector |
|---|---|---|
| production | `https://taskmaster.dev/auth/callback` | `taskmaster.dev` |
| laptop | `http://127.0.0.1:5173/auth/callback` | `127.0.0.1` |

Taskmaster guest already has `IDENTIKEY_ISSUER=https://auth.identikey.me`,
`IDENTIKEY_CLIENT_ID=taskmaster`, `ORIGIN=https://taskmaster.dev`
(RP derives redirect as `${ORIGIN}/auth/callback`). PKCE S256.
`client_secret_basic`. Reuse the existing client secret; do not mint a
second one and strand the RP.

Two ways to get OIDC tokens, one proof format:

- **Managed (C1/C2):** we hold Sign. A browser RP uses authorization-code
  + PKCE. The user authenticates *to us* with A3 passkeys
  (`add-passkey-ceremonies` / `5gh.1`). After that we may sign an
  `identikey-auth` `Response` with `managed_key_blob`. Consent for that
  use is the access credential, never our own Sign.
- **Self-custody (C3/C4):** the wallet signs the `Response`. The RP
  (or native client) presents it as
  `grant_type=urn:identikey:params:oauth:grant-type:challenge-response`
  (`add-urn-grant` / `ccf.5`, still PENDING).

Protocol: sibling `identikey-protocol`
`docs/standards/identikey-auth-challenge-v1.md` (§8.1 dual signer) and
`docs/standards/identikey-oidc-urn-grant-v1.md`. This repo does not
yet depend on `identikey-auth`. `IDENTIKEY_DEV_LOGIN` stands in for
managed `/authorize` at `/authorize/dev`. Production login is passkey
assertion: `/authorize` redirects to `/authorize/passkey`. First
account: `GET`/`POST /signup` (`c2_native` + `create_managed`) then
`POST /webauthn/register/finish`. Register an existing XID at
`POST /webauthn/register/begin` then `finish`. Assertion of an
unknown credential still inserts no account. The blob is not used
to Sign yet. Elect-key export at signup is not this surface.
