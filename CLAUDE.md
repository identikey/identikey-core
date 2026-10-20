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

Run the local OP with `scripts/dev-server.sh`. It loads the root
`.env` (gitignored), and on first run creates it from `.env.example`
with your Postgres user and a fresh `IDENTIKEY_MANAGED_WRAP_KEY` (boot
fails without one). Shell env wins. The server does not read `.env`
itself; sqlx macros do, so keep `DATABASE_URL` there with a user in it.
The Keycloak-era TypeScript backend (web CLI, MCP, Drizzle) was removed
2026-09-28; `web/` is only the static app.

Local OIDC (code+PKCE) for hooking an app, after `add-oidc-endpoints`
and `add-dev-authorize`. These are the values in `.env.example`:

    IDENTIKEY_DEV_LOGIN=1
    IDENTIKEY_CLIENT_ID=smoke
    IDENTIKEY_CLIENT_REDIRECT=http://127.0.0.1:9999/cb
    IDENTIKEY_CLIENT_SECTOR=127.0.0.1
    IDENTIKEY_CLIENT_AUTH_METHOD=none
    IDENTIKEY_ISSUER=http://localhost:8080
    WEBAUTHN_RP_ID=localhost
    WEBAUTHN_EXPECTED_ORIGIN=http://localhost:8080
    DATABASE_URL=postgres://$USER@localhost:5432/identikey-core-sqlx

Confidential clients (optional extra registrations, secrets hashed at boot):

    IDENTIKEY_CLIENT_SECRET=...                 # with IDENTIKEY_CLIENT_ID
    IDENTIKEY_CLIENT_AUTH_METHOD=client_secret_basic
    IDENTIKEY_CLIENTS='[{"id":"basic-1","redirect":"https://127.0.0.1:8443/test/a/identikey-basic/callback","sector":"127.0.0.1","secret":"...","auth":"client_secret_basic"}]'

Pairwise clients (the default subject type) require an opaque sector pin.
Before deploying pinned registrations, run `identikey-server check-clients`;
it exits non-zero unless every pairwise pin exactly matches the sector the
previous redirect-derived loader used. Public clients do not require a pin.

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

This OP pins `base_image = "ubuntu-24.04"` in `mjolnir.toml` (mjolnir-6ee1).
`mj deploy . --name identikey --memory 2048 --domain auth.identikey.me`
reads that pin (or `--base ubuntu-24.04` overrides it). Do not omit the
pin: Orchestrator still defaults inferred/unpinned apps to
`deploy-node-bun`. The **host** Mjolnir must include 6ee1; until that
release is running, laptop `mj deploy` still ignores the key and you
must rpc `Orchestrator.deploy(..., base_image: "ubuntu-24.04")`.
Source lands in `/var/lib/mjolnir/deploy/src/identikey` (`git archive`
of HEAD, or `mj deploy` tarball). Bun defaults `NODE_ENV` to
development — the web build step sets `NODE_ENV=production`.

Related Mjolnir beads from the first ship: `mjolnir-bhcr` (live
deploy-node-bun has the agent unit and no binary), `mjolnir-hjnz`
(inject_guest_agent silent no-op; June ubuntu agent cannot unlock
managed secrets), `mjolnir-pj6t` (doctor misses this), `mjolnir-igi9`
(bare `:boot_timeout`), `mjolnir-606w` (`serial-getty@ttyS0` 90s on
snapshot boots).

Apex `identikey.me` must be in **both** `MJOLNIR_GATEWAY_APEXES`
(`/etc/mjolnir/env`, put_env is not durable) **and**
`/etc/mjolnir/gateway.toml` `[[domain]]` (else HTTP 400 "Invalid
domain"). Bind is `0.0.0.0:8080` in `start_command` — `PORT` is
ignored. Do not set `IDENTIKEY_DEV_LOGIN`. Host: `root@45.76.77.97`.

Live (2026-09-30, `2ed829d`: sector pins, passkey list, recovery UI,
takeover fix): app `identikey`, service VM `FaxZyk8oBEEt9vuUQqfvoF`,
owner `3dLGACrVKP67MtW4kwbG54JqBGS5nSb46uZVkJNueWKJ` (cut over from
`Ybwq8bBxJhQTCZfi6yA4cQ`, which was `4884e07`). Sector-pin rollout
verified: pairwise salt sha256 prefix `e96107c3ac49` unchanged and the
`taskmaster-laptop` probe `sub` identical before and after. Unsigned
`register/begin` is 403. Deploy notes: `mj` tokens expire fast; the
host path is `git archive` into `/var/lib/mjolnir/deploy/src/identikey`
plus `Mjolnir.Deploy.Orchestrator.deploy(..., deployer: <base58 owner>)`
over `bin/mjolnir rpc` with `/etc/mjolnir/env` sourced. Build VMs have
stalled mid-`cargo` (`mjolnir-mne7`); `codegen-units = 16` and 8 GB
(`:deploy_build_memory_mb`, runtime only) got a clean ~48 min build.
Takeover audit (2026-09-29, before the fix): 13 accounts, 3 passkeys,
none added after signup. `mj login` defaults to
`https://auth.identikey.me` as `mjolnir-cli`. A token from the old
Keycloak issuer is 401.
Public
`https://auth.identikey.me` — DNS A `45.76.77.97` (grey-cloud), HTTP-01
cert SAN `auth.identikey.me` until 2026-11-25, `/health` 200, discovery
200, JWKS EdDSA kid `JZnOxfXDaklXwH9yyeEbqi6AMkD68zE74w3mv7_A3yk`
(managed `IDENTIKEY_SIGNING_KEY`; did not rotate). Bare `/authorize` is
400 (client_id required). `/signup` 200. Unsigned `GET /account` is 401
hosted HTML (`Your account — IdentiKey`); first-party register/finish
sets `identikey_account` and `next: /account`. OIDC signup still
returns to `/authorize/passkey`. No `IDENTIKEY_DEV_LOGIN` in the guest
(`/authorize/dev` is 404).

`IDENTIKEY_MANAGED_WRAP_KEY` is set (64 hex, kid defaults to `v1`).
Do not rotate it: blobs sealed at signup after this cutover open only
with that key. `POST /managed-challenge/begin` is the real handler
(empty JSON is 422, not the old SPA 405). Signups from this binary mint
Ed25519 operational keys. Accounts created on `35aee29` and earlier are
still Schnorr and cannot use the responder; remint via signup. `mj
deploy` packs untracked files that are not gitignored —
`.identikey-dev-data/` (local signing JWK and pairwise salt) must stay
ignored. Deploy a clean tree, not a dirty checkout.

Encoding (cite protocol `docs/standards/encoding-conventions.md`).
Bytes stay bytes in Postgres, Rust, and CBOR. A **text** boundary
picks one encoding per kind — hex is diagnostics only, not the
identifier form. `Xid` `Display` / `FromStr` / JSON `xid` /
`GET /.well-known/xid/{xid}` / `/authorize/dev` / public OIDC `sub`
are **base58btc**. `Xid::to_hex` is diagnostics. Pairwise `sub` is
the same alphabet over **different** 32 bytes (HKDF of salt+sector+XID),
so it never equals a XID. After this cutover, Mjolnir
`owner_id` for `subject_type=public` is the base58 string; `mj logout`
&& `mj login` if an old hex token is still on disk.

| Value | Inside | Text boundary |
|---|---|---|
| XID (32 B SHA-256 of inception CBOR) | `bytea` / `[u8; 32]` | **base58btc** |
| Public OIDC `sub` | token claim | **base58btc** of that XID |
| Pairwise OIDC `sub` | token claim | base58btc of HKDF-SHA-256 (not the XID) |
| Pairwise salt | 32 B | env/file 64-hex (operator secret) |
| JWKS `x` / JWT | — | base64url (RFC 7517/7518) |
| Signing `kid` | — | opaque (not a XID) |
| identikey-auth Response (URN grant) | CBOR envelope | unpadded base64url (variable blob) |
| HTTP ETag of a XID document | SHA-256 of bytes | lowercase hex (cache validator) |
| WebAuthn `user.id` | — | UUID v5 (`NAMESPACE_URL` + xid bytes) |
| WebAuthn `user.name` / `/account` | — | base58btc XID |
| Account cookie / ceremony session | — | UUID |
| Whole envelope in chat/QR | CBOR | `ur:envelope/…` |

`Client::new` defaults to pairwise `sub` (HKDF of salt + sector + XID,
base58btc of those 32 bytes). Mjolnir owner checks are string equality against the
public `sub` (base58btc XID). Live `IDENTIKEY_CLIENTS` already has
`mjolnir-cli` (`http://127.0.0.1/callback`) and `mjolnir-term`
(`https://api.vm.worldtree.network/auth/callback`) as `auth=none`
`subject_type=public`. `mjolnir-cli` must list
`authorization_code`, `refresh_token`, and
`urn:ietf:params:oauth:grant-type:device_code`. Loopback `mj login`
uses the code grant. `mj login --device`, an SSH session, and a
Linux session with no display use the device grant. A client that
omits `grants` gets only code and refresh, so headless login is
`unauthorized_client` until that list is on the host secrets JSON.
`mjolnir-term` stays the code grant. Do not give the device grant to
taskmaster, Conduit, or `wtnf-web`. `taskmaster` / `taskmaster-laptop` stay
pairwise. Conduit laptop RP is confidential `id=localhost`
(`http://127.0.0.1:8008/_matrix/client/v3/login/identikey/callback`,
plus `http://localhost:8008/...`), `auth=client_secret_basic`, pairwise
sector `127.0.0.1`. Secret is not in this file; Conduit reads
`CONDUIT_OIDC_CLIENT_SECRET`. Next `mj deploy` of identikey picks the
host secrets JSON; until then the guest wrapper
`/app/target/release/identikey-server` exports `/root/identikey-clients.json`. The 2026-09-24 binary (`35aee29`) reads `subject_type` from
that JSON (`client_from_spec`). Tokens minted before that cutover stay
pairwise until `mj logout` and `mj login` again. The owner check is
`sub`. There is no Mjolnir user row.

Domains (checked 2026-09-18, bead `identikey-core-wzm` **P2**): both
NameCheap. `identikey.me` created 2023-07-20, registry expiry
**2030-07-20** (Duke multi-year renew; NameCheap WHOIS may lag). WHOIS
`clientTransferProhibited` only (registrar lock on; **not** .ME registry
lock). `identikey.io` expiry **2027-09-26**, same registrar lock,
`renewPeriod`. Remaining on wzm: independent expiry monitor (≥60 days,
not NameCheap email). Registry lock is extra.

Public SPA clients (PKCE `none`) may list extra `redirects` in
`IDENTIKEY_CLIENTS`. CORS on `/token` (and the rest of the OP) allows
those redirect origins, including loopback port flexibility.

World Tree site CMS (`wtnf-web`):

```json
[{"id":"wtnf-web","auth":"none","redirect":"https://worldtree.network/admin/callback/","redirects":["http://127.0.0.1:5173/admin/callback/"],"sector":"worldtree.network"}]
```

Append that object to the existing `IDENTIKEY_CLIENTS` array on the
guest; do not replace taskmaster clients. Pairwise sector is
`worldtree.network`.

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

Hosted login mints one token shape. A browser on this machine uses
authorization code + PKCE. A headless client uses the device grant
when that registration lists it. The wallet URN grant is a third
path and stays opt-in.

Two ways to get OIDC tokens, one proof format:

- **Managed (C2):** we hold Sign. A browser RP uses authorization-code
  + PKCE. The user authenticates to us with A3 passkeys. A native
  client that needs an edge identity proof uses
  `POST /managed-challenge/begin`, then `/finish/a3` or `/finish/a4`,
  then `/retrieve`. That ceremony signs one canonical identikey-auth
  v1 Challenge with the Ed25519 seed in `managed_key_blob`, and only
  after a fresh A3 assertion or a user-held A4 Elect signature bound
  to that Challenge. The account cookie does not authorize it. C1 is
  not this ceremony. It does not sign the Mjolnir session bind. That
  signature, under consent that covers the bind fields, is
  `mjolnir-22ff.3.2`. The Challenge Response is not that consent.
- **Self-custody (C3/C4):** the wallet signs the Response and the
  session bind locally. The RP presents the Response as
  `grant_type=urn:identikey:params:oauth:grant-type:challenge-response`.

Protocol: sibling `identikey-protocol`
`docs/standards/identikey-auth-challenge-v1.md` (§8.1 dual signer) and
`docs/standards/identikey-oidc-urn-grant-v1.md`. This repo depends on
`identikey-auth` (workspace crate, protocol rev `fd073c0`).
`IDENTIKEY_DEV_LOGIN` is the dev stand-in at `/authorize/dev`.
Production login is passkey assertion: `/authorize` redirects to
`/authorize/passkey`. First account: `GET`/`POST /signup`
(`c2_native` + `create_managed`, Ed25519 operational key) then
`POST /webauthn/register/finish`. Adding a passkey to an existing XID
requires that XID's `identikey_account` session cookie. A XID alone
is public. Backup ownership proofs are future work. Assertion of an
unknown credential still inserts no account. Elect-key export at
signup is not this surface. Blobs sealed before `35aee29` are Schnorr
and fail closed on the responder; remint via signup.
