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
    IDENTIKEY_ISSUER=http://127.0.0.1:8080
    DATABASE_URL=postgres://$USER@localhost:5432/identikey-core-sqlx

The flag must be exactly `1`. `/authorize/dev` is unregistered without
it. `/health` does not report the flag. The test user must already exist
in `KeysStore` (no implicit signup). Pairwise salt and the EdDSA signing
JWK are created under `IDENTIKEY_DATA_DIR` on first boot. OIDF Basic OP
+ Config OP CI is `add-oidf-conformance` and still needs independent
advise before it can be acted.
