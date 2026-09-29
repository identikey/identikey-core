# identikey-core

The IdentiKey OpenID Provider: a Rust OIDC server with passkey login,
managed and self-custody keys, and pairwise subjects. Production runs at
`https://auth.identikey.me`
([discovery](https://auth.identikey.me/.well-known/openid-configuration)).

## Run it locally

Prerequisites: Rust (stable), PostgreSQL, [Bun](https://bun.sh/) for the
web build.

```sh
createdb identikey-core-sqlx
scripts/dev-server.sh
```

The first run copies `.env.example` to `.env` (gitignored), fills in your
Postgres user and a fresh `IDENTIKEY_MANAGED_WRAP_KEY`, then runs
`cargo run -p identikey-server` on `http://localhost:8080`. Variables
already set in your shell take precedence. sqlx query macros also read
`DATABASE_URL` from `.env`, so a plain `cargo build` works too.

Try `/signup`, `/account`, `/.well-known/openid-configuration`, or a
code+PKCE `/authorize` with the `smoke` client that `.env.example`
registers. `IDENTIKEY_DEV_LOGIN=1` enables `/authorize/dev`; never set
it in production.

The server also serves the static SvelteKit app from `web/build`:

```sh
cd web && bun install && NODE_ENV=production bun run build
```

## Tests

```sh
cargo test --workspace          # schema tests need Postgres, see CLAUDE.md
cd web && bun vitest --run
```

After changing a `sqlx::query!` or a migration, regenerate `.sqlx/`
with `cargo sqlx prepare --workspace -- --all-targets` and commit it.

## Layout

```
crates/
  identikey-keys/         managed custody (C2): accounts, credentials, migrations
  identikey-oidc/         OIDC provider over the custody ladder
  identikey-oidc-client/  relying-party JWT/JWKS validator (not the OP)
  identikey-recovery/     assisted key recovery (C3): guardians, SSKR
  identikey-server/       axum binary: hosted pages, WebAuthn, web assets
web/                      static SvelteKit app served from web/build
docs/                     architecture, OIDC certification, standards
scripts/dev-server.sh     local OP launcher
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Custody ladder](docs/custody-ladder.md)
- [OIDC certification](docs/oidc/README.md)
- `CLAUDE.md`: deploy, clients, encoding conventions, and operator notes

## Contributing

Contributors to identikey-core must agree to the [Contributor License
Agreement](CLA.md). Contributors to identikey-protocol use the
identikey-protocol Developer Certificate of Origin instead of this CLA.

## License

Private — IdentiKey Platform
