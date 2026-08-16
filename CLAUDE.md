When running vitest tests, always use `bun vitest`.

Rust schema tests (`cargo test -p identikey-keys`) need real Postgres
(ADR-006). Point `DATABASE_URL` at `identikey-core-test` and set `PGUSER`
(or put a username in the URL). A URL of the form `postgres://localhost/…`
makes sqlx 0.9 ask the `whoami` crate for a user, which can come back as
`anonymous` and fail the test setup.
