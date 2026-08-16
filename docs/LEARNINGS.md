# Learnings

Append-only. One dated line per hard-won fact, with a file reference.
Write here whenever something cost you time that reading the code would not have prevented.
See morphist-tools `CONVENTIONS.md`.

---

- 2026-07-28 — `identikey-auth` is `MIT OR Apache-2.0` with zero recrypt deps, but
  `identikey-storage-auth` is `AGPL-3.0-or-later` and depends on `recrypt-core`/`recrypt-wire`.
  They must not share a workspace or the commercial product inherits AGPL entanglement.
  (recrypt/crates/*/Cargo.toml)
- 2026-07-28 — `bd dep add` rejects a non-epic blocking an epic ("epics can only block other
  epics"). Wire decision beads to the specific *task* they block, not the epic.
- 2026-07-28 — a freshly-created `.beads/` may need `bd dolt commit` then `bd migrate` before
  `bd create` works; `bd list` warns but succeeds, so the failure only shows up on write.
- 2026-07-28 — `src/lib/server/db/schema.ts` `user` table is still the SvelteKit scaffold
  (`id`, `age`). Real user storage is in Keycloak, so leaving Keycloak means *building* a user
  store, not migrating one. This is the largest unbudgeted item in the pivot.
- 2026-07-28 — `aws-lc-sys` 0.36.0 declared `... AND OpenSSL`, a GPL-incompatible license, and
  reached both AGPL binaries via `recrypt-storage -> aws-sdk-s3 -> rustls -> aws-lc-rs`. Fixed by
  bumping `aws-lc-rs` (not `aws-lc-sys` — its 0.x releases are semver-incompatible so
  `cargo update -p aws-lc-sys` reports zero changes). Transitive crypto deps are the usual way
  copyleft-incompatible licenses enter an AGPL project. (recrypt/Cargo.lock)
- 2026-07-28 — `cargo metadata --format-version 1 --all-features` gives license fields for
  *every* package including ones absent from the local registry src cache; scanning
  `~/.cargo/registry/src` directly only resolved 396 of 659 and would have missed this.
- 2026-08-16 — `bc-xid` 0.23 does not enforce `Elect` on `add_key`/`remove_key`, and
  `XIDVerifySignature::Inception` accepts any rewrite signed by the inception
  private key. A C2 privilege split is decorative unless we (a) authorize key-graph
  changes ourselves (`authorize_elect`) and (b) do not persist inception private
  after promotion. (`crates/identikey-keys/src/privilege.rs`, ADR-010)
- 2026-08-16 — `#[sqlx::test]` against `postgres://localhost/...` (no user in the URL)
  asks the `whoami` crate for a username. On this host that can come back as
  `anonymous`, and Postgres then fails with `role "anonymous" does not exist`.
  Put a user in `DATABASE_URL` or export `PGUSER`. Peer-auth `psql` hides this
  because it uses the OS user over a unix socket. (`crates/identikey-keys` tests)
- 2026-08-16 — C2 consent is a hash-chained Postgres log of *access-credential* proofs,
  not a reuse of `identikey-storage-auth` capability envelopes. Importing that crate
  would pull recrypt + AGPL into the product workspace. The chain *pattern* is the
  useful part and is cheap to reimplement (`crates/identikey-keys/src/consent.rs`).
- 2026-07-28 — `sub` must be a XID (hash of an *inception* key), not the current key's
  fingerprint. Fingerprint-as-subject makes key rotation an identity break, and PQ migration is
  a *scheduled* rotation — so it would have had a known future date on which every identity
  broke. `bc-components` 0.31.1 already ships `XID`, and `bc-xid` (BSD-2-Clause-Patent, matching
  our protocol tier) has the full document + rotation model. `bc-components` also ships SSKR,
  relevant to guardian recovery. (docs/ARCHITECTURE.md ADR-001)
