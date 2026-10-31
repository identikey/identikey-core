# Learnings

Append-only. One dated line per hard-won fact, with a file reference.
Write here whenever something cost you time that reading the code would not have prevented.
See morphist-tools `CONVENTIONS.md`.

---

- 2026-09-11 — C2 `c2_native` + `PrivateKeyBase::new()` (bc-components 0.31)
  yields Schnorr (secp256k1) + X25519, not Ed25519 or P-256. The C2 PUK
  wrap-target is the X25519 encapsulation half as-is; protocol §7.2
  Ed25519→X25519 does not apply to Schnorr. Signup drops the user private,
  so a wrap to that recipient is inert until Elect export or a wallet.
  (`openspec/specs/guild-keyspaces/spec.md`, `docs/ARCHITECTURE.md` ADR-012)
- 2026-09-11 — Protocol `identikey-keyspace-v1` §6 admits `ed25519` / `p256`
  only. A C2 row of this store is a §7 `Wrap.recipient` and not a constructible
  §6 `RosterEntry` until identikey-protocol `ikp-2l8` adds `PublicKey.alg`
  `x25519`. Core SHALL NOT mint that alg. (`openspec/specs/guild-keyspaces/spec.md`)
- 2026-10-19 — `ikp-2l8` landed (`8ac2c70`). identikey-keys mints
  `PublicKey.alg` `x25519` on a §6 `RosterEntry` for the C2 encapsulation
  half. The key is a wrap-target. `admin: true` still needs an Ed25519
  `actor`. (`crates/identikey-keys/src/keyspace.rs`)
- 2026-10-21 — Sealing the user X25519 (`IKEK`) makes a wrap to that public
  openable by IdentiKey with the managed wrap key and an
  `encapsulation_unwrap` consent, including a house PTK. The 2026-09-11
  "inert until Elect export or a wallet" line holds only for a null seal.
  (`openspec/specs/guild-keyspaces/spec.md`, `docs/ARCHITECTURE.md` ADR-012)
- 2026-10-21 — A returned friend wrap cannot be revoked; stopping that
  friend means a new data key. A friend whose seal is null cannot open
  the wrap through IdentiKey. Rewrap can share a house PTK with a
  non-roster friend.
  (`openspec/changes/archive/2026-10-21-add-friend-rewrapping/specs/managed-custody/spec.md`,
  `docs/ARCHITECTURE.md` ADR-012)
- 2026-08-27 — Two concurrent `navigator.credentials.get` (conditional +
  button) finish the same ceremony; 1Password completes both and the
  second is unknown/expired. One in-flight get. (`crates/identikey-server/src/pages.rs`)
- 2026-08-27 — `fetch` + 302 hides `Location` as an opaque redirect.
  Passkey finish returns the OIDC redirect as JSON; the page assigns
  it. (`crates/identikey-server/src/pages.rs`)
- 2026-08-20 — `webauthn-rs` user.id is a UUID. Map XID → UUID v5
  (`NAMESPACE_URL` + xid bytes) so the handle is stable across
  registration options, matching the TS suite's "same userId → same
  user.id". (`crates/identikey-server/src/ceremonies.rs`)
- 2026-08-19 — `identikey-auth` is a git dep on identikey-protocol (rev pin).
  `cargo deny` `[sources] unknown-git = deny` needs an `allow-git` for that
  repo. The Linux TPM stack is an `enclave` feature so CI does not need
  libtss2; `all-features` still sees `Apache-2.0 WITH LLVM-exception`.
  (`Cargo.toml`, `deny.toml`)
- 2026-08-19 — RFC 6749 §2.3.1 HTTP Basic encodes `client_id` and
  `client_secret` with `application/x-www-form-urlencoded` *before*
  Base64 (`:` in an id becomes `%3A`). Decode after split-on-first-colon,
  not before. (`crates/identikey-oidc/src/provider.rs` `parse_http_basic`)
- 2026-08-19 — `last_advise_verdict` sorts review filenames. `YYYY-MM-DD-advise.md`
  sorts *after* `YYYY-MM-DD-advise-2.md` (`-` < `.`), so a send-back kept
  blocking accept-with-nits until a later dated file existed.
  (`openspec/changes/archive/` after fold; ready `advise_status.py`)
- 2026-08-18 — Advise send-back does not un-fold. First stop is classify
  which assumption died: instrument-only → amend the in-flight change
  (`/change` on that id); a folded SHALL is false → new change with
  MODIFIED against `openspec/specs/`. Archives stay. (`openspec/changes/add-oidf-conformance/reviews/2026-08-18-advise.md`)
- 2026-08-18 — The OpenID Foundation conformance suite (gitlab.com/openid/conformance-suite
  `LICENSE.txt`) is MIT. GitHub’s “unclassified” badge on mirrors is why
  `identikey-core-ccf.3` existed. Safe as a Docker CI runner; not a Cargo
  dependency; official certification is a separate paid program.
- 2026-07-28 — `identikey-auth` is `MIT OR Apache-2.0` with zero recrypt deps, but
  `identikey-storage-auth` is `AGPL-3.0-or-later` and depends on `recrypt-core`/`recrypt-wire`.
  They must not share a workspace or the commercial product inherits AGPL entanglement.
  (recrypt/crates/*/Cargo.toml)
- 2026-08-24 — That learning is about Cargo linking, not process placement.
  Running `recrypt-server` (which links `recrypt-storage-auth`) as a sibling
  HTTP process on a household box is mere aggregation; it does not AGPL the
  dashboard. An OP on hardware the user holds does not fail the exit test —
  keys they cannot take would. Self-custody remains an option (today: CLI).
  (`docs/licensing-and-commons.md` §8, `docs/custody-ladder.md` I3)
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
- 2026-08-16 — C2→C3 must not export `managed_key_blob`. After ADR-010 the user
  already holds Elect; they generate a Sign key we have never held, and we
  destroy ours in the same transaction as the document write. The old zan.2
  line "hand them the managed key" and ADR-008's "migration authorised by our
  key" are both withdrawn (ADR-011). (`docs/ARCHITECTURE.md` ADR-011)
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
- 2026-08-16 — `identikey-core-test` still holds the old Drizzle schema. `sqlx migrate
  run` against it dies on `relation "challenges" already exists`. Use a clean DB
  (`identikey-core-sqlx`) for migrate / `cargo sqlx prepare`; `#[sqlx::test]` can
  still use the dirty DB as a maintenance connection. (`.sqlx/`, CLAUDE.md)
- 2026-08-17 — `#[sqlx::test]` can fail setup with `databases_pkey` when a leftover
  `_sqlx_test.databases` row names a db that still exists. Retry once; that is
  infra, not a store bug. (`crates/identikey-keys` tests)
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
- 2026-10-31 — There is no mailer. Signed-in `POST /account/email/begin`
  returns the redeem URL in the JSON body (`redeem_url`, expires in
  900 seconds). The link is not sent.
  (`crates/identikey-server/src/email_link.rs`)
