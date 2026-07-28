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
