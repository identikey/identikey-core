# Tasks

- [ ] `ClientJson.sector` and `IDENTIKEY_CLIENT_SECTOR`; both go through `client_from_spec`, which takes the sector verbatim and never derives it
- [ ] Boot refuses a pairwise client whose sector is missing or empty, naming the client; public clients need none
- [ ] `legacy_sector` in a preflight module reproduces `merge_redirects` precedence, `Url::parse(..).host_str()`, and the literal `default` fallback; nothing on the boot or request path calls it
- [ ] `identikey-server check-clients`: candidate loader over primary + JSON config, one row per client (id, source, subject type, pin, legacy, match), no secrets, non-zero exit on refusal or any pairwise mismatch
- [ ] Tests (fixed salt + XID) compare the legacy-derived `sub` with the pinned `sub` for: primary and JSON clients; omitted and explicit pairwise subject type; singular-vs-plural redirect precedence; host case normalization by `Url`; hostless and unparseable redirects (`default`); redirect addition, reordering, replacement, and removal; empty and missing pins refused; public client equals the XID with no sector; sanitized fixtures of taskmaster, taskmaster-laptop, Conduit `localhost`, and wtnf-web
- [ ] `.env.example`, `CLAUDE.md` client examples, and `docs/oidc/README.md` show `sector` and `check-clients`
- [ ] ASK: approve the live rollout (design.md steps 0–4), then cut over (step 5) with the baseline `sub` comparison
- [ ] Fresh advise after preparation

## Owed from advise (2026-09-29, astra-arch-review)

- [x] R1: Amend the rollout contract to inventory effective primary + JSON registrations against escrow/guest configuration; validate the complete proposed configuration with the candidate loader and compare every effective pairwise sector byte-for-byte with the legacy value before cutover. Capture live probe baselines before mutation, preserve the existing salt, and specify backup/abort/rollback while retaining the human gate. Old-binary restart alone is not the preflight. — design.md "Preflight" and "Rollout" steps 0–6.
- [x] R2: Specify verbatim pin handling and exact legacy backfill semantics (`merge_redirects`, URL host extraction, literal `default` fallback), with a migration-helper exception to the runtime no-derivation requirement. Require deterministic legacy-versus-pinned subject equality tests through primary and JSON configuration, sanitized live pairwise fixtures, parser/merge edge cases, redirect replacement/removal/addition/reordering, empty/missing pins, and public subjects. — design.md "Shape", "Legacy semantics"; tasks 3 and 5; spec delta.
