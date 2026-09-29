# Tasks

- [ ] `ClientJson.sector` and `IDENTIKEY_CLIENT_SECTOR`; `client_from_spec` takes the sector and never derives it from a redirect
- [ ] Boot refuses a pairwise client with no sector, naming the client; public clients need none
- [ ] Tests: reordering or adding redirects leaves a pairwise `sub` unchanged; missing sector refuses; public client without sector boots
- [ ] `.env.example`, `CLAUDE.md` client examples, and `docs/oidc/README.md` show `sector`
- [ ] Backfill helper that prints each pairwise client's current derived sector from an `IDENTIKEY_CLIENTS` value (no secrets printed)
- [ ] ASK: approve the live escrow backfill (design.md steps 1–3) before deploy
- [ ] Deploy and verify taskmaster and Conduit pairwise `sub` unchanged for a known XID
