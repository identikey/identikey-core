# Tasks

Owed by this architecture activation (`nod-guild-keyspace-arch`) only:

- [x] `openspec/changes/add-guild-keyspaces` proposal, design, deltas
- [x] Independent architecture read (advise 2026-09-01: send-back)
- [ ] Cite `identikey-keyspace-v1`; do not fork kinds / genesis id / admin field / epoch conflict
- [ ] Map C2 Elect/Sign and `credentials` devices onto PUK wrap-targets (protocol §2.1 / §5)
- [ ] Remove radio and Lightning Admin SHALLs from `guild-keyspaces` deltas
- [ ] Fix device-revoke scenario: PUK rotate then rewrap; device is not on the PTK wrap-list
- [ ] Distinguish fade (no admin) from remaining PTK wraps until epoch
- [ ] Re-advise after those amends
- [ ] ADR-012 in `docs/ARCHITECTURE.md` (act after advise accept)

Not owed here (bullets, not boxes):

- Protocol spec with test-vector hooks — `ikp-cvu` / `add-keyspace-spec`
- Runtime wrap/join/leave/rotate — `add-keyspace-runtime`
- Access-node inner keyspace — `identikey-core-trr.2`
- Fleet client SSID / network name — `add-client-network-name` (lightning-mesh)
- Lightning Admin v2 verbs — `add-lightning-admin-guild`
- Keycloak `user.guilds` rename
- Wallet `"keyspace-membership"` assertion
