# Tasks

Owed by this architecture activation (`nod-guild-keyspace-arch`) only:

- [x] `openspec/changes/add-guild-keyspaces` proposal, design, deltas
- [x] Independent architecture read (advise 2026-09-01: send-back)
- [x] Cite `identikey-keyspace-v1`; do not fork kinds / genesis id / admin field / epoch conflict
- [x] Map C2 Elect/Sign and `credentials` devices onto PUK wrap-targets (protocol §2.1 / §5)
- [x] Remove radio and Lightning Admin SHALLs from `guild-keyspaces` deltas
- [x] Fix device-revoke scenario: PUK rotate then rewrap; device is not on the PTK wrap-list
- [x] Distinguish fade (no admin) from remaining PTK wraps until epoch
- [x] Re-advise after those amends (advise 2026-09-01: accept-with-nits)
- [ ] ADR-012 in `docs/ARCHITECTURE.md` (act after advise accept)

Not owed here (bullets, not boxes):

- Protocol wire — `identikey-keyspace-v1` (already folded)
- Runtime wrap/join/leave/rotate — `add-keyspace-runtime`
- Access-node wrap-on-login — `identikey-core-trr.2`
- Fleet client SSID — lightning-mesh `client-network-name`
- Lightning Admin SSID knob — `mjolnir-mesh-st1.3`
- Lightning Admin v2 verbs — `add-lightning-admin-guild`
- Keycloak `user.guilds` rename
- Wallet `"keyspace-membership"` assertion
