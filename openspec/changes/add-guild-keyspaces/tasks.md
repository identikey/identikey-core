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
- [x] ADR-012 in `docs/ARCHITECTURE.md` (act after advise accept)

Owed by send-back 2026-09-11 (`reviews/2026-09-11-advise.md`, fable-5.1-arch-review):

- [x] Name the C2 PUK against the stored document: `c2_native` + `PrivateKeyBase::new()` yields Schnorr (secp256k1) + X25519, not Ed25519 or P-256. Decide X25519 encapsulation half vs a distinct user-held PUK; amend ADR-012 §4 and design.md wording; state C1 rows and rows with no user-held private key have no wrap-target; state PUK rotation in-document is an Elect rewrite
- [x] Name the Ed25519 `Op.actor` for a member of this store (Schnorr user key cannot author ops or be admin); say where the admin companion lives and whether A4 `identikey_auth` device keys are excluded
- [x] State the live-instance premise: signup drops the user's Elect private key; no C2 row can unwrap until a named user-held-key surface exists; amend `add-keyspace-runtime` design "at C2 it usually is the PUK" to match
- [ ] Re-advise after 2026-09-11 PUK/actor/live-instance amends

Not owed here (bullets, not boxes):

- Protocol wire — `identikey-keyspace-v1` (already folded)
- Runtime wrap/join/leave/rotate — `add-keyspace-runtime`
- Access-node wrap-on-login — `identikey-core-trr.2`
- Fleet client SSID — lightning-mesh `client-network-name`
- Lightning Admin SSID knob — `mjolnir-mesh-st1.3`
- Lightning Admin v2 verbs — `add-lightning-admin-guild`
- Keycloak `user.guilds` rename
- Wallet `"keyspace-membership"` assertion
