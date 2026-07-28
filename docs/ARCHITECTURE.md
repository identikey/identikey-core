# Architecture — IdentiKey Core

**Status:** Living document. ADRs inline, amended rather than deleted.
**Date:** 2026-07-28

**Supersedes** `_bmad-output/planning-artifacts/architecture.md` (ADR-001…009), which describes
the Keycloak-era design. That document is retained for provenance; where the two disagree, this
one is authoritative.

---

## What this is

The identity layer of the sovereign stack. A Rust auth server plus a web UI, serving the
**managed rungs** of the custody ladder and projecting them onto standard OIDC for relying
parties that only speak OAuth.

```
identikey-protocol/          Apache-2.0 OR BSD-2-Clause-Patent — separate repo
  identikey-auth             A4: enclave challenge/response, cipher-agile, PQ-ready
  docs/standards/            the specs + test vectors

identikey-core/  (here)      AGPL-3.0-or-later + commercial
  crates/identikey-oidc      rung 3: the OIDC provider
  crates/identikey-keys      rung 2: managed custody, consent records, C2→C3 migration
  crates/identikey-recovery  rung 1.5: guardian quorum, Shamir, MPC
  crates/identikey-server    axum binary; also serves the SSG assets
  web/                       SvelteKit, adapter-static — login / consent / account UI
```

Companion documents: [`custody-ladder.md`](./custody-ladder.md) (the normative rungs),
[`licensing-and-commons.md`](./licensing-and-commons.md),
[`passkey-requirements.md`](./passkey-requirements.md), [`LEARNINGS.md`](./LEARNINGS.md).

---

## ADR-001: `sub` is the key fingerprint at every custody rung ✅ Decided

**Context.** A user's identity must survive moving between custody rungs. If climbing from
managed custody (C2) to self-custody (C3) issued a new identifier, every downstream relying
party, capability chain and stored record would break — and nobody would climb.

**Decision.** The subject of every token, capability and record is the **Ed25519 public-key
fingerprint**. It does not change when custody changes. Moving C2 → C3 is a change of *holder*,
not of *identity*.

**Consequences.**

- The OP mints tokens *about* a key, never *instead of* one. A C4 sole-custody user has a `sub`
  the OP has never held the private half of.
- Key rotation is therefore a genuinely hard problem, not a free one: rotating the key changes
  the subject. Needs an explicit successor-key mechanism (signed attestation from old to new)
  before any rotation feature ships. **Open — see Open Questions.**
- Capability chains in `identikey-storage-auth` already key on fingerprints, so this is
  consistent with what recrypt does rather than a new convention.

**Why this matters beyond tidiness.** It is what makes the exit test satisfiable. A user who
leaves takes their key, and everything that referenced them still verifies against a server
they no longer talk to.

---

## ADR-002: Protocol crates live in a separate repository ✅ Decided

**Context.** `identikey-auth` is a protocol library with many consumers (recrypt, mjolnir,
Papyrus, the native app, this repo). `identikey-core` is a product. They have different
audiences, different release cadences, and — decisively — **different licences**.

**Decision.** Split `identikey-protocol` into its own repo holding `identikey-auth` and the
specs. `identikey-storage-auth` stays with recrypt.

**Consequences.**

- Consumers depend on a published crate, not on the product repo.
- **`identikey-storage-auth` must not move into the protocol workspace.** It is
  `AGPL-3.0-or-later` and depends on `recrypt-core`/`recrypt-wire`; putting it beside the
  commercially-licensed product would create exactly the entanglement the tiering avoids.
- **Standing rule: the protocol tier may never take a copyleft dependency.** One AGPL/MPL/GPL
  dep in `identikey-auth` collapses the permissive strategy. `cargo-deny` enforces a stricter
  allowlist there than elsewhere. Currently clean — `identikey-auth` has zero workspace deps.

---

## ADR-003: Protocols permissive, products copyleft-plus-commercial ✅ Decided

**Context.** The work must survive its steward (the PGP lesson), *and* fund itself. See
[`licensing-and-commons.md`](./licensing-and-commons.md) for the full analysis.

**Decision.**

| Tier | Licence |
|---|---|
| Specs | OWFa or CC-BY + patent non-assert *(pending)* |
| Protocol code | **`Apache-2.0 OR BSD-2-Clause-Patent`** |
| Products (this repo, recrypt server/cli, native app) | **`AGPL-3.0-or-later` + commercial** |

**Consequences.**

- Both protocol branches carry a *mandatory* patent grant, so the disjunction is a choice of
  compliance regime, not of protection level. This is what made `MIT OR Apache-2.0` unsafe.
- Apache gives the corporate-allowlist path; BSD-2-Clause-Patent gives GPLv2 reach, which
  matters because OpenWrt and Freifunk-adjacent firmware are GPL-2.0 and the identity primitive
  must be linkable there.
- Inbound contributions to the protocol tier must match the disjunctive expression; a
  single-licensed file silently collapses the choice for the whole crate.
- **`identikey-core` currently has no licence declared at all.** Blocking — `identikey-core-ydd.5`.

---

## ADR-004: WebAuthn RP ID is a dedicated auth origin 🟡 Proposed — revised 2026-07-28

**Context.** The RP ID is **effectively permanent**: it is baked into every credential at
registration, and changing it forces every user to re-enrol. It must equal, or be a
registrable suffix of, the origin's domain. An RP ID of `identikey.io` works for any
`*.identikey.io` origin; an RP ID of `id.identikey.io` works only at or below that name.

**Proposed decision.**

| Origin | Purpose | WebAuthn |
|---|---|---|
| `identikey.io` | marketing, docs, status | never |
| `app.identikey.io` | the product UI | never — redirects to the OP |
| **`id.identikey.io`** | **the OIDC provider: login, consent, account** | **yes — this is the RP ID** |

Publish `/.well-known/webauthn` (Related Origin Requests) on the RP ID from day one.

**Rationale — why not the registrable domain.** The usual advice is "pick the broadest domain,
because you can never widen later," and that is right for a consumer product with many
first-party surfaces that each authenticate. **An OIDC provider is not that shape.** Auth is
centralised by construction: the app never performs WebAuthn, it redirects to the OP and
receives tokens back. So there is structurally only ever *one* first-party origin doing
WebAuthn, and the argument for breadth mostly evaporates.

Given that, the narrow choice is strictly better:

- **Tightest blast radius.** A compromise of the marketing site or the app cannot reach
  passkeys at all — different RP ID, and the origin check fails.
- **It matches the architecture** rather than hedging against a topology we are not building.
- Related Origins remains available for white-labelled login on customer domains, with either
  choice — so the narrow RP ID costs nothing there.

**Correcting the previous draft.** The first version of this ADR recommended `identikey.io`
and claimed that XSS on any `*.identikey.io` subdomain "can exercise the passkey." That
overstated it. A script on `evil.identikey.io` could *obtain* an assertion for a broad RP ID,
but it could not *use* it against us: `clientDataJSON` carries the true origin, and the server
verifies it against a strict allowlist — the mechanism already exists as
`WEBAUTHN_EXPECTED_ORIGIN`. The residual risk is real but narrower than stated, and strict
origin allowlisting is the actual mitigation. The case for a dedicated auth origin rests on
architectural fit, not on that risk.

**Consequences / accepted risk.**

- **If we ever want WebAuthn at a second first-party origin, every user re-enrols.** This is
  the whole cost of the decision. It is acceptable only because an OP centralises auth; if
  that assumption ever breaks, this ADR breaks with it.
- Native apps are unaffected — associated-domain files
  (`apple-app-site-association`, `assetlinks.json`) point at `id.identikey.io`.
- **Do not later move the OP to `identikey.io/login`.** Some products serve auth from the
  root; that path is closed once credentials exist under `id.`. Decide now, permanently.
- `WEBAUTHN_EXPECTED_ORIGIN` must stay a strict allowlist, never a wildcard.

**Alternatives.** `identikey.io` (registrable domain) — maximum future flexibility, wider blast
radius, and hedges against a topology we are not building. `app.identikey.io` — conflates the
product surface with the auth surface; if the app and the OP ever separate, the RP ID is
stranded on the wrong one.

**Open.** Confirm `identikey.io` is the durable production domain, and pick the auth subdomain
(`id.` vs `auth.` — cosmetic, but permanent).

## ADR-005: The URN grant requires an `identikey-auth` Response, not a WebAuthn assertion 🟡 Proposed

**Context.** `urn:identikey:params:oauth:grant-type:challenge-response` lets a key holder obtain
OIDC tokens for legacy relying parties without the OP ever holding a key. The open question
(`identikey-core-h4p`) was whether a WebAuthn assertion should also satisfy it, unifying rung 1
and rung 3 behind one verifier.

**Proposed decision.** **No.** The URN grant accepts only an `identikey-auth` `Response`.
WebAuthn authenticates through the ordinary authorization-code flow.

**Rationale.** The two prove different things, and conflating them muddles the ladder:

- The **URN grant** proves *"I hold the IdentiKey key."* Raw signature over domain-separated
  canonical dCBOR, verifier-issued nonce, audience-bound, cipher-agile with a downgrade-proof
  policy.
- A **WebAuthn assertion** proves *"I hold a passkey that is registered against an account."*
  RP-ID-bound, browser-mediated, with its own replay model (signature counters, origin binding,
  client data JSON).

Accepting both formats at the single most security-critical endpoint means two parsers, two
replay defences and two downgrade surfaces on the path that mints tokens. That is a poor trade
for a convenience that the auth-code flow already provides.

The custody-ladder framing makes it clean: WebAuthn is access level **A3**, which authenticates
you *to the party holding your key* (C1/C2) — normal OIDC. The URN grant is for **A4**, where
you hold the key yourself, at any rung. Different column *and* different row.

**Consequences.**

- One proof format, one verifier, minimal surface on the token endpoint.
- A C3/C4 user with a passkey uses the passkey for local key unlock, then the URN grant with the
  unlocked key — the passkey never crosses the wire to us.
- Costs a little elegance: there is no single endpoint that "does both." Judged worth it.

---

## ADR-006: Postgres via `sqlx`; `pglite` only for genuine embedding 🟡 Proposed

**Context.** Standardising on Postgres. recrypt currently uses SQLite via `rusqlite`, behind
already-abstracted store traits (`OwnershipStore`, `GrantStore`, `KeyspaceStore`,
`AccountStore`), so a `postgres` feature is mechanical rather than a rewrite.

**Proposed decision.** `sqlx`, with the offline query cache committed. Real Postgres in dev and
CI. `pglite` reserved for in-process embedding (the desktop app), never as the dev default.

**Rationale.** Compile-time-checked SQL is worth the build-time friction in an auth server —
the failure mode of a wrong query here is a security bug, not a 500. And a dev/prod split
between `pglite` and Postgres diverges precisely where it hurts: concurrency, advisory locks,
and `SELECT … FOR UPDATE SKIP LOCKED` on the challenge and token tables.

**Consequences.** `DATABASE_URL` needed at build time unless the offline cache is current — CI
must verify the cache is not stale. `recrypt-server`'s direct `tokio_rusqlite` use (outside the
store traits) needs converting.

---

## Open questions

1. **Key rotation under ADR-001.** Rotating changes the subject. Needs a signed
   successor-attestation mechanism, designed before any rotation feature ships.
2. **Stewardship structure** — `licensing-and-commons.md` §5 (a)/(b)/(c)/(d). Currently
   materially (b).
3. **C2 consent-record format.** Signed by what, stored where, shown how. Probably a capability
   envelope reusing the `identikey-storage-auth` chain machinery.
4. **Is WebCrypto non-extractable a distinct rung (C2.5)?** Stronger than C2, weaker than C3;
   device loss unrecoverable. Deferred.
5. **Does the OP advertise custody rung to relying parties** via `acr`/`amr`? Useful for
   RPs wanting to require C3+, but leaks user posture to every RP. Default: no.
