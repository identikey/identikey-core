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

## ADR-001: `sub` is a XID — a stable identifier derived from an inception key ✅ Decided (revised 2026-07-28)

**Context.** Identity must survive both *custody* changes and *key* changes.

The first draft of this ADR set `sub` to the fingerprint of the user's current key. That gets
custody right — climbing C2 → C3 keeps the same subject — but it makes **key rotation change
the user's identity**, which is not a corner case:

- **Post-quantum migration is a scheduled rotation.** `identikey-auth` already supports hybrid
  Ed25519 + ML-DSA. Moving to PQ-only rotates every key in the system. A fingerprint-based
  `sub` therefore has a *known future date* on which every identity breaks.
- Key compromise would force a new identity — the worst possible time to lose continuity.
- Device loss, algorithm deprecation, and enclave migration are all ordinary events.

A stable identifier is required. The naive fix — a random opaque ID in our database — is worse:
it makes *us* the authority that says which key belongs to which subject, so a departing user's
`sub` becomes meaningless without our server. That is precisely the capture the project exists
to avoid.

**Decision.** `sub` is a **XID** (eXtensible IDentifier): the SHA-256 of the CBOR encoding of
the user's **inception** public signing key.

- **Self-certifying** — derived from a key, not assigned by us. No authority mints it.
- **Stable for life** — keys rotate beneath it; the XID never changes.
- **Verifiable** — the XID document carries keys, endpoints, permissions and delegations, and
  is signed by the subject's own keys.

This implies a **two-tier key model**: a long-lived *inception key* whose hash is the identity,
and *operational/device keys* that rotate freely underneath it. Rotation becomes a normal,
signed event rather than an identity break. Signal, SSH CAs and the DID family all converge on
this shape for the same reason.

**Implementation.** Adopt `bc-xid` (BCR-2024-010). Three reasons it is the obvious choice
rather than a build:

1. `XID` is already present in `bc-components` 0.31.1, which recrypt depends on today.
2. `bc-xid` is **BSD-2-Clause-Patent** — one of the two branches chosen in ADR-003, so it drops
   into `identikey-protocol` with no licence friction and satisfies ADR-002's
   no-copyleft-dependency rule.
3. It is Gordian Envelope / dCBOR native, matching `identikey-auth`'s existing wire format.

`bc-components` also ships **SSKR** (Sharded Secret Key Reconstruction), which is directly
relevant to the guardian-recovery work — worth evaluating there rather than reaching for a
separate Shamir implementation.

**Consequences.**

- Custody migration (C2 → C3) and key rotation are now *both* non-events for identity. That was
  the goal.
- The OP mints tokens *about* a XID, never *instead of* one. A C4 sole-custody user has a `sub`
  we have never held a private key for.
- **A resolution story is now required.** A stable identifier is only useful if a relying party
  can obtain current key state. See Open Questions — this is the real remaining cost of the
  decision, and it is smaller than it looks: because the XID document is signed by the subject,
  a resolver can serve it but cannot forge it. Losing our resolver costs *freshness*, not
  *verifiability* — an availability dependency, not a trust dependency.
- Supersedes the successor-key-attestation task filed under ADR-001's first draft; XID's
  rotation model covers it, except for pre-rotation (below).

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

## ADR-004: WebAuthn RP ID is `auth.identikey.com` 🟡 Proposed — revised twice, 2026-07-28

**Context.** The RP ID is **permanent**. It is baked into every credential at registration;
changing it forces every user to re-enrol. It must equal, or be a registrable suffix of, the
serving origin's domain.

**Proposed decision.**

| Origin | Purpose | WebAuthn |
|---|---|---|
| `identikey.com` | marketing, docs, status | never |
| `app.identikey.com` | product UI | never — redirects to the OP |
| **`auth.identikey.com`** | **the OIDC provider: login, consent, account** | **yes — this is the RP ID** |
| `identikey.io` / `.me` / `.org` | redirects, defensive registrations | — |

Publish `/.well-known/webauthn` (Related Origin Requests) on the RP ID from day one.

**Rationale 1 — a dedicated auth origin, not the registrable domain.** The usual advice is
"pick the broadest domain, you can never widen later." That is right for a consumer product
with many first-party surfaces that each authenticate. **An OIDC provider is not that shape:**
auth is centralised by construction — the app redirects to the OP and receives tokens back, and
never performs WebAuthn itself. So there is structurally only ever *one* first-party WebAuthn
origin, and the argument for breadth evaporates. Given that, narrow is strictly better: a
compromise of the marketing site or the app cannot reach passkeys at all.

`auth.` over `id.` — `id.identikey` is repetitive, and `auth.` matches the convention users
already recognise (`accounts.google.com`, `login.microsoftonline.com`).

**Rationale 2 — the gTLD, because the RP ID domain must outlive everything.** All four of
`identikey.{io,me,com,org}` are held. `.io` and `.me` are **ccTLDs**; `.com` and `.org` are
gTLDs with no retirement mechanism. `.io` in particular has an active, publicised sovereignty
question following the Chagos/BIOT handover. Retirement of a ccTLD is slow and well-signposted
— `.yu` took years, `.su` never happened — so this is low-probability and long-horizon.

But the cost if it lands is total: **an RP ID on a dead domain means every passkey is dead**,
and worse, whoever acquires the name inherits the credential namespace. And the mitigation is
free, because we already own the gTLD.

**Related Origins does not rescue this.** It lets one RP ID serve login from *many origins* —
it does not make the RP ID itself relocatable. The RP ID domain is the one thing that must
survive forever. That asymmetry is the whole argument: put the RP ID on the most durable name
you own, then serve login from wherever the branding wants via Related Origins.

**Consequences / accepted risk.**

- **If we ever want WebAuthn at a second first-party origin, every user re-enrols.** The whole
  cost of the narrow choice. Acceptable only because an OP centralises auth; if that assumption
  breaks, this ADR breaks with it.
- **Do not later move the OP to a domain root.** That path closes once credentials exist.
- `WEBAUTHN_EXPECTED_ORIGIN` must stay a strict allowlist, never a wildcard.
- Native apps are unaffected — associated-domain files point at `auth.identikey.com`.
- `identikey.io` / `.me` / `.org` must be renewed indefinitely anyway as defensive
  registrations, but nothing cryptographic depends on them.

**Alternatives considered.**

- **`auth.identikey.io`** — brand-consistent if `.io` is the primary identity. Inherits the
  ccTLD question on the one name that can never change. Viable; the risk is real but small.
- **`identikey.me`** — genuinely attractive: `.me` reads as personal identity, and a separate
  registrable domain gives *absolute* cookie isolation (a subdomain can set a cookie on its
  parent; an unrelated eTLD+1 cannot), which is stronger than the subdomain separation above.
  Rejected because it is a ccTLD *and* a second permanent renewal dependency — two ways to lose
  the credential namespace instead of one. Worth revisiting only if the cookie-isolation
  argument proves load-bearing in the session design.
- **`identikey.com` root** — conflates marketing with auth; loses the blast-radius separation.

**Correcting the first draft.** It claimed XSS on any `*.identikey.io` subdomain "can exercise
the passkey." Overstated: a script on a sibling subdomain could *obtain* an assertion for a
broad RP ID, but not *use* it — `clientDataJSON` carries the true origin and the server
allowlists it via `WEBAUTHN_EXPECTED_ORIGIN`. Strict origin allowlisting is the real
mitigation; the case for a dedicated auth origin rests on architectural fit, not that risk.

**Open.** Confirm `identikey.com` is the intended primary user-facing domain. If the brand is
committed to `.io`, say so and this becomes `auth.identikey.io` with the ccTLD risk accepted
and documented.

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

1. **Pre-rotation.** KERI commits to a *digest of the next key* at each rotation, so a
   compromised current key cannot rotate to an attacker's key. Whether `bc-xid` supports this,
   and whether we need it, is unresolved — it matters most at C3/C4 where there is no
   custodian to appeal to. **Check before the protocol split lands.**
2. **XID document resolution.** Who serves it, and how does a relying party get fresh key
   state? Candidates: the OP (availability dependency only — it cannot forge a signed
   document), a user-controlled endpoint, recrypt storage, or a witness set. A user must be
   able to self-host or relocate resolution, or the exit test degrades.
3. **Pairwise subject identifiers.** A global self-certifying `sub` lets every relying party
   correlate the same user across services. OIDC's `pairwise` subject type exists for exactly
   this. Likely shape: XID is the canonical internal identity; the `sub` shown to an ordinary
   RP is derived from (XID, sector_identifier), with the bare XID disclosed only where the user
   wants to be linkable. Painful to retrofit — decide before the first token is issued.
4. **Stewardship structure** — `licensing-and-commons.md` §5 (a)/(b)/(c)/(d). Currently
   materially (b).
5. **C2 consent-record format.** Signed by what, stored where, shown how. Probably a capability
   envelope reusing the `identikey-storage-auth` chain machinery.
6. **Is WebCrypto non-extractable a distinct rung (C2.5)?** Stronger than C2, weaker than C3;
   device loss unrecoverable. Deferred.
7. **Does the OP advertise custody rung to relying parties** via `acr`/`amr`? Useful for
   RPs wanting to require C3+, but leaks user posture to every RP. Default: no.
