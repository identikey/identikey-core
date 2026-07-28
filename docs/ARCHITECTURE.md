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

## ADR-004: WebAuthn RP ID is `auth.identikey.me` 🟡 Proposed — revised 2026-07-28

**Context.** The RP ID is **permanent** — baked into every credential at registration; changing
it forces every user to re-enrol. It must equal, or be a registrable suffix of, the serving
origin's domain.

Domains actually held: **`identikey.io`** and **`identikey.me`** (both NameCheap, 2023).
`identikey.com` (1998, MarkMonitor) and `identikey.org` both redirect to **OneSpan's
"Authentication Servers" product page** — see the trademark note below. The gTLDs are not
obtainable, so the choice is between two ccTLDs.

**Proposed decision.**

| Origin | Purpose | WebAuthn |
|---|---|---|
| `identikey.io` | marketing, docs, status | never |
| `app.identikey.io` | product UI | never — redirects to the OP |
| **`auth.identikey.me`** | **the OIDC provider: login, consent, account** | **yes — this is the RP ID** |

Publish `/.well-known/webauthn` on the RP ID from day one.

**Rationale 1 — a dedicated auth origin.** The usual "pick the broadest domain, you can never
widen later" advice suits a consumer product with many authenticating surfaces. **An OIDC
provider is not that shape:** auth is centralised by construction — the app redirects to the OP
and never performs WebAuthn itself. There is structurally only ever *one* first-party WebAuthn
origin, so breadth buys nothing and costs blast radius.

**Rationale 2 — `.me` over `.io`, which inverts the earlier draft.** Both are ccTLDs, so the
gTLD-durability argument is unavailable. Between them, **`.io` is the riskier name**: it has an
active, publicised sovereignty question following the Chagos/BIOT handover, while `.me`
(Montenegro) has no comparable open question. For the one identifier that can never change,
prefer the domain with no live retirement discussion attached to it.

`.me` also happens to be the better fit on two independent axes:

- **Absolute cookie isolation.** A subdomain can set a cookie on its parent; an unrelated
  eTLD+1 cannot. Keeping auth on `.me` while marketing and the app live on `.io` eliminates
  cookie-tossing and session-fixation vectors entirely, rather than merely narrowing them.
- **It reads as personal identity** — the right register for a login page on an identity
  product.

Holding both domains is not a new dependency: both are already owned and must be renewed
defensively regardless. The decision is only *which one the credential namespace rests on*.

**Rationale 3 — `auth.` rather than the `identikey.me` root.** An identity product plausibly
wants public profile pages at `identikey.me/<handle>` later, carrying user-controlled content
(display name, avatar, bio) — an XSS surface. If the root were the RP ID, that surface would
sit permanently inside it. `auth.` keeps them separated forever, at the cost of a slightly less
pretty URL. `accounts.google.com` is the precedent. **Do not later add the profile surface as
a Related Origin**, or this separation is undone.

**Related Origins does not rescue a bad RP ID choice.** It lets one RP ID serve login from many
origins; it does not make the RP ID itself relocatable. The RP ID domain is the single name
that must outlive everything.

**Consequences / accepted risk.**

- **WebAuthn at a second first-party origin would mean re-enrolling everyone.** The whole cost
  of the narrow choice. Acceptable only because an OP centralises auth.
- `identikey.me` must never lapse. Set registrar auto-renew, multi-year, with expiry monitoring
  — a lapsed RP ID domain hands the credential namespace to whoever registers it next.
- `WEBAUTHN_EXPECTED_ORIGIN` stays a strict allowlist, never a wildcard.
- Native apps point associated-domain files at `auth.identikey.me`.
- Users see `.me` at login and `.io` elsewhere. Mild, and passkeys are phishing-resistant
  regardless, but worth consistent presentation.

**Alternatives.** `auth.identikey.io` — brand-consistent, but puts the permanent identifier on
the domain with the live sovereignty question. `identikey.me` root — prettier, forecloses a
safe profile surface. `identikey.com` — unobtainable.

**Correcting earlier drafts.** (1) The first claimed XSS on any `*.identikey.io` subdomain
"can exercise the passkey" — overstated: a sibling subdomain could *obtain* an assertion but
not *use* it, since `clientDataJSON` carries the true origin and the server allowlists it.
(2) The second asserted `identikey.com` was available; that was inferred from DNS resolving
behind Cloudflare, which proves nothing about ownership. It is OneSpan's.

**Open.** Confirm `.me` for auth is acceptable given marketing sits on `.io`. See also the
trademark question below, which could moot the whole naming discussion.

---

### Trademark risk on the name itself ⚠️

`identikey.com` (registered 1998, via MarkMonitor — a corporate brand-protection registrar) and
`identikey.org` both redirect to OneSpan's authentication-server product. **IDENTIKEY is a
registered trademark of VASCO Data Security International** (now OneSpan, NASDAQ: OSPN), listed
among their marks in SEC filings, used for an authentication server — *the same product
category we are entering*, with roughly 28 years of prior use.

This is material beyond the domain question:

- The **certification-mark revenue line** (`identikey-core-ydd.11`) proposes licensing
  "IdentiKey Certified". A certification mark in the authentication category is squarely in
  OneSpan's lane and is exactly the kind of commercial use that draws enforcement.
- The **anti-burial trademark policy** (`ydd.3`) presumes we can hold the mark at all.
- Brand exposure grows precisely as the product becomes visible in enterprise identity — the
  "MS Entra alternative" market where OneSpan also sells.

**Mitigating:** OneSpan has *rebranded* IDENTIKEY to "OneSpan Authentication Server." A US
registration unused for three consecutive years is vulnerable to cancellation for abandonment,
so the mark may be weakening or already dormant — which is a risk *and* a possible opening.

**This is a flag, not an opinion — get an actual search.** USPTO and EUIPO, live status,
classes, territories, and evidence of continued use, before further brand investment and
*definitely* before building a revenue line on the mark. Tracked as P0.

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
