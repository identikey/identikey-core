# Architecture — IdentiKey Core

**Status:** Living document. ADRs inline, amended rather than deleted.
**Date:** 2026-07-28

**Supersedes** the Keycloak-era `_bmad-output/planning-artifacts/architecture.md`, deleted
2026-08-07 (`identikey-core-sbw.1`) once it had drifted into contradicting this document on the
central fact of the pivot. It survives in history at tag `pre-rust-pivot` if provenance is ever
needed. The surviving BMAD-era material is `docs/passkey-port-spec/`, kept as the port
specification for `identikey-core-5gh.1`.

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

**Scaffolded 2026-08-07.** The four crates exist, build, and pass `clippy -D warnings`
and `cargo deny check`. `identikey-keys` owns the Postgres schema (`zan.1`) and a
durable `KeysStore` (`add-keys-store`, 2026-08-16): boot requires `DATABASE_URL`,
migrates, and refuses an Elect-denied document write. C2→C3 is
`migrate_c2_to_c3` (ADR-011, folded `add-c2-c3-exit`). Devices are
`credentials` rows (`add-device-records`, 2026-08-17): `list_devices` /
`revoke_device`, no `devices` table, no `device_trust` / `is_master`.
`web/` is *not* yet in place — the SvelteKit
app is still at the repository root, frozen at tag `pre-rust-pivot`. Relocating
it is `identikey-core-ccf.11`.

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
  can obtain current key state. Settled in **ADR-007**. ⚠️ This bullet originally argued the cost
  was "smaller than it looks" because a signed document cannot be forged, so losing our resolver
  would cost *freshness, not verifiability — availability, not trust.* **ADR-007 corrects that.**
  A resolver cannot forge a document but it can serve an **old, validly-signed** one, and after a
  compromise rotation that presents the attacker's key as current. Withholding an update is
  indistinguishable in effect from authorising the attacker, so freshness is a security property
  and resolution is partly a trust dependency.
- Supersedes the successor-key-attestation task filed under ADR-001's first draft; XID's
  rotation model covers it, except for pre-rotation (below).
- ⚠️ **`bc-xid` brings a dependency tail this ADR did not price, discovered 2026-08-07 when
  `cargo deny` first ran against the Rust workspace.** The licence reasoning above holds —
  every crate in the tail is permissive. The *supply chain* reasoning was never done:
  - `rsa` 0.9, carrying **RUSTSEC-2023-0071** (Marvin timing attack) with **no fix
    available**, via `ssh-key` inside `bc-components`. Harmless today only because
    IdentiKey performs no RSA operation; that ceases to be true the moment anything
    accepts an SSH RSA key (`identikey-core-zan.9`).
  - `pqcrypto-mldsa` / `-mlkem` / `-traits` / `-internals`, all **unmaintained because
    upstream PQClean is being archived**. This one bites where it hurts: the argument for
    a XID over a key fingerprint *is* that PQ migration is a scheduled certainty, so the
    ML-DSA implementation is not incidental — it is the thing this decision was made in
    anticipation of, and it is unmaintained beneath us (`identikey-core-zan.10`).

  Neither is a reason to revisit the decision; `bc-xid` remains the right choice. Both are
  reasons to treat "adopt a crate" as including its transitive tail, which this ADR did not.

## ADR-002: Protocol crates live in a separate repository ✅ Decided — realized 2026-08-01

**Status.** Done. [`identikey-protocol`](https://github.com/identikey/identikey-protocol) now
holds `identikey-auth`, `identikey-wallet` (the wallet engine extracted from `recrypt-cli`),
`identikey-log`, and the `ikey` CLI, under `Apache-2.0 OR BSD-2-Clause-Patent`. Recorded on the
recrypt side as D-4 (`docs/decisions/2026-08-02-protocol-tier-extraction.md`), which also
freezes the wallet compatibility surfaces. `identikey-storage-auth` stayed with recrypt as this
ADR requires. Remaining protocol work — crates.io publish, specs with test vectors, and the
`cargo-deny` gate that makes the no-copyleft rule below enforced rather than merely asserted —
is tracked in that repo's own bd workspace (`ikp-6yz`, `ikp-45w`), not here.

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

## ADR-004: WebAuthn RP ID is `auth.identikey.me` ✅ Decided 2026-07-28

**Context.** The RP ID is **permanent** — baked into every credential at registration; changing
it forces every user to re-enrol. It must equal, or be a registrable suffix of, the serving
origin's domain.

Domains actually held: **`identikey.io`** and **`identikey.me`** (both NameCheap, 2023).
`identikey.com` (1998, MarkMonitor) and `identikey.org` both redirect to **OneSpan's
"Authentication Servers" product page** — see the trademark note below. The gTLDs are not
obtainable, so the choice is between two ccTLDs.

**Decision.**

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

**Confirmed 2026-07-28** by Duke: `.me` for auth, marketing on `.io`.

**Scope of what this decision does and does not settle.** It fixes the *credential namespace*
— the one string that can never change. It does **not** settle the product name or the
marketing domain, which remain revisable and are subject to the trademark question below. If
the name has to change, `auth.identikey.me` can keep serving as the RP ID behind a differently
branded login page (the RP ID is an identifier, not a user-facing brand); losing the *domain*
is the only thing that costs re-enrolment. Do not treat this ADR as a reason to consider the
naming question closed.

**Actions this decision commits us to** (before the first production credential is written):

1. `identikey.me` — registrar lock, multi-year auto-renew, independent expiry monitoring.
2. Serve `/.well-known/webauthn` from `auth.identikey.me` from the first deploy.
3. `WEBAUTHN_EXPECTED_ORIGIN = https://auth.identikey.me` — strict allowlist, never a wildcard.
4. Never add a profile/user-content origin as a Related Origin.

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

## ADR-005: The URN grant requires an `identikey-auth` Response, not a WebAuthn assertion ✅ Decided 2026-08-01

**Context.** `urn:identikey:params:oauth:grant-type:challenge-response` lets a key holder obtain
OIDC tokens for legacy relying parties without the OP ever holding a key. The open question
(`identikey-core-h4p`) was whether a WebAuthn assertion should also satisfy it, unifying rung 1
and rung 3 behind one verifier.

**Decision.** **No.** The URN grant accepts only an `identikey-auth` `Response`.
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

**Two further arguments, added when this was decided — both stronger than the original draft's.**

**Privilege separation would be defeated at the token boundary.** ADR-008 splits `bc-xid`
privileges so that at C2 the user's key holds `Elect` + `Transfer` while ours holds `Sign` +
`Auth`. A passkey is a credential holding **`Auth`**. The key that satisfies the URN grant may
hold `Sign`, `Elect`, `Transfer`. If a WebAuthn assertion could satisfy the grant, an
**`Auth`-only credential would mint tokens indistinguishable from ones backed by full key
authority** — collapsing the separation at the one place it most needs to hold.

**It makes invariant I2 enforceable structurally rather than by policy.** I2 (`custody-ladder.md`)
requires that account recovery and key recovery never merge, and calls any breach of it a release
blocker. A passkey is re-registerable through an **A1** mechanism — an email link. So if a
passkey assertion satisfied the URN grant, **an email link would transitively reach a C3 key**,
which is exactly the silent collapse to C1 that I2 forbids. Refusing the assertion at the grant
makes that unreachable by construction, rather than something a future change might quietly
reintroduce.

**Consequences.**

- One proof format, one verifier, minimal surface on the token endpoint.
- A C3/C4 user reaches their key through **local user verification**, then signs the URN grant
  challenge with it. Nothing about that flow crosses the wire to us. Note this is *not*
  necessarily WebAuthn: on a native app it is the platform biometric gating the enclave or
  keychain item, and no passkey is involved at all. WebAuthn appears at C3/C4 only in a browser
  context, via the `prf` extension used to unwrap a locally-stored key — where it is a
  key-wrapping mechanism rather than an authentication. See `custody-ladder.md`, "Local user
  verification is not an access level."
- Costs a little elegance: there is no single endpoint that "does both." Judged worth it.

---

## ADR-006: Postgres via `sqlx`; `pglite` only for genuine embedding ✅ Decided 2026-07-30

**Context.** Standardising on Postgres. recrypt currently uses SQLite via `rusqlite`, behind
already-abstracted store traits (`OwnershipStore`, `GrantStore`, `KeyspaceStore`,
`AccountStore`), so a `postgres` feature is mechanical rather than a rewrite.

**Decision.** `sqlx`, with the offline query cache committed. Real Postgres in dev and
CI. `pglite` reserved for in-process embedding (the desktop app), never as the dev default.

**Rationale.** Compile-time-checked SQL is worth the build-time friction in an auth server —
the failure mode of a wrong query here is a security bug, not a 500. And a dev/prod split
between `pglite` and Postgres diverges precisely where it hurts: concurrency, advisory locks,
and `SELECT … FOR UPDATE SKIP LOCKED` on the challenge and token tables.

**Consequences.** `DATABASE_URL` needed at build time unless the offline cache is current — CI
must verify the cache is not stale. `recrypt-server`'s direct `tokio_rusqlite` use (outside the
store traits) needs converting.

**Actions this decision commits us to:**

1. Commit `.sqlx/` and add a CI step that fails when the offline cache is stale — a cache that
   silently drifts turns compile-time SQL checking into decoration. Done as `identikey-core-xg2`.
2. Real Postgres service container in CI; no SQLite or `pglite` fallback in the test path.
3. Convert `recrypt-server`'s direct `tokio_rusqlite` usage to go through the store traits
   (`identikey-core-zan.4`) — it is the one place that bypasses the abstraction.
4. If `pglite` is ever introduced for the desktop app, it runs the *same* migrations and the
   same trait implementations, and its divergences (advisory locks, `SKIP LOCKED`) are tested
   explicitly rather than assumed equivalent.

---

## ADR-007: XID document resolution — controller-designated resolvers, threshold reads ✅ Decided 2026-08-01

**Context.** ADR-001 makes `sub` a XID. A stable identifier is only useful if a relying party
can obtain *current* key state, so this is the remaining cost of ADR-001 (`identikey-core-zan.6`).

**Correcting the framing in `zan.6`.** That bead reasoned: the document is signed by the
subject, so a resolver can serve but not forge it — therefore losing our resolver costs
"freshness, not verifiability; an availability dependency, not a trust dependency."

**Freshness *is* a security property.** A resolver cannot forge a document, but it can serve an
old, validly-signed one. If key K1 is compromised and the user rotates to K2, the previous
document is still correctly signed and still lists K1. A resolver serving it — maliciously or
from a stale cache — presents an attacker's key as current. Withholding an update is
indistinguishable in effect from authorising the attacker. So resolution is *partly* a trust
dependency, and the design must make staleness detectable rather than assume it is benign.

**Decision.**

1. **The document declares its own resolvers.** `bc-xid` provides `resolution_methods()` — a set
   of URIs inside the signed document. The controller designates them; because the set is
   signed, relocation is a document update, not a support request. IdentiKey runs one resolver
   and is never the only permitted one.
2. **Provenance marks are the ordering primitive.** `bc-xid`'s `Provenance` gives a verifiable
   chain of revisions, so "newer" is checkable without trusting the resolver that served it.
3. **Threshold reads for consequential operations.** A relying party that needs assurance
   queries K of the N declared resolvers and takes the highest provenance mark. Disagreement
   beyond staleness — two valid documents that are not on the same chain — is a duplicity
   signal: **fail closed**, do not pick a winner.
4. **Freshness tiers by operation value.** An ordinary OIDC login may use a cached document
   within a short TTL. Key-graph changes, delegation issuance, custody migration and wallet-class
   actions require a fresh threshold read. One resolution mechanism, tiered strictness.
5. **The OP is a convenience resolver, never a root of trust.** It serves the document over a
   well-known path as an availability service. It holds no authority the document does not
   grant it.

**Rationale — what we take from KERI, and what we decline.** KERI's witness sets and duplicity
detection exist for exactly the staleness problem above, and the pattern is worth adopting:
controller-designated servers, threshold agreement, relocatable by the controller. We adopt the
*pattern* and decline the *stack*. KERI's substrate is CESR/ACDC; ours is dCBOR / Gordian
Envelope — `identikey-auth` signs over canonical dCBOR and `bc-xid` is Gordian-native. Running
both would mean a permanent translation layer between two canonical encodings, which is where
signature-verification bugs live. The Rust KERI implementations are also fragmented and thinly
adopted relative to `bc-xid`. KERI's real value to us is as an audit checklist for corner cases
we must cover anyway: partial rotation, superseding recovery, multi-sig thresholds, and
rotation of the resolver set itself.

**Consequences.**

- Resolver relocation must be a first-class, self-service ceremony, or the exit test degrades
  from "leave intact" to "leave and hope someone cached you."
- A revocation or compromise rotation needs a short TTL and a push signal; the worst case is an
  RP honouring a rotated-out key for the length of its cache.
- Rotating the *resolver set* is itself a key-graph change and must require the same authority
  as `Privilege::Update`, or the resolver set becomes the soft underbelly of the identity.
- Threshold reads cost latency on exactly the operations that can least afford to be wrong.
  Accepted: those are also the operations that can most afford the milliseconds.

**Interaction with pairwise subjects (open question 3).** If an ordinary RP sees only a pairwise
pseudonym, it cannot resolve the XID document at all — resolution serves the parties who see the
real XID. These two decisions constrain each other and should be settled together.

**K and N — resolved, and the ladder decides it.**

At C1/C2, **N=1 (IdentiKey alone) is an acceptable default**, because at those rungs IdentiKey
*already holds the key*. A dishonest custodian has no need to lie about resolution — it can
simply sign. Resolver honesty is dominated by custodian honesty, so additional resolvers buy
nothing a C2 user does not already have to assume. Cheap default, no security theatre.

At **C3/C4 the calculus inverts.** The user holds the key, so IdentiKey-as-sole-resolver is the
*only* remaining lever we would hold over an otherwise self-custodial identity — precisely the
lever the exit test exists to remove. Therefore **C3+ requires N≥2 with at least one resolver
not operated by IdentiKey**, and K=2 for the consequential tier in (4).

**This makes resolver diversity part of the C2→C3 migration ceremony** (`identikey-core-zan.2`):
climbing to self-custody without relocating resolution is a half-migration that leaves us
holding the freshness lever. The ceremony must move both, or it has not moved custody.

---

## ADR-008: Pre-rotation (scoped by rung), privilege separation, one canonicalisation ✅ Decided 2026-08-01 — revised same day

**Context.** Two questions arrived together and resolve together: does IdentiKey adopt KERI-style
pre-rotation, and does it adopt KERI itself? See ADR-007 for the resolution half of the same
discussion.

**Decision 1 — pre-rotation, yes, but scoped by rung.** Every rotation commits to the *digest of
the next key set* in advance, so a compromised current key cannot rotate the identity to an
attacker's key. **Its benefit is proportional to the separation between where the current key
lives and where the successor lives**, and is therefore not uniform across the ladder:

| Where current / successor live | Guarantee |
|---|---|
| Same party, same security domain | **None.** A hash in a document, nothing more. |
| Same party, materially colder domain (offline HSM, separate KMS and access control) | Partial — defence in depth against a partial breach. |
| Different parties | Full. |

Pre-rotation is fundamentally **hot/cold separation within one controller**: KERI assumes a
controller holding a hot signing key and a colder successor. Someone must custody the successor.

**The condition is separation, not rung.** An earlier draft of this ADR mandated pre-rotation at
C3/C4 while also publishing the table above — a contradiction, because **a C3 user with a single
device is "same party, same security domain."** The successor sits in the same enclave, behind
the same unlock, exposed to the same compromise as the hot key. For that user pre-rotation is
not merely useless, it is **strictly negative**: no protection gained, and a new way to lose the
identity.

That loss mode is real and asymmetric. Losing the committed successor does not break the
identity today — the current key still signs — it removes the ability to *ever rotate again*.
The identity is frozen to one key forever, and when that key is eventually lost, aged out, or
compromised, there is nothing to move to. A slow fuse on an identifier whose entire premise is
that it is stable for life.

**Therefore pre-rotation is optional at every rung, and is enabled by a structural condition
rather than a preference:**

- **Off by default.** Including at C3 and C4.
- **On when, and only when, the successor lives in a custody domain distinct from the hot key**
  — a second device, a hardware token, an offline HSM, or guardian-held shares.
- **Never on with the successor in the same domain as the hot key**, at any rung. That
  configuration is pure downside and the software should refuse it rather than offer it.
- At C2 the question applies to whoever holds `Elect` (see Decision 3), not to the account.

It is deliberately *not* a naked user-facing toggle. The user chooses whether to establish a
separate successor custody; enabling pre-rotation follows from that, so nobody can switch on the
loss risk without having first created the thing that earns the benefit.

**The C3 synthesis: guardians should hold the successor.** At C3 a guardian quorum already
exists for key recovery. Generating the successor into guardian-held shares puts it in a
genuinely distinct security domain (earning the full guarantee) *and* makes it recoverable
(removing the loss risk). That resolves both sides of the trade at once — but it couples
pre-rotation to guardian infrastructure (`identikey-core-vt4`), and to superseding recovery
(`identikey-core-wzr`) as the escape hatch when successor material is lost anyway. **Pre-rotation
at C3 is only safe once those exist.** It cannot ship ahead of them.

**Decision 2 — one canonicalisation: dCBOR / Gordian Envelope.** We take KERI's *ideas* and
decline its *stack*. No CESR, no ACDC, no OOBI, no KERIA.

**Decision 3 — privilege separation is what makes managed custody non-rent, not pre-rotation.**
`bc-xid` models `Elect` ("add or remove other verifiers — rotate keys") and `Transfer` ("remove
the inception key") as privileges *distinct from* `Sign` and `Auth`, assignable to different
keys. At C2 we therefore split them:

- **IdentiKey's key holds `Sign` + `Auth`** — the day-to-day signing that is the managed
  convenience the user is paying for.
- **The user's key holds `Elect` + `Transfer`** — only they can rotate keys or remove the
  inception key.

Two properties follow, and they are the point of the rung:

- **A breach of IdentiKey yields `Sign`, not `Elect`.** An attacker can sign as the user *now* —
  bad, and detectable — but cannot take over the identity. No permanent theft.
- **Exit is unilateral.** The user rotates our key out without our cooperation. Not a ceremony we
  grant them; an operation they perform. This is the exit test enforced cryptographically at the
  managed rung rather than by policy.

Pre-rotation and privilege separation are **orthogonal tools for different threats**: pre-rotation
defends a single holder against theft of their hot key; privilege separation defends the user
against their custodian. Conflating them is what produced this ADR's first draft, in which
pre-rotation was claimed to carry a benefit that in fact only privilege separation provides.

**Rationale for pre-rotation.** It is the highest-value idea in KERI and among the cheapest to
implement — a hash commitment. It matters most at C3/C4, where there is no custodian to appeal
to and key compromise is otherwise terminal for the identity. It also closes an asymmetry the
ladder would otherwise carry: at C2 a compromised key can be remediated by the custodian, at C3
it could not be. Pre-rotation gives the self-custodial rungs a defence that does not require a
custodian, which is the whole point of those rungs.

**Rationale for one canonicalisation.** `identikey-auth` signs over canonical dCBOR; `bc-xid` is
Gordian-native. KERI's substrate is CESR. Running both would mean a permanent translation layer
between two canonical encodings — and canonicalisation mismatches are precisely where
signature-verification bugs live, because both sides believe they are verifying the same bytes.
Secondary but real: the Rust KERI implementations are fragmented and thinly adopted (`keri` 28k
downloads, `keri-core` 20k, `keriox` 1.5k, `keri-rs` 285 and self-described as under active
development) next to `bc-xid`'s 38k as the reference implementation of its own spec. `bc-xid` is
also licensed **BSD-2-Clause-Patent** — already ADR-003's protocol-tier licence — and Blockchain
Commons' Gordian Principles restate our exit test in their own words. We are in the right
ecosystem already.

**What KERI is still for.** An audit checklist, not a dependency. Their corner-case work on
partial rotation, superseding recovery, multi-sig thresholds, and rotation *of the witness set
itself* is the accumulated value, and we should check our derivation against it rather than
re-discover those cases as bugs.

**Consequences.**

- **Pre-rotation is adoptable at any rotation, not only at inception.** An earlier draft of this
  ADR claimed it "cannot be retrofitted"; that was wrong. Any rotation may begin committing a
  successor. What cannot be recovered is protection for rotations that already happened
  uncommitted — and starting late is safe only if the key is *not already compromised*, since a
  breached current key can commit the attacker's own successor. Committing from inception is
  meaningfully better, but it is not a one-way door.
- **The C2→C3 migration must verify the committed digest against the user's own key** when
  a successor was committed. ⚠️ ADR-008's first draft said the migration rotation is
  "authorised by our key." **ADR-011 corrects that.** After ADR-010, the user holds `Elect`
  at C2; we cannot authorize a key-graph change. The remaining attack is a *client* that
  accepts a successor we suggested. The user's device still checks a published digest
  against the key it generated locally (`identikey-core-4qd`).
- If `bc-xid` does not implement pre-rotation, carry the commitment as an **extension assertion**
  on the XID document rather than forking the crate (`identikey-core-zan.5`).
- Losing the pre-committed successor is a way to lose *rotatability* while still holding a valid
  current key. Wherever pre-rotation is on, successor material must be covered by the C3 recovery
  design (`identikey-core-vt4`) exactly as the current key is.
- **The recovery path for lost successor material is also an attack path** — this is KERI's
  "superseding recovery" problem and we do not get to skip it. Deferred, but it must be solved
  before C3 ships, not after.
- Any future KERI interop is a bridge written at the edge, never a second encoding admitted to
  the core.

**Shipping decision: v1 ships without pre-rotation.** Recorded 2026-08-01.

It is not on the critical path. It is optional at every rung, its only compelling configuration
at C3 depends on guardian infrastructure that does not exist yet (`vt4`), and it is safely
adoptable at any later rotation. The one hazard of late adoption — a *compromised* current key
committing the attacker's own successor, cementing rather than evicting them — does not reach
the population that will want it, because climbing to C3 generates a fresh user-held key we
never possessed. The commitment starts on a key with no exposure history.

The gate, in place of "a hardening pass":

1. **Pre-rotation must exist before the first C3/C4 identity does** — not before v1 ships.
   Introduced at the C2→C3 migration rotation, which is generating a new key anyway.
2. **Never enabled without a distinct successor custody domain and a recovery path.** Enabling
   it into a single-device C3 would ship the strictly-negative configuration above.
3. **Leave the extension point now** (`identikey-core-29v`). The one thing that makes this
   expensive later is a rotation ceremony or event format with nowhere to carry the commitment,
   which would turn a retrofit into a format break across every identity. `bc-xid` preserves
   unrecognised assertions, so this should be nearly free — but confirm it before shipping
   rather than during the hardening pass.

**The C2 privilege split needs its own ADR.** Decision 3 states the mechanism but not its
mechanics. Settled as **ADR-010**.

---

## ADR-009: Pairwise `sub` by default, via an exportable server salt ✅ Decided 2026-08-02

**Context.** ADR-001 makes `sub` a XID: globally unique and self-certifying. That is exactly what
makes it *correlatable* — every relying party sees the same string, so any two RPs can collude to
link a user across services. That is a privacy regression against incumbent IdPs (Sign in with
Apple is pairwise by default) and an odd look for an identity product built on consent.
Retrofitting is impossible in the direction that matters: every issued token embeds a subject the
RP stores forever (`identikey-core-ccf.7`).

**Stock OIDC pairwise, and why it is sufficient.** The standard construction is
`sub = H(sector_identifier ‖ local_id ‖ salt)` with a **server-held salt**. An earlier draft of
this ADR rejected it as failing the exit test — reasoning that only the OP could compute or
prove the mapping, so a departing user could not prove to an RP that they are the person it
knows. **That was an over-read.** The salt is *data*. Export it, and a successor OP reproduces
every pseudonym exactly, so continuity at every relying party survives our disappearance. This
is a data-export obligation — one we already carry and can test — not a cryptographic-
architecture problem.

It also fits the exit test as narrowed: the test protects the *substrate*, not the feature set.
The substrate here is the XID, which the user controls at every rung regardless. A pairwise
`sub` is a **projection for legacy relying parties**, not the identity itself.

**Proportionality — the reason the elaborate version was wrong.** The OIDC surface is the
*legacy bridge*, not the high-assurance path. High-assurance operations run through
`identikey-auth` and the URN grant against the real key, and those counterparties are
capability-aware, so they are in *disclosed* mode anyway — capability chains need the real XID.
A construction that introduces a new class of critical user-held secret to protect the
low-assurance surface, while buying nothing on the surface that matters, is mis-proportioned.
Build the legacy bridge to legacy-bridge complexity.

**Decision.**

1. **Pairwise by default.** Ordinary RPs receive a per-sector pseudonym. The bare XID is
   disclosed only on explicit, per-RP user consent.
2. **A server-held salt, which is exportable.** `sub_rp = KDF(salt, XID, sector_identifier)`,
   computed by the OP. The salt is per-deployment secret material, **never published and never
   placed in the XID document** — a root in the document would be served publicly by every
   resolver, letting anyone compute every user's pseudonym at every sector, which is strictly
   worse than using the bare XID and irreversible the moment it happens. Its exit-test
   obligation is discharged by **export**, not by user custody: the salt (or the derived
   `sector → sub` map) is part of the user's data export.
3. **Sector identifiers per OIDC**, including `sector_identifier_uri`, so an organisation's
   several RPs can share one pseudonym deliberately.
4. **Two disclosure modes, chosen by the user, both legitimate.** This is the same shape as the
   custody ladder — a spectrum the user positions themselves on, not a setting we pick for them:

   | Mode | RP sees | RP can resolve the XID document? | Trust model |
   |---|---|---|---|
   | **Pairwise** (default) | per-sector pseudonym | **No** | ordinary OIDC — the RP trusts our token |
   | **Disclosed** (opt-in) | the bare XID | Yes | self-certifying — the RP verifies without us |

   This resolves the interaction ADR-007 flagged: a pairwise RP *cannot* resolve the XID
   document, and that is correct rather than a gap. Legacy RPs live in the ordinary OIDC trust
   model, which is what they already expect. Capability-aware RPs across the sovereign stack
   (recrypt, mjolnir, Papyrus) use disclosed mode and get the full self-certifying benefit.
5. **No first-issuance binding table, and no asserted pseudonyms.** Because the OP computes
   `sub_rp` deterministically at every rung, a user can never present someone else's pseudonym.
   The impersonation class an earlier draft had to defend against does not arise.

**Rationale — privacy is the goal, not a side effect.** Be precise about the mechanism: pairwise
prevents no *attack*. Not account takeover, not impersonation, not token forgery, not key
compromise. What it prevents is **correlation** — two relying parties, or two breach dumps,
joining their user tables to establish that user X at A is user Y at B.

Earlier drafts let that sit inside a security-shaped argument, which was wrong twice over: it
misdescribed the mechanism, and it implied that being "only" a privacy control was a demotion.
**For this product it is the point.** IdentiKey is an identity system built on consent, and an
identity system that hands every relying party a global, permanent, cross-service correlation
key has conceded the thing it exists to protect — regardless of how good its key custody is.
Making identities less correlatable, at genuinely small cost, is worth doing on its own terms.
That is the primary rationale. The arguments below are supporting, not load-bearing.

**Rationale — asymmetric reversibility, with the claim corrected.** Pairwise → disclosed is
always available later: an additional claim the user consents to per RP. Disclosed → pairwise
cannot un-correlate what an RP has already stored and may already have shared.

⚠️ But an earlier draft called that a one-way door closing at *first token issuance*, and
inherited the same framing from `ccf.7`. **That is overstated.** The door closes **per relying
party, as each one onboards** — ship a bare XID and add pairwise later, and only the RPs already
onboarded keep the global identifier. The blast radius is "RPs onboarded before the switch," not
"everyone forever." Worth recording precisely, because the corrected version is a materially
weaker argument than the one originally used to justify this decision.

**Why day one rather than deferred.** With the reversibility argument corrected, deferral was
genuinely arguable — and was recommended and rejected. The decision rests on the privacy
rationale above plus two practical points:

- **Building it now means never needing the switch.** No migration, no window during which some
  RPs hold a global identifier and others do not, and no judgement call about which RP counts as
  "third-party enough" to trigger it.
- **The cost is small in absolute terms**, which is what makes the values argument decisive
  rather than merely nice. The salt rides on secret-material infrastructure epic 7 already
  requires for JWT signing keys, and the revised construction adds **no per-rung code** — the OP
  computes the pseudonym identically at every rung, because it mints the token at every rung.

A control that is cheap and aligned with the product's purpose does not need to clear the bar of
"strictly necessary."

**Consequences.**

- **The salt is operational secret material, on the same footing as signing keys** — backed up,
  rotated only with a migration plan, and never logged. Losing it costs every user's continuity
  at every relying party simultaneously. But it is *ours* to protect, not a new burden placed on
  the user, and it does not enter the recovery design (`identikey-core-vt4`), which stays scoped
  to key material.
- **Rotating the salt breaks every pairwise `sub`.** It is therefore effectively permanent, and
  must be generated per-deployment at install rather than shipped as a default or derived from
  anything guessable.
- **Export is the exit-test obligation and must be tested as one.** A user's export includes
  enough to reproduce their pseudonyms at a successor OP. Untested export is the failure mode
  here, not cryptography.
- **The derivation must be pinned before the first token.** A pseudonym computed differently
  later silently breaks every RP account a user already has.
- Pairwise `sub` values must never be used as internal keys. The XID remains the canonical
  internal identity; the pseudonym is a projection at the token boundary only.
- **The OP can correlate its own users across sectors.** Accepted: it already can, since it
  authenticates them. Pairwise defends against *RP-to-RP* collusion, which is the threat that
  exists on this surface.

**If the OP should ever be unable to correlate, the answer is a VRF** — `sub_rp = VRF_sk(sector)`
with a proof verifiable against a key in the XID document: unlinkable across sectors, computable
only by the holder, and verifiable by the OP without holding the secret. Named so it is not
re-derived later. Out of scope here, because defending the user against *us* on the legacy OIDC
surface is not this ADR's threat model — that is what the URN grant and disclosed mode are for.

**Actions this decision commits us to:**

1. **Compute `sub` behind a single seam** — one function, never inlined at token construction —
   so the pairwise/disclosed choice is one decision point rather than scattered across every
   flow that mints a token.
2. **`subject_type` on client registration**, and `subject_types_supported` in discovery, per
   OIDC. Both `public` and `pairwise` are supported from v1; `pairwise` is the default for new
   clients and `public` requires the user's per-RP consent.
3. **Salt lifecycle**: generated per deployment at install, never shipped as a default or derived
   from anything guessable, stored with the JWT signing keys, never logged, and included in user
   data export. Rotation breaks every pairwise `sub` and is therefore not a supported operation.
4. **Test the export path**, since export — not cryptography — is the failure mode that would
   make this fail the exit test.

**Open.** The exact KDF. Whether disclosed mode is per-RP only, or also available as a standing
"always disclose to capability-aware RPs" preference.

---

## ADR-010: C2 is the privilege split, and it is C1 until the user holds Elect ✅ Decided 2026-08-16

**Context.** ADR-008 Decision 3 assigned `Elect` + `Transfer` to a user-held key and `Sign` +
`Auth` to IdentiKey. That is the mechanism that makes managed custody non-rent. Three mechanics
were left open (`identikey-core-av9`): how `Elect` is provisioned at signup for someone with no
device yet; what happens when they lose it; and whether a user with no key custody at all is
simply C1.

A fourth fact, discovered against `bc-xid` 0.23 rather than inferred: **the crate does not
enforce `Elect` on mutation.** `add_key` / `remove_key` are in-memory edits. The only
first-party verification mode is `XIDVerifySignature::Inception` — whoever holds the inception
*private* key can publish any successor document, regardless of the privileges written on it.
If IdentiKey keeps the inception private key, the split is a promise.

**Decision.**

1. **No user-held `Elect` + `Transfer` ⇒ the identity is C1.** C2 *is* the split. A user who
   has not yet generated a key we cannot use is a C1 customer, and we will say so. We do not
   mint a C2 document that lists privileges the user cannot exercise.

2. **Two constructions, one invariant.**
   - **C2-native.** The user's `Elect` key *is* the inception key. IdentiKey's key is a
     separate operational key holding only `Sign` + `Auth`. We never possessed inception
     private, so we cannot `Inception`-sign a rewrite.
   - **C1 → C2 promotion.** Signup without a device starts C1: our key is inception and holds
     `All`. Promotion is a single inception-signed update that adds the user's `Elect` +
     `Transfer` key (and `Verify` + `Update`, so they can change the document and the resolver
     set), adds a *new* operational key for us with `Sign` + `Auth`, **Transfers the inception
     key out of the document**, and **forgets the inception private key**. After that, the only
     authorized key-graph change is a signature from a key that holds `Elect` in the *previous*
     document. `XIDVerifySignature::Inception` is the wrong verifier at C2.

3. **Lost `Elect` does not collapse to C1 and is not A1-recoverable.** We still cannot rotate
   or take over the identity — that is the point of the split. The user also cannot exit or
   rotate until they recover `Elect`. Email/SMS/social restore *account access* (A1), never
   the `Elect` key (I2). Restoring rotatability is guardian / superseding-recovery work
   (`identikey-core-vt4`, `identikey-core-wzr`), not a support action. Holding a second `Elect`
   key (or wrapping the first to every passkey) is how a user avoids the trap; it is not
   required to *be* C2.

**Rationale.** The alternative — "C2 from the first click, we hold `Elect` until they have a
device" — is C1 with a nicer name. The alternative — "A1 restores `Elect`" — is the I2 collapse.
The alternative — "keep inception private so we can still sign document updates" — makes every
privilege in the document decorative, because inception-verify will accept a document we forged
that puts `All` back on our key.

`Verify` and `Update` travel with the user at C2 even though ADR-008 named only `Elect` +
`Transfer`. Without them the user cannot change the document or the resolver set, and C2 → C3
(ADR-007: relocation of resolution) becomes a thing we do *to* them.

**Consequences.**

- Signup is C1 until the C1 → C2 ceremony completes. The product must not advertise C2 before
  that.
- After promotion we must not persist inception private. A backup that still has it is a C1
  backup of a C2 customer — treat that as a breach-class incident, not an operational
  convenience.
- Resolvers and our own apply-path must authorize key-graph changes via `Elect` on the previous
  document, not via inception-verify. That function lives in `identikey-keys` (`authorize_elect`).
- `bc-xid` remaining the document format is unchanged. We are not forking it to add
  `XIDVerifySignature::Elect`; we wrap it.
- C2 → C3 (`identikey-core-zan.2`) starts from a document that already has the split, and must
  also move resolution (ADR-007). It does not have to invent the privilege model.

**Actions this decision commits us to:**

1. Construct C2 documents that encode the split, and refuse to call a document C2 if any key
   holds `All` or if IdentiKey's key holds `Elect`.
2. `authorize_elect` rejects our `Sign` key. A test covers the reject path.
3. Promotion Transfers inception and takes inception private by value so the happy path cannot
   keep it by accident.

---

## ADR-011: C2→C3 hands over the document, not our key ✅ Decided 2026-08-16

**Context.** Invariant I3 requires a self-service exit: same `sub`, stop paying, no permission.
`identikey-core-zan.2` originally said "the managed key is handed to the user, the server's copy
is destroyed." ADR-007 added that resolution must move too — N≥2 at C3+, at least one resolver
not operated by us — or we keep the freshness lever and the climb is a half-migration.

ADR-010 then changed the authorisation story. At C2 the user holds `Elect` + `Transfer`; we
hold `Sign` + `Auth`. `authorize_elect` rejects our Sign key. The 4qd / ADR-008 line that
"the migration rotation is authorised by our key" is therefore false, and exporting our Sign
private to the user would hand them a key that has been in our custody — a contaminated C3.

**Decision.**

1. **We do not export `managed_key_blob`.** The user signs at C3 with a key they generated
   locally, which we have never held. I3 is identity + data + connectivity, not "leave with
   the operational key we used to sign for you." Exporting our Sign private is a contaminated
   C3 — the withdrawn zan.2 sentence.

2. **`migrate_c2_to_c3` is the only climb path.** It is one transaction and one `UPDATE`
   that writes the new document, sets `managed_key_blob` NULL, and sets `rung = c3`
   (Postgres CHECKs are per-statement). It also writes `custody_events` and `consent_log`.
   **`apply_document_update` is not a climb path.** It MUST refuse a new document that is
   not valid for the stored rung (a C2 row's new document must still satisfy `is_c2`).
   Privilege-shape change that drops our Sign key only goes through `migrate_c2_to_c3`.
   Today's public `apply_document_update` can already persist a C3-shaped document and
   leave the blob — that is a defect the implementation node closes, not an acceptable
   interim.

3. **The user authorizes with Elect *private*, not Elect public.** `authorize_elect` as
   written matches public keys. The XID document is public, so naming the Elect public
   key is not authorization. `migrate_c2_to_c3` verifies a signature over the new document
   bytes by a key that holds `Elect` on the *stored* previous document. This retires
   ADR-008's "authorised by our key."

4. **Stored state must already be C2.** Fail closed unless `rung = c2` and `is_c2(stored)`.
   C1 `All` would pass a naive Elect check because `All` implies Elect — that is our key,
   not an exit.

5. **The C3 document (acceptance, not a new `is_c3` predicate).**
   - Same XID as the C2 row (I1).
   - **Keys we hold:** every Sign+Auth key on the stored C2 document (there is no
     operational-public column; the blob is opaque). None of those publics may retain
     Sign, Elect, All, Transfer, Verify, Update, Delegate, Burn, or Revoke on the new
     document.
   - **User capability:** some key we do not hold can Sign, and some key we do not hold
     can Elect (same key or a hot/cold split — ADR-008's good C3). Some user key keeps
     `Update` so later resolver relocation is possible. Do **not** require Sign and Elect
     on one key; do **not** infer C3 vs C4 from privileges. The rung column is the rung.
   - **Resolution:** N≥2 *distinct hosts*. At least one host's eTLD+1 is outside the
     operator-host allowlist (`identikey.me`, `identikey.io` — all subdomains). Hostless
     URIs (`btcr:…`) do not count as "not us." Do not CNAME-follow. Refuse localhost /
     RFC1918. We cannot prove a third-party URI is honest; we only refuse to be the
     entire set.
   - **Provenance:** if C2 had no mark, C3 must start one. The **client** creates the
     genesis mark and holds the generator. The server refuses a C3 document with no mark
     when C2 had none, and refuses a submitted document that carries generator material
     (plaintext or encrypted). We must not hold a generator that would win every future
     threshold read.

6. **`successor_digest`, when present.** v1 does not turn pre-rotation on (ADR-008). If
   the column is set, the user's device checks it against the key it generated before
   submit (`identikey-core-4qd`). The server stores the public document; it does not
   re-derive the digest.

7. **Consent.** `action = c2_to_c3`. `result = signed` means "authorized instruction
   completed," not "we produced a signature." Proof is A3 or A4 only (not A0/A1/A2).
   Insert consent first, then the event with `consent_id`.

8. **Resolver relocation is this ceremony, the first time.** Later relocation is an
   Elect-gated document write that does **not** change privilege shape, blob, or rung
   (`identikey-core-cmd`).

9. **C3→C2 is not this ceremony.** I4, later, fail closed if invoked here.

**Rationale.** Handing them our Sign key would make C3 "self-custody of a key we used to
hold." Generating a fresh user Sign key and dropping ours makes C3 a key we have never
been able to use. Relocating resolution at the same moment is what makes the climb satisfy
the exit test rather than a change of who can *sign* while we still decide what the world
believes is current. A general document-write that can drop our Sign without destroying
the blob would make the ceremony optional — so that write is refused.

**Consequences.**

- The original zan.2 sentence "managed key handed to the user" is withdrawn. Destroy, do
  not export.
- A C3 identity may still have an account row here (OIDC convenience, recovery
  subscription). That is not custody. `managed_key_blob` is the custody bit. "Stop paying"
  here means stop paying for custody, not account deletion (salt / consent export is
  ADR-009 / I3 data, a different path).
- Our convenience resolver (`identikey-core-998`) may remain one of the N. It must not be
  the only one.
- Implementation (`nod-c2-c3-exit`) closes the `apply_document_update` hole and adds
  `migrate_c2_to_c3` using the private `apply_document_update_tx` hook (or equivalent)
  inside one transaction. This ADR does not write those functions.
- Do not add an `is_c3` that means "one key has Sign+Elect." That rejects ADR-008's
  hot/cold C3, cannot tell C3 from C4, and fights `is_c2`.

**Actions this decision commits us to:**

1. Implement `migrate_c2_to_c3` and close `apply_document_update` against privilege-shape
   escape, in the implementation node — not here.
2. Fail closed on the cases in design.md (not-C2, XID change, our key as signer, no Elect
   signature, our publics still privileged, user cannot Sign or Elect or Update, resolution
   only-ours / hostless-as-not-us, missing provenance / generator present, A0/A1/A2 proof).
3. Record the climb on `consent_log` as above.

---

## Open questions

1. **Pre-rotation.** ~~Open~~ — decided as **ADR-008** (adopt). Whether `bc-xid` implements it
   natively is an implementation question, not an open decision (`identikey-core-zan.5`).
2. **XID document resolution.** ~~Open~~ — decided as **ADR-007**.
3. **Pairwise subject identifiers.** ~~Open~~ — decided as **ADR-009**.
4. **Stewardship structure** — `licensing-and-commons.md` §5 (a)/(b)/(c)/(d). Currently
   materially (b).
5. **C2 consent-record format.** ~~Open~~ — settled at the schema layer 2026-08-16
   (`identikey-core-zan.1`).
   - **Signed/proved by** the *access* credential that authorised the action: a WebAuthn
     assertion at A3, or an `identikey-auth` Response at A4. Not by the managed Sign key —
     a log of our own signatures would make C2 self-certifying theatre.
   - **Stored in** `consent_log` (Postgres): append-only, hash-chained per account. UPDATE
     and DELETE are refused. The hash is computed in-process (`identikey_keys::consent`)
     so the encoding cannot drift from a SQL expression.
   - **Shown from** the row: when, what action, for whom, which credential, outcome. The
     account UI (`ccf.11`) renders it; the table is already shaped for that.
   - We take the hash-chain *pattern* from `identikey-storage-auth` and do **not** depend
     on that crate (AGPL + recrypt; LEARNINGS 2026-07-28). The full capability-envelope
     wire format is still available later if a grant needs to leave the server; the C2
     audit log does not need it.
6. **Is WebCrypto non-extractable a distinct rung (C2.5)?** Stronger than C2, weaker than C3;
   device loss unrecoverable. Deferred.
7. **Does the OP advertise custody rung to relying parties** via `acr`/`amr`? Useful for
   RPs wanting to require C3+, but leaks user posture to every RP. Default: no.
