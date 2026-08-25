# Licensing & Commons Doctrine

**Status:** §5c decided (2026-07-28). §5 (a/b/c/d) still open — needed before the protocol split lands
**Date:** 2026-07-28
**Requirement being served:** *"I'd like our system to be usable by future generations even
if IdentiKey gets bought & buried (as happened when I worked at PGP)."*

---

## 1. The PGP lesson, stated precisely

PGP Inc. → Network Associates (1997, source releases stopped) → sold off → PGP Corp (2002)
→ Symantec (2010) → Broadcom. The product was captured, repeatedly.

**And yet PGP-the-capability survived.** Not because of the company, and not because of the
license on the original code. It survived because of two things:

1. **OpenPGP became an IETF standard** (RFC 1991 → 2440 → 4880 → 9580). A written,
   implementable, patent-clear specification.
2. **An independent implementation existed** (GnuPG, 1997) — written from the spec, by
   people with no relationship to the company.

The books mattered too — publishing the source as printed text to route around export
controls put it beyond any single owner's reach — but the durable mechanism was
**spec + independent implementation**.

**The lesson is not "pick the right license."** It is:

> The spec is the asset. Code is a hostage; a specification is not.

Everything below follows from that.

---

## 2. What actually resists burial

Ranked by how much they matter, most first:

| Mechanism | Why it works | Our status |
|---|---|---|
| **A published, versioned, implementable spec** | An acquirer can stop publishing code; they cannot un-publish a spec. It's what lets a GnuPG exist. | Partial — `identikey-auth-challenge-v1.md` exists inside recrypt. Not independently published. |
| **Test vectors + a conformance suite** | Turns "implementable in principle" into "implementable on a weekend." This is the difference between a spec that gets reimplemented and one that doesn't. | **Missing.** Highest-leverage gap. |
| **An explicit patent grant** | Apache-2.0 §3 grants patent rights and terminates them for anyone who sues. MIT grants *no* patent rights at all. This is the specific instrument that stops an acquirer weaponizing a patent portfolio against reimplementers. | Partial — recrypt workspace is `MIT OR Apache-2.0`, so the Apache option is available. |
| **Copyright not concentrated in one acquirable entity** | An *assignment* CLA is precisely the mechanism that lets a buyer stop releasing. A *licensing* CLA is much weaker medicine. | **Better than assumed.** `recrypt/CLA.md` is an explicit non-assignment CLA — "You keep the copyright to your contribution." See §4. |
| **Trademark policy permitting forks to name their origin** | The most common quiet capture: the acquirer keeps the name, the fork can't say what it is. | **Missing.** |
| **More than one implementation, ideally more than one org** | Redundancy of the thing itself. | Missing, but a natural consequence of the first two rows. |
| **Foundation stewardship** | Structural, but slow and not sufficient alone. | Precedent exists — lightning-mesh is Foundation-owned under AGPL (per `Mirror/roadmap.md`). |

---

## 3. The doctrine

> **Protocols permissive. Products copyleft-plus-commercial.**

This is not a new principle — it is already written down for the connectivity layer in
`Mirror/roadmap.md`: *"protocol free, metal and labor are the product."* This document
applies the same rule to identity.

| Tier | What it is | License | Rationale |
|---|---|---|---|
| **Specs** — `identikey-auth-challenge-v1`, the URN grant, wire formats | The thing that must outlive everything | **Permissive spec license + explicit patent non-assert.** OWFa 1.0 (what OpenID Foundation uses) or CC-BY-4.0 plus a separate patent grant. | Maximum reimplementability. This is the PGP lesson applied. |
| **Protocol code** — `identikey-protocol` workspace (`identikey-auth`) | Reference implementation of the specs | **`Apache-2.0 OR BSD-2-Clause-Patent`** — decided, see §5c | Both options carry a mandatory patent grant, so the disjunction is safe. Apache for familiarity, BSD+Patent for GPLv2 reach. Embeddable anywhere, including by people who compete with us. That is the point. |
| **Products** — `identikey-core` (hosted OP), recrypt server, native app | Things worth selling | **AGPL-3.0-or-later + commercial exception** | Network copyleft protects against SaaS free-riding; the commercial exception funds the work. Burial matters less here because a product is replaceable once the protocol survives. |

**Why permissive rather than AGPL for the protocol tier:** an AGPL protocol library cannot be
embedded by the people whose adoption proves the protocol survives — including proprietary
password managers, OS vendors, and enterprises. The whole point of the protocol tier is that
it spreads beyond our control. Copyleft on a protocol library optimizes for a control we have
explicitly said we do not want.

---

## 4. The trade-off to decide consciously

**Dual-licensing requires sufficient rights in all the code.** You can only sell a commercial
exception if you hold, or have been granted, the right to relicense every contribution.

There are two ways to get that, and they differ enormously for burial resistance:

- **Assignment CLA** — contributors transfer copyright. Maximum flexibility for the steward,
  and precisely the instrument that lets an acquirer stop releasing.
- **Licensing CLA** — contributors keep copyright and grant a perpetual, irrevocable,
  non-exclusive licence including the right to include the work in commercially-licensed
  releases. The steward can dual-license; the contributor retains independent rights.

**`recrypt/CLA.md` is the second kind** — "You keep the copyright to your contribution — this
is a license, not an assignment." That is the right choice and it substantially reduces the
burial risk described in §1, because no single entity can ever become the sole rights holder.

Two residual exposures remain, and they are inherent rather than fixable:

1. The grants run to "Identikey Inc. **and its successors and assigns**" — an acquirer
   inherits the commercial licensing right. Unavoidable if the right is to be sellable at all.
2. An acquirer can stop publishing *future* work. They cannot retract past releases: every
   shipped version's AGPL/permissive grant is irrevocable, and contributors keep their own
   copyright. So the fork always starts from the last public release.

That is materially the shape of option (b) below, already in place.

Worth noting from `Mirror/roadmap.md`: of the four stated revenue lines —

1. Grants
2. Deployments + hardware
3. Paid convenience with a door (managed gateway, hosted onboarding)
4. Commercial dual-licensing

**only #4 needs the CLA at all.** Three of four are unaffected by any of this.

---

## 5. Options — needs a decision

**(a) Foundation holds copyright; Identikey Inc. holds a commercial licensing right.**
Revenue preserved, burial resistance strong (an acquirer buys the company, not the copyright).
Cost: real legal setup, and the Foundation must be genuinely independent or it's theater.

**(b) Company holds copyright, plus an irrevocable public release commitment.**
Every released version is irrevocably AGPL. An acquirer can stop *future* releases but can never
retract what shipped. Cheap. Weaker: the fork starts from the last release and loses the roadmap.

**(c) Permissive everything; monetize hosting, hardware, support, and grants only.**
Maximum commons, zero burial risk on the protocol, drops revenue line #4.

**(d) Tiered — the recommendation.**
Apply (c) to the **protocol tier** and (a) or (b) to the **product tier**. The thing that must
survive is permissively licensed and independently specified, so it cannot be buried regardless
of what happens to the company. The thing that generates revenue keeps the CLA. The acquirer
can buy and bury `identikey-core`; they cannot bury `identikey-protocol`, because the spec is
published, the test vectors exist, the patent grant is irrevocable, and anyone can implement it.

**One additional clause worth investigating for the product tier:** a reversion trigger — if
the steward ceases to publish under an open license for N consecutive days, rights revert or
auto-relicense. Unusual but not unheard of. Ask a lawyer whether it survives an acquisition;
the answer determines whether it's worth the drafting cost.

---

## 5b. Audit against the current business model (2026-07-28)

Checked the actual state rather than assuming it. **The structure works for all four revenue
lines.** Findings:

**Recrypt's per-crate split is sound.**

| Tier | Crates | Licence |
|---|---|---|
| Permissive core | `recrypt-core`, `-ffi`, `-openfhe-sys`, `-wire`, `-storage`, `-client`, `identikey-auth` | MIT OR Apache-2.0 |
| Deployable stack | `recrypt-server`, `recrypt-cli`, `identikey-storage-auth` | AGPL-3.0-or-later **or** commercial |

Permissive crates feed copyleft crates, which is the legal direction. `LICENSE`,
`LICENSE-COMMERCIAL.md` and `CLA.md` are consistent with each other and with the Cargo metadata.

**No third-party licence blocks the commercial tier.** Scanned all 660 lockfile entries against
the local registry cache (396 resolved). Nothing GPL/AGPL/SSPL/BUSL. Three near-misses, all fine:

- `self_cell` — `Apache-2.0 OR GPL-2.0-only`; take Apache-2.0.
- `r-efi` — `MIT OR Apache-2.0 OR LGPL-2.1-or-later`; take MIT.
- `option-ext` — **MPL-2.0**, transitive via `dirs`. File-level copyleft: no obligation unless
  those files are modified. Not a blocker; belongs in NOTICE.

Native deps are clean: OpenFHE BSD-2-Clause, liboqs MIT, `tss-esapi` Apache-2.0,
`fips204` MIT/Apache-2.0, `bc-envelope`/`bc-components` **BSD-2-Clause-Patent**.

**Gap 1 — `identikey-core` has no licence at all.** No LICENSE file, no `license` field in
`package.json`. Default is all-rights-reserved. This is now the repo that will hold the OIDC
provider and the hosted login UI, so it needs the product-tier licence (AGPL + commercial)
declared explicitly.

**Gap 2 — `MIT OR Apache-2.0` undercuts the patent argument.** §2 claims Apache-2.0's patent
grant as the anti-burial instrument, but a disjunctive licence lets the *licensee* choose MIT,
which has no patent grant and no retaliation clause — so a hostile actor simply takes the MIT
option and the protection never attaches. **Dropping the disjunction is the fix**; see §5c for
which single licence to drop to.

**Gap 3 — only one contributor file** (`contributors/individual.md`, a template). Today Duke
holds essentially all rights, so the dual-licence is unambiguous. The CLA starts mattering the
moment a second contributor lands; make signing it part of the contribution flow before that,
not after.

## 5c. Protocol-tier licence: Apache-2.0 vs BSD-2-Clause-Patent

**Both fix the patent problem.** The defect in `MIT OR Apache-2.0` is the *disjunction* — the
licensee elects, and a hostile actor elects MIT. Any single licence with a mandatory patent
grant closes that hole. So this is a choice between two correct answers, not a fix.

| | Apache-2.0 | BSD-2-Clause-Patent |
|---|---|---|
| Mandatory patent grant | ✅ §3 | ✅ |
| Defensive termination on patent suit | ✅ | ✅ |
| **GPLv2-compatible** | ❌ | ✅ *(designed for it)* |
| Corporate-legal familiarity | Very high | Moderate |
| Length | ~200 lines | ~20 lines |
| NOTICE + change-statement obligations | Yes (§4b, §4d) | No |
| Explicit trademark disclaimer | Yes (§6) | No |
| Inbound-contribution default clause | Yes (§5) | No |
| OSI approved | ✅ | ✅ |

**Decided 2026-07-28: `Apache-2.0 OR BSD-2-Clause-Patent` for `identikey-protocol`.**

Rationale for taking both is at the end of this section. The single-licence analysis below is
retained because it explains *why these two* and not some other pair.

The deciding factor is GPLv2. Apache-2.0's patent-termination and indemnity provisions count as
"further restrictions" under GPLv2 and make the two incompatible — the FSF and Apache both say
so plainly. BSD-2-Clause-Patent was written specifically to be *"a simple permissive licence
compatible with the GPL version 2, with an express patent grant"*, and the FSF lists it as
GPLv2-compatible.

That matters concretely here rather than theoretically: **the mesh side of this stack lives in
GPLv2 territory.** OpenWrt is GPL-2.0, and Freifunk-adjacent firmware ecosystems are largely
GPLv2. `identikey-auth` is meant to be *the* identity primitive across the whole sovereign
stack — mesh included. Licensing it Apache-2.0 would mean the identity layer legally cannot be
linked into the connectivity layer's own ecosystem. That is a self-inflicted wound, and it is
exactly the class of mistake that only shows up two years later when someone tries.

Secondary arguments, all pointing the same way:

- **Brevity is on-brand.** If the thesis is "the spec is the asset," a 20-line licence anyone
  can read beats a 200-line one nobody does.
- **No NOTICE or change-statement obligations**, so embedding in a proprietary password manager
  or an OS credential provider carries essentially zero compliance friction. Maximum spread is
  the entire point of this tier.
- **Precedent in our own dependency tree** — Blockchain Commons ship `bc-envelope` and
  `bc-components` under it, for the same reasons.

**The cost, stated honestly:** Apache-2.0 is on every corporate allowlist and
BSD-2-Clause-Patent will trigger a fresh legal review at some enterprises. Mitigate by stating
in the README that it is OSI-approved, SPDX-recognised (`BSD-2-Clause-Patent`), FSF-listed as
GPL-compatible, and permissive — that is usually enough to convert a review into a rubber stamp.

### The decision: take both

`Apache-2.0 OR BSD-2-Clause-Patent`.

**Why the disjunction is safe here and was not safe before.** The defect in
`MIT OR Apache-2.0` was never that it offered a choice — it was that the two options differed
in *how much protection they carried*, so a licensee acting against our interests would elect
the weaker one. MIT has no patent grant at all. Here, **both options carry a mandatory patent
grant with defensive termination**, so the licensee elects a compliance regime, not a level of
patent protection. There is no weaker branch to escape into. The anti-burial property holds
under either election.

**What each branch buys:**

- **Apache-2.0** — the allowlist path. Enterprises, OS vendors and password-manager vendors
  approve it without a fresh legal review. Also brings the NOTICE requirement, the
  change-statement requirement, an explicit trademark disclaimer, and the §5
  inbound-contribution default.
- **BSD-2-Clause-Patent** — the GPLv2 path, and the low-friction path. Lets the identity layer
  be linked into OpenWrt/Freifunk-class GPLv2 firmware, and lets an embedder ship with no
  NOTICE or change-statement obligations at all.

Taken together the tier reaches both the corporate world and the copyleft world, which is
precisely what "spreads beyond our control" requires. The cost is one paragraph of README
explaining it — cheaper than either exclusion.

### Implementation notes

- **Cargo metadata:** `license = "Apache-2.0 OR BSD-2-Clause-Patent"` on the workspace, inherited
  via `license.workspace = true`.
- **Files at the repo root:** `LICENSE-APACHE`, `LICENSE-BSD-PATENT`, and a short `LICENSE`
  explaining that the recipient elects either. Follow recrypt's existing `LICENSE`-as-map pattern.
- **Inbound must match outbound.** Contributions to `identikey-protocol` come in under the same
  disjunctive expression. Do not accept Apache-only or BSD-only contributions into this tier —
  a single-licensed file silently collapses the choice for the whole crate.
- **Per-file SPDX headers** (`// SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause-Patent`)
  are worth the noise here: this tier is meant to be copied, vendored and excerpted, and the
  header is what survives being pasted into someone else's tree.
- **README:** state OSI-approved, SPDX-recognised, FSF-listed GPL-compatible, mandatory patent
  grant under both. That sentence is what converts a legal review into a rubber stamp.

**Unaffected:** the product tier stays AGPL-3.0-or-later + commercial, and recrypt's existing
permissive core crates can stay `MIT OR Apache-2.0` — they are not the anti-burial artefact and
churning them buys nothing.

## 6. Actions implied

1. **Extract the specs from recrypt and publish them independently**, versioned, under OWFa
   or CC-BY + patent non-assert. Not inside a product repo.
2. **Write test vectors for `identikey-auth`.** Highest-leverage single artifact in this
   document. A spec without test vectors gets read; a spec with test vectors gets implemented.
3. **Set `identikey-protocol` to `Apache-2.0 OR BSD-2-Clause-Patent`** (§5c, decided) and keep it free
   of any AGPL dependency — this is why `identikey-storage-auth` / `recrypt-storage-auth`
   (AGPL-3.0-or-later, depends on `recrypt-core`/`recrypt-wire`) must not move into the
   protocol workspace. **Running it as a sibling process is a different question** — see
   §8.
4. **Publish a trademark policy** that explicitly permits forks to state their origin.
5. **Decide §5.** Blocks the protocol split only insofar as the license header must be right
   on the first public commit — so decide before publishing, not after.
6. **Revisit the recrypt CLA** in light of §4. Consider DCO for the protocol tier and reserve
   the CLA for the product tier.

---

## 7. A note on why this is worth the time

The exit test asks whether a *user* can leave. This document asks the same question one level
up: whether the *commons* can leave — whether the work survives its steward. They are the same
principle applied at different scales, and a project that fails the second while passing the
first has only postponed the capture.

The counter-example is already in the record: PGP passed neither, and OpenPGP passed both, and
the difference was a specification.

---

## 8. Sibling process vs. linking (why storage-auth *should* run on a box)

The 2026-07-28 learning — *"`identikey-storage-auth` is AGPL and must not share a
workspace with the protocol tier"* — is about **Cargo linking**, not about **where the
binary runs**.

`recrypt-storage-auth` (née `identikey-storage-auth`) is a library. The deployable is
`recrypt-server`, which links it. That binary is AGPL-3.0-or-later + commercial.
Putting the crate into `identikey-protocol` or `identikey-keys` would make those
workspaces AGPL. That is the entanglement we refuse.

**HTTP to a sibling process is mere aggregation.** An Edgebox image, a Mjolnir guest,
or a compose file that *runs* `recrypt-server` next to a MIT PHP dashboard does not
make the dashboard AGPL. GPL/AGPL copyleft follows derivative works and (for AGPL §13)
users of *that network service*. It does not infect a process that speaks HTTP at it.

What *does* apply when we ship the appliance:

- We (or MeAll, if they redistribute our image) must offer **source of the AGPL
  binary** to people who receive it. That is our duty, not theirs to rewrite
  `edgeboxctl`.
- Keep the recipe in `apps/` as `image: …recrypt-server…`, not a vendored crate.
- Enterprises that will not honor AGPL §13 buy `LICENSE-COMMERCIAL.md`. A household
  box does not need that carve-out.

So: **do put storage-auth on the box** — as `recrypt-server`. Do **not**
`recrypt-storage-auth = { path = … }` from `identikey-core` or
`identikey-protocol`. Consent-log in this repo copies the hash-chain *pattern*
and reimplements it (`crates/identikey-keys/src/consent.rs`) for exactly that
reason.

Port collision to remember: Mjolnir's blob door already owns `10.200.0.1:7222`
(unauthenticated CAS). `recrypt-server` defaults to 7222 too. On a Mjolnir guest
the server listens *inside* the VM and uses `blob_door_url` as backend. On
bare metal, pick one listener for the door and another for the server, or run
the server with a local `blob/b3/` backend and no door.
