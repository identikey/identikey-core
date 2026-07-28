# Licensing & Commons Doctrine

**Status:** Draft doctrine — needs a decision on §5 before the protocol split lands
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
| **Copyright not concentrated in one acquirable entity** | An assignment-style CLA is *precisely* the mechanism that lets a buyer stop releasing. | **Risk.** `recrypt/CLA.md` exists. See §4. |
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
| **Protocol code** — `identikey-protocol` workspace (`identikey-auth`) | Reference implementation of the specs | **Apache-2.0**, or `MIT OR Apache-2.0` (Rust convention, already in use) | Patent grant + retaliation clause. Permissive so it can be embedded anywhere, including by people who compete with us. That is the point. |
| **Products** — `identikey-core` (hosted OP), recrypt server, native app | Things worth selling | **AGPL-3.0-or-later + commercial exception** | Network copyleft protects against SaaS free-riding; the commercial exception funds the work. Burial matters less here because a product is replaceable once the protocol survives. |

**Why permissive rather than AGPL for the protocol tier:** an AGPL protocol library cannot be
embedded by the people whose adoption proves the protocol survives — including proprietary
password managers, OS vendors, and enterprises. The whole point of the protocol tier is that
it spreads beyond our control. Copyleft on a protocol library optimizes for a control we have
explicitly said we do not want.

---

## 4. The trade-off to decide consciously

**Dual-licensing requires copyright concentration.** You can only sell a commercial exception
if you own, or have been assigned, all the rights. That means a CLA with assignment — which
is the *same instrument* that lets an acquirer stop releasing.

The revenue model and the burial risk share a mechanism. This cannot be engineered away; it
can only be chosen deliberately.

Worth noting from `Mirror/roadmap.md`: of the four stated revenue lines —

1. Grants
2. Deployments + hardware
3. Paid convenience with a door (managed gateway, hosted onboarding)
4. Commercial dual-licensing

**only #4 requires copyright concentration.** Three of four are unaffected. That reframes the
question from "how do we protect the dual-license business?" to "is line #4 worth the structural
risk it introduces?"

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

## 6. Actions implied

1. **Extract the specs from recrypt and publish them independently**, versioned, under OWFa
   or CC-BY + patent non-assert. Not inside a product repo.
2. **Write test vectors for `identikey-auth`.** Highest-leverage single artifact in this
   document. A spec without test vectors gets read; a spec with test vectors gets implemented.
3. **Set `identikey-protocol` to Apache-2.0** (or keep `MIT OR Apache-2.0`) and keep it free
   of any AGPL dependency — this is why `identikey-storage-auth` (AGPL-3.0-or-later, depends
   on `recrypt-core`/`recrypt-wire`) must not move into the protocol workspace.
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
