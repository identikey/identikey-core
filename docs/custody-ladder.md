# The Custody Ladder

**Status:** Canonical. This is the reference definition of IdentiKey's rungs.
**Date:** 2026-07-28
**Prior art:** `~/work/Mirror/sovereign-stack/concepts.md` §1 (the 2026-07-12 resolution),
where this was first written down as prose. This document is the normative version.

---

## Why this document exists

The custody spectrum has been described in conversation, in the Mirror concepts genealogy,
and implicitly in the code — but never as a single normative reference. Without one, the
server-vs-keyset oscillation that concepts.md documents across six years (server → sovereign
keyset → server → contested) keeps recurring, because each conversation re-derives the model
from scratch.

It also fixes a conflation that has caused real confusion: **custody and access are two
different axes.** "Passkey" is not a rung. "Self-custody" is not a login method. Treating
them as one ladder is what makes the passkey story feel fragmented — you are trying to sort
one list by two keys.

---

## The two axes

### Custody — *who can produce a signature with your key?*

| Rung | Name | Who can sign | Recovery | Notes |
|---|---|---|---|---|
| **C0** | Throwaway | You, until you lose it | None — by design | Ephemeral / semi-anonymous. A legitimate destination, not a failure. |
| **C1** | Custodial | IdentiKey, unilaterally | IdentiKey restores | Traditional account. Honest name for what most "web3 login" products actually are. |
| **C2** | Managed | IdentiKey, but only on your authenticated instruction, with a signed consent record | IdentiKey restores | The hosted product's default. Server-signs-for-you. |
| **C3** | Self-custody, assisted recovery | Only you | Guardian quorum (Shamir / MPC ceremony) | The recommended destination. "Recovery subscription." |
| **C4** | Self-custody, sole | Only you | None | Be your own bank. Deliberately available, never the default. |

The nudge runs **upward**: C1 → C2 → C3. C3 is the target, not C4 — the assisted-recovery
rung is what makes self-custody survivable for people who are not cryptographers.

**The line between C1 and C2 is the product's integrity.** C1 means we can sign without you.
C2 means we cannot sign without an authenticated instruction that we log and you can audit.
Everything about consent, revocability, and the "miniature authority" framing lives on that line.

### Access — *how do you authenticate in order to reach the key?*

| Level | Mechanism | Available at custody rungs |
|---|---|---|
| **A0** | Password | C1, C2 |
| **A1** | Email magic link / SMS OTP | C1, C2 — **account** recovery only, never **key** recovery |
| **A2** | Social bootstrap (Apple / Google) | C1, C2 — identity verification at signup, not ongoing auth |
| **A3** | Passkey / WebAuthn | C1, C2, and C3/C4 locally (unlocking a local key) |
| **A4** | Enclave-held key, challenge/response (`identikey-auth`) | C2–C4 — the native mechanism |
| **A5** | Offline / air-gapped signer | C4 |

Access mechanisms are **plural and freely chosen**. A user may have three of them at once.
This is not fragmentation — it is redundancy, and redundancy is the point.

---

## The grid

```
                      A0        A1        A2        A3        A4        A5
                    passwd    email    social    passkey   enclave   airgap
  C4  sole            ·         ·         ·         ○         ●         ●
  C3  assisted        ·         ·         ·         ●         ●         ○
  C2  managed         ○         ○         ○         ●         ●         ·
  C1  custodial       ●         ●         ●         ●         ○         ·
  C0  throwaway       ·         ·         ·         ○         ●         ·

  ● primary   ○ supported   · not applicable
```

The hosted OP (this repo) serves the **C1–C2 rows**. `identikey-auth` serves the **A4 column**.
The native app is what makes **C3 reachable by ordinary people**, because it is the thing that
can hold a key in an enclave and participate in a guardian ceremony.

---

## The invariants

These are non-negotiable and every design decision is checked against them.

### I1. `sub` is the key fingerprint, at every rung

The subject of every token, capability, and record is the Ed25519 public-key fingerprint.
It does not change when a user moves up the ladder. Moving from C2 to C3 is a **change of
custody, not a change of identity** — same key, different holder. If climbing the ladder
required a new identifier, nobody would climb it.

### I2. Access recovery and key recovery are different systems

- **Account recovery** (A1: email, SMS, social re-verification) restores *access to a managed
  account*. Fine at C1/C2.
- **Key recovery** (guardian quorum, Shamir, MPC) restores *the key itself*. Required at C3.

**These must never merge.** If an email link can reach a key, the email provider is the real
root of trust and the whole ladder silently collapses to C1. Any change that lets an A1
mechanism recover a C3 key is a release blocker.

### I3. Every rung passes the exit test

> Can a user leave with identity, data, and connectivity intact, and stop paying, without
> permission?

At C2 this means an explicit, documented, self-service **custody migration ceremony**: the
managed key is handed to the user, the server's copy is destroyed, and the account continues
to work at C3 with the *same* `sub`. If that ceremony does not exist, C2 is rent, not a service.

**Build the C2 → C3 migration before, or at the same time as, C2 itself.** A managed-custody
product without an exit is the exact thing this project exists to oppose, and it is much
harder to add later than to design in.

### I4. Downward moves are allowed and must be explicit

A user may move down (C3 → C2) — losing a device and choosing convenience is legitimate. It
must require the same deliberate, informed ceremony as moving up. Never silent, never a
side effect of a support interaction.

---

## How the pieces map

| Component | Serves |
|---|---|
| `identikey-auth` (protocol crate) | A4 across C2–C4. Challenge/response, enclave backends, cipher-agile. |
| `identikey-oidc` (this repo) | Projects C1/C2 identity to legacy relying parties over OIDC. |
| `identikey-keys` (this repo) | C2 custody: managed keys, consent records, and the C2 → C3 migration. |
| `identikey-recovery` (this repo) | C3: guardian quorum, Shamir, MPC ceremony. |
| Native app | Makes C3 reachable: enclave custody + passkey provider + guardian participation. |
| `urn:identikey:params:oauth:grant-type:challenge-response` | The bridge — lets an A4 signature at **any** custody rung obtain OIDC tokens for legacy RPs. |

That last row is the load-bearing one. It means a C4 sole-custody user gets first-class access
to ordinary OAuth relying parties **without the OP ever holding a key**. One protocol, five
custody rungs, one token format at the edge. This is the thing Keycloak structurally cannot do.

---

## Open questions

1. **C2 consent-record format.** Signed by what, stored where, presented to the user how?
   Probably a capability envelope, reusing the `identikey-storage-auth` chain machinery.
2. **Is C2 with a WebCrypto non-extractable key a distinct rung?** concepts.md floats it.
   It is stronger than C2 (server genuinely cannot extract) but weaker than C3 (device loss
   is unrecoverable). Possibly C2.5. Deferred until the device-loss story is solved.
3. **Guardian selection UX at C3** — the hardest unsolved problem on the ladder, and the one
   that determines whether anyone actually reaches it.
4. **Does the OP advertise the user's custody rung to relying parties?** An `acr`/`amr` claim
   could let an RP require C3+. Useful, but leaks user posture to every RP. Default: no.
