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
| **A3** | Passkey / WebAuthn — authentication **to a remote party** | C1, C2 |
| **A4** | Enclave-backed key, challenge/response (`identikey-auth`) | C2–C4 — the native mechanism |
| **A5** | Offline / air-gapped signer | C4 |

Access mechanisms are **plural and freely chosen**. A user may have three of them at once.
This is not fragmentation — it is redundancy, and redundancy is the point.

### Local user verification is not an access level

A3 previously read "C1, C2, **and C3/C4 locally (unlocking a local key)**." That conflated two
mechanisms with different trust models, and the correction matters:

- **WebAuthn authenticates you to a remote party.** It is a network protocol with a DNS-bound
  RP ID. That is its job at C1/C2 — proving to the custodian that you authorise use of the key
  it holds for you. At C2 the assertion is also the *consent artifact* that makes the rung
  distinguishable from C1.
- **Local user verification gates access to a key you already hold.** At C3/C4 there is no
  remote party in the loop, so there is nothing to authenticate *to*. On a native app this is
  the platform biometric API over a keychain or enclave item — **not WebAuthn**, and it needs
  none of WebAuthn's RP-ID machinery.

If you hold the key on your device, you simply use the key. The one genuine case for WebAuthn at
C3/C4 is a **browser** context, where the WebAuthn `prf` extension can derive a wrapping key to
decrypt a locally-stored key. Even there the passkey is a key-wrapping mechanism, not a proof of
identity to anyone.

**A4 is enclave-backed, not statically enclave-held.** Label custody **per key half**,
in three states (`identikey-core-zan.7`; Apple CryptoKit, verified):

- **enclave-held** — private material never leaves the Secure Enclave. Classical:
  NIST P-256 only (not an `identikey-auth` algorithm). PQ: `SecureEnclave.MLDSA87`
  from OS 26.0. `identikey-auth` does not hold ML-DSA in the enclave yet (`ikp-zyq`).
- **enclave-wrapped** — the enclave holds a wrapping key; the seed is unwrapped into
  app memory on every signature. This is the Ed25519 half we actually use.
- **mixed** — one half held, one half wrapped. A hybrid Ed25519 + ML-DSA key is mixed
  only when the OS is 26.0+ *and* `ikp-zyq` has landed; otherwise both halves are
  wrapped (or the PQ half is software).

Do not assert that A4 is enclave-held. When a client exists, the source of truth is a
runtime probe (`SecureEnclave.isAvailable` plus an OS-version floor). That probe lives
in the native client, not in `identikey-server` — this repo has no Apple client.

---

## The grid

```
                      A0        A1        A2        A3        A4        A5
                    passwd    email    social    passkey   enclave   airgap
  C4  sole            ·         ·         ·         ○         ●         ●
  C3  assisted        ·         ·         ·         ○         ●         ○
  C2  managed         ○         ○         ○         ●         ●         ·
  C1  custodial       ●         ●         ●         ●         ○         ·
  C0  throwaway       ·         ·         ·         ○         ●         ·

  ● primary   ○ supported   · not applicable
```

**A3 at C3 was ● and is now ○**, following the correction above. WebAuthn is not the primary
access mechanism at C3 — at C3 you hold the key, so you reach it by local user verification and
sign with it directly. A3 remains *supported* there only for the browser `prf` unwrapping case.
**Local user verification deliberately has no column**: it is not a way of authenticating to a
remote party, so it is not an access level. It is the gate in front of a key you already hold.

The hosted OP (this repo) serves the **C1–C2 rows**. `identikey-auth` serves the **A4 column**.
The native app is what makes **C3 reachable by ordinary people**, because it is the thing that
can back a key with the enclave (held or wrapped) and participate in a guardian ceremony.

---

## The invariants

These are non-negotiable and every design decision is checked against them.

### I1. `sub` is a XID — stable across both custody *and* key changes

The subject of every token, capability, and record is a **XID**: the SHA-256 of the CBOR
encoding of the user's inception public signing key (see `ARCHITECTURE.md` ADR-001).

It survives two different kinds of change:

- **Custody change.** Moving C2 → C3 is a change of *holder*, not of identity. Same subject,
  different party holding the key. If climbing the ladder required a new identifier, nobody
  would climb it.
- **Key change.** Operational keys rotate underneath the XID — for device loss, compromise,
  or the post-quantum migration that `identikey-auth`'s hybrid support makes inevitable.
  Rotation is a signed event, not an identity break.

The earlier formulation used the current key's fingerprint directly. That got custody right
and key rotation catastrophically wrong: it would have put a scheduled expiry on every
identity in the system, on the day PQ migration landed.

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
server's Sign material is destroyed (not exported), the user signs with a key we have never
held, resolution moves to N≥2 with one resolver that is not us, and the account continues
at C3 with the *same* `sub`. See `docs/ARCHITECTURE.md` ADR-011. If that ceremony does not
exist, C2 is rent, not a service.

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

1. **C2 consent-record format.** ~~Open~~ — settled at the schema layer 2026-08-16
   (`identikey-core-zan.1`). Proved by the access credential (A3 assertion or A4
   Response), stored in append-only hash-chained `consent_log`, shown from the row.
   See `docs/ARCHITECTURE.md` open question 5. We do not import
   `identikey-storage-auth`.
2. **Is C2 with a WebCrypto non-extractable key a distinct rung?** concepts.md floats it.
   It is stronger than C2 (server genuinely cannot extract) but weaker than C3 (device loss
   is unrecoverable). Possibly C2.5. Deferred until the device-loss story is solved.
3. **Guardian selection UX at C3** — the hardest unsolved problem on the ladder, and the one
   that determines whether anyone actually reaches it.
4. **Does the OP advertise the user's custody rung to relying parties?** An `acr`/`amr` claim
   could let an RP require C3+. Useful, but leaks user posture to every RP. Default: no.
