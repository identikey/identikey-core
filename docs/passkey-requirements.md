# Passkey Requirements

**Status:** Draft — requirements only, no implementation commitment
**Date:** 2026-07-28
**Audience:** whoever builds the hosted OP (rung 3) and, later, the native app
**Supersedes:** ADR-007 ("Passkeys in Keycloak Credentials"), already amended in practice

---

## 0. The framing that makes the rest coherent

**Passkeys are access rungs, not roots.**

IdentiKey's root of trust is an Ed25519 key (see `identikey-auth`, custody spectrum
rungs 1–2). A passkey is a *credential that grants access to that key* for users on
the managed rungs. It is not the identity, and losing one is not losing the identity.

Three consequences that drive every requirement below:

1. **A solid recovery floor removes the need to nag.** Plural passkeys are good, but
   they are not the safety mechanism — recovery is. If recovery works, losing every
   passkey is an inconvenience, not a catastrophe, and we do not have to badger users
   into enrolling backups they don't want. **Invest in the floor, not the nagging.**
2. **Legibility beats control.** We cannot control where platform passkeys live.
   We can always tell the user where each one lives, and that closes most of the gap.
3. **The IdentiKey key must never fragment.** Passkeys are replaceable; the key is not.
   Anything that risks the key is a different severity class from anything that risks
   a passkey.

See [`custody-ladder.md`](./custody-ladder.md) for the normative rung definitions.
Passkeys are access level **A3**; they appear at several custody rungs and are never
themselves a rung.

---

## 1. Hosted OP requirements (rung 3 — build with the OP)

### R1. Passkey is the primary login method

- Registration flow offers passkey enrollment first, before any password path.
- Password is a fallback rung, never the default, and never required to exist.
- Conditional UI (`mediation: "conditional"`) on the login form so returning users
  authenticate from autofill without choosing a method.
- Discoverable credentials (resident keys) required — usernameless login is the
  target UX. The existing `authentication-options.ts` / assertion-verification work
  already supports the `challenge.userId === null` discoverable path.

### R2. Additional passkeys — offered, never pushed

**Decided 2026-07-28:** we do *not* nag users toward multiple passkeys. A working
recovery floor (R6) is the safety mechanism; enrollment plurality is a nice-to-have,
and pestering users about it is the kind of security theatre that trains people to
dismiss our warnings.

- "Add another passkey" is discoverable on the account page. That is the whole requirement.
- Offer it contextually at moments when it is genuinely useful — first login from a
  new device, or enrolling the native app — and never more than once per context.
- No recurring warnings, no interstitials, no `passkey_count < 2` badge.
- **The corollary is that R6 is load-bearing.** If recovery is weak, this decision is
  wrong. Revisit this section if the recovery floor ever degrades.

### R3. Legibility — the user always knows where each passkey lives

- Store the **AAGUID** from the registration response on every credential record.
- Resolve AAGUID → provider name + icon via the FIDO community AAGUID mapping,
  vendored and refreshed on a schedule (not fetched at request time).
- Credential list renders as *"iCloud Keychain · added Mar 3 · last used yesterday"*,
  never *"Credential #3"*.
- Capture a user-editable nickname at enrollment time, defaulted from the AAGUID name
  plus a device hint.
- Record and display `backedUp` (the BS flag) — a synced passkey and a device-bound
  passkey have very different loss characteristics and the user should see which is which.

> **Security caveat, must be respected:** AAGUID is self-asserted by the authenticator,
> and consumer platform authenticators generally return `none` attestation. AAGUID is a
> **UX hint only**. It must never gate a security decision, drive a policy branch, or be
> presented to the user as verified.

### R4. Stale-credential hygiene via the Signal API

- Call `PublicKeyCredential.signalAllAcceptedCredentials()` after login and after any
  credential deletion, so the user's provider drops entries we no longer accept.
- Call `signalUnknownCredential()` when an assertion arrives for a credential ID we
  do not recognise.
- Call `signalCurrentUserDetails()` when the username or display name changes.
- Treat all three as best-effort: unsupported in some browsers, must never affect the
  outcome of the authentication itself.

This is the second half of the "which passkey do I pick?" problem — R3 labels what
exists, R4 removes what shouldn't.

### R5. RP ID — decide once, decide early

- The RP ID is **effectively permanent**. Changing it invalidates every enrolled
  credential and forces a full re-enrolment of every user.
- IdentiKey is an OP serving many relying parties, potentially across several domains.
  Decide the RP ID **before the first production credential is written**.
- If more than one origin must share credentials, publish
  `/.well-known/webauthn` (Related Origin Requests) from day one — retrofitting it
  is not possible for already-enrolled users.
- **Action:** this decision blocks production passkey enrolment. Record it as an ADR.

### R6. Recovery — and the line that must not be crossed

Account recovery for a managed (rung 2/3) account may use:

- email magic link (epic 13-3)
- SMS OTP (epic 13-4)
- social re-verification (epic 13-5)
- a remaining enrolled passkey (always preferred — try this first)

**Hard constraint:**

> Email and SMS recovery restore *access to a managed account*. They must **never** be
> a recovery path for a rung-1 or rung-2 **key**. Key recovery goes to guardians /
> Shamir / MPC quorum (`identikey-recovery`, and the prior art in
> `~/work/IdentiKey/{guardian-key-recovery,threshold-crypto}`).

If these two paths are ever merged for convenience, the email provider silently becomes
the root of trust for the entire system and the custody ladder collapses to its bottom
rung. Any PR that lets an email link reach a self-custody or managed *key* is a
release blocker, not a review comment.

Corollary: the UI must be explicit about which is which. When a user is on rung 1 or 2,
the recovery page says what recovery can and cannot restore, in plain language.

### R7. Cross-device authorisation

- Hybrid transport (caBLE — QR + BLE proximity) is the standards-track answer to
  "log in on a device that has no passkey."
- **This is epic 13-7 ("temporary device QR flow") under a different name.** Merge them;
  do not build a bespoke QR protocol alongside a standard one that platforms already
  implement.

### R8. Data model

Carry forward from the existing `passkey_credentials` table (Postgres — ADR-007
amended), adding:

| Field | Purpose |
|---|---|
| `aaguid` | provider identification (R3) |
| `nickname` | user-editable label (R3) |
| `backed_up` | already present — surface it in the UI (R3) |
| `attestation_format` | recorded for audit; `none` expected in the common case |
| `last_used_at` | already present |
| `signal_state` | last successful Signal API call, for hygiene scheduling (R4) |

Existing replay protection (signature counter update on every assertion) is retained.
Note that most synced platform passkeys report a counter of `0` and never increment —
counter regression must be treated as a signal to investigate, not an automatic reject,
or synced-credential users will be locked out.

---

## 2. Native app requirements (deferred — capture now, build later)

The app is where the fragmentation story actually gets solved. Two roles, and the
second is the one that matters.

### R9. IdentiKey as a platform credential provider

Register as a system credential provider so IdentiKey appears in the OS passkey
picker alongside iCloud Keychain and 1Password:

- Apple: `ASCredentialProviderExtension` (passkey support)
- Android: Credential Manager provider API
- Windows: the plugin authenticator API

This is the 1Password model, and it gives the user a **primary storage location that
syncs across their devices** — which is what you actually want when you say the story
feels fragmented.

### R10. The convergence — the same app holds the root key

The app that provides passkeys is also the app that holds the IdentiKey Ed25519 key
in the hardware enclave. `identikey-auth` already ships enclave backends for all three
platforms:

- macOS Secure Enclave + Touch ID (`enclave/macos.rs`)
- Windows CNG Platform Crypto Provider + Hello (`enclave/windows.rs`)
- Linux TPM 2.0 via tpm2-tss ESAPI (`enclave/linux.rs`)

This is the strategic point of the whole app: it can **nudge the user up the custody
ladder from inside the credential picker**, at the exact moment they are thinking about
credentials. No other passkey provider can offer that, because no other provider has a
rung above passkeys to nudge toward.

### R11. Portability — the exit test, applied to passkeys

Support **CXP/CXF** (FIDO Credential Exchange Protocol / Format) for both import and
export, as a stated product commitment rather than a roadmap item.

Standards status as of mid-2026:

- CXF reached Review Draft in March 2025 (JSON format covering passkeys, passwords,
  TOTP secrets, notes).
- Apple shipped CXF-based same-device transfer in iOS/macOS 26; Android supports it
  via a Google Play Services update.
- CXP (the HPKE-encrypted *transfer* protocol) targets early 2026 for standardization.
  Until it lands, transfers are local/on-device only — cross-device and cross-platform
  exchange comes with CXP adoption.
- Authors/contributors include Apple, Google, Microsoft, 1Password, Bitwarden, Dashlane.

**Why this is not optional for us:** the exit test asks whether a user can leave with
identity, data, and connectivity intact and stop paying, without permission. A passkey
vault you cannot export from fails that test. Import-only support would make IdentiKey
a roach motel for credentials, which is precisely the shape of the thing we exist to
oppose. Ship export before, or at the same time as, import.

### R12. Sync

- Sync must be end-to-end encrypted, keyed to the user's IdentiKey key, with the
  server holding ciphertext only. `recrypt` is the natural transport.
- Self-hosted sync must be first-class, not a degraded tier.
- Sync being unavailable must degrade to local-only operation, never to lockout.

---

## 3. Open questions

1. **RP ID value** — blocks production enrolment (R5). Needs an ADR now.
2. **Do we ever gate on attestation?** Default answer is no (consumer authenticators
   return `none`). Revisit only if an enterprise buyer requires authenticator policy.
3. **Passkey → managed key binding semantics.** When a user enrols a passkey on the
   hosted OP, exactly what does it authorise — a session, or use of the managed key?
   Probably: a session, which can then request key operations under a separate,
   shorter-lived, explicitly-consented grant. Needs design before `identikey-keys` is built.
4. **Does the OP accept passkeys as an `identikey-auth` challenge/response signer?**
   That is, can a WebAuthn assertion satisfy the
   `urn:identikey:params:oauth:grant-type:challenge-response` grant, or does that grant
   strictly require a raw Ed25519/P-256 signature? Affects whether rung 3 and rung 1
   share one verification path or two.
5. **CXP export granularity** — all credentials, or per-credential? Does export include
   the IdentiKey key itself (it should, for rung-1 users, via a distinct and
   deliberately high-friction ceremony)?

---

## 4. Sources

- [FIDO Alliance — Credential Exchange Protocol spec](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html)
- [FIDO Alliance — new specifications for user choice and passkey UX](https://fidoalliance.org/fido-alliance-publishes-new-specifications-to-promote-user-choice-and-enhanced-ux-for-passkeys/)
- [Corbado — CXP & CXF explained](https://www.corbado.com/blog/credential-exchange-protocol-cxp-credential-exchange-format-cxf)
- [1Password — Portability without compromise](https://www.1password.community/blog/developer-blog/portability-without-compromise-1password-helps-author-a-new-standard-for-secure-/163208)
- [Bitwarden — Security vendors join forces to make passkeys more portable](https://bitwarden.com/blog/security-vendors-join-forces-to-make-passkeys-more-portable-for-everyone/)
