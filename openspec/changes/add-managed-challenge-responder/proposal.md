# add-managed-challenge-responder

> **ACTIVE BUILD**

Bead `mjolnir-22ff.3.1` (parent `mjolnir-22ff.3`). Steer 2026-09-24.

**Rigor:** architecture

## Why

C1/C2 managed custody must answer an edge-issued identikey-auth
Challenge so a Mjolnir edge can stay custody-agnostic. Today's
`managed_key_blob` is stored at signup and never used as a Signer.
`PrivateKeyBase::new()` yields BIP-340 Schnorr, which identikey-auth
v1 cannot verify. Duke: switch the managed operational key off
secp256k1; do not add Schnorr to the protocol.

## What

- Mint IdentiKey's C2 Sign+Auth key as Ed25519 (identikey-auth v1
  software signer). Store that private in `managed_key_blob`. User
  Elect / X25519 wrap-target is unchanged.
- Narrow canonical-challenge signer: accept only identikey-auth
  Challenge bytes; return `identikey-auth::Response`. No arbitrary-byte
  signing, no blob getter.
- C2 requires a fresh A3 WebAuthn assertion or user-held A4 proof
  bound to the exact challenge digest. A long-lived account cookie
  is not enough.
- Append `signing_instruction_authorized` before key use;
  `signing_completed` / `signing_failed` after. Release the Response
  only to the initiating client.
- Pre-switch Schnorr C2 rows: remint via signup (Elect private was
  dropped; cannot rotate).

## Impact

- Capabilities: MODIFIED `managed-custody`
- ADRs: none in this repo (Mjolnir `0012-direct-edge-auth`; protocol
  stays identikey-auth v1)

## User journey & surfaces

A native `mj` (or other client) that pinned an edge XID needs a C2
user to sign the edge Challenge. Browser `/authorize` passkey login
is unchanged.

- **Working (after act)** — after a fresh passkey (or A4) consent
  bound to that Challenge, the client retrieves a v1 Response that
  verifies as the account XID's Sign+Auth key.
- **Empty** — no passkey / no C2 row → no signature.
- **Failed (today)** — blob is Schnorr and unused; production login
  is passkey → hosted JWT only.
- **Off** — C3/C4 sign locally; this endpoint is not used.

## Preparation — 2026-09-24 send-back

Outcome: revised. Authority: the banner is already ACTIVE BUILD; this note
does not activate or deactivate it. Input: Astra send-back
`reviews/2026-09-24-advise-2.md` (READER astra-arch-review). R6–R8 are now
in `design.md` Decisions 5–8 and `specs/managed-custody/spec.md`. That
send-back does not accept this later text. R9–R10 from
`reviews/2026-09-24-re-advise.md` are now in the same files. That
review does not accept this later text.

## Preparation — act

Outcome: still valid. The accepting review is
`reviews/2026-09-24-re-advise-2.md` (READER astra-arch-review). Authority is
the ACTIVE BUILD banner plus that accept. Bounds: C2 operational Sign+Auth
only. No edge verifier, no Schnorr in the protocol, no in-place migration of
old blobs, no Elect export.

## Out of scope

- identikey-core as the edge verifier or OIDC wrapper for direct auth
- Extending identikey-auth with Schnorr
- P-256 for the server blob (enclave path for user-held keys)
- Elect-key export at signup
- Wrapping to `managed_key_blob`
- Edge nonce consume + Biscuit mint — Mjolnir `add-direct-auth-endpoints`
- Migrating existing Schnorr rows in place
