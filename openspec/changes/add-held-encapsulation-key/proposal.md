# add-held-encapsulation-key

> **ACTIVE BUILD**

## Why

A recording encrypted to a live IdentiKey has to be wrapped to the X25519
public already on that account. Hosted signup generates that key and drops
the private, so nobody can open the wrap after the process exits. The
operational companion X25519 is a different key and is discarded on purpose.
This change keeps the user X25519 private, sealed, so a later process can
open a data key wrapped to the published public.

## What

- Capability `managed-custody`.
- New C2 signups seal the user X25519 encapsulation private that matches
  `c2_wrap_recipient`. The Elect/Schnorr half of that same user key is still
  not kept.
- The sealed private lives in its own column and envelope. It is not written
  into `managed_key_blob`, and it is not a Sign key.
- A new process with the managed wrap key can unwrap an
  `x25519-xchacha20poly1305` data key addressed to that public. The unwrap
  function does not take the user `PrivateKeyBase`.
- Opening or exporting the private requires an encapsulation consent
  (`identikey-encapsulation-consent-v1\n`, purpose `export` or `unwrap`).
  An account cookie names the account and does not open the seal. A
  managed-challenge consent does not either. Live hosted proof is A3,
  because Elect was not kept.
- Export is `POST /account/encapsulation/export`. Unwrap is library-only.
  The data key does not leave the process. Success writes a consent-log
  entry and a custody event.
- The owner can export the scalar before climb. Climb refuses while a
  seal exists and no export is logged, then destroys the server copy
  without returning it.
- A held C2 member is no longer an inert wrap. IdentiKey can open a PTK
  wrapped to that member, including a house keyspace. Older rows stay
  inert. `managed_key_blob` is still not a wrap target.
- Accounts created before this change keep a null seal and fail closed.
  `IDENTIKEY_MANAGED_WRAP_KEY` is not rotated.

## Impact

- Capabilities: MODIFIED `managed-custody` (durable store, C2→C3 climb,
  operational Sign+Auth). ADDED held user X25519 encapsulation private.
  MODIFIED `guild-keyspaces` (wrap-target inert rule).
- ADRs: will amend `docs/ARCHITECTURE.md` ADR-012 item 4, the live-instance
  paragraph that says signup drops the user private and no C2 row can unwrap.

## User journey & surfaces

No new UI because this change does not add a page. The owner still enrolls
a passkey on the existing signup page. An account-page export button is a
later change. Export here is `POST /account/encapsulation/export`, called
from a same-origin test, and it returns the scalar, not HTML. Unwrap has
no route and no live caller. Tests call the library. The first production
caller is `add-recrypt-proxy-vm`. The data key stays in that process.
Working: a test unwraps a data key after the creating process is gone, and
a passkey export returns the scalar. Empty: an older C2 row has no seal
and unwrap fails. Failed: a cookie, a managed-challenge consent, a proof
for a different wrap, or a revoked passkey is refused and the seal stays
closed. Off: C1 and C3 rows have no encapsulation seal.

## Out of scope

- Choosing or implementing a classical proxy-recryption scheme. The reserved
  recrypt backends (BN254, secp256k1) do not take this X25519 public. That
  is `add-classical-pre` in the recrypt repo.
- OpenFHE / lattice as a stand-in.
- Putting ciphertext in Blob Door (`add-recording-blob`).
- Deploying a recryption proxy VM (`add-recrypt-proxy-vm`).
- Treating an OIDC login, a passkey, or managed Sign+Auth as the wrap key.
- Multi-recipient X25519 wrap as a substitute for a recryption key.
- Reconstructing a private for an account that already dropped it.
- Rotating `IDENTIKEY_MANAGED_WRAP_KEY`, the signing JWK, or client secrets.
- Deploying `auth.identikey.me`.
- Keeping the user's Elect/Schnorr private.
- A purpose that nulls the seal so a hosted user can make IdentiKey forget
  the scalar. Not this change.
- An `/account` export button. A same-origin test calls export here.

## Preparation

- Upstream: chat DAG node `pin-held-encryption-key` (session
  `01a1530b-5bbf-7802-8b83-591102c833b5`). No bead. `map --current
  share-recording` was unresolved.
- Anchors: `docs/ARCHITECTURE.md` ADR-012 item 4 (wrap target is the user
  X25519; live signup drops `PrivateKeyBase`).
  `crates/identikey-server/src/main.rs` `signup` generates `PrivateKeyBase`
  and seals only `operational.seed()`.
  `crates/identikey-keys/src/managed_challenge.rs` `OperationalEd25519::generate`
  discards a different X25519 private.
  `crates/identikey-keys/src/privilege.rs` `c2_wrap_recipient`.
  `openspec/specs/managed-custody/spec.md`.
  identikey-protocol `docs/standards/identikey-keyspace-v1.md` §7
  `x25519-xchacha20poly1305`.
- Outcome: `revised` after `reviews/2026-10-21-advise.md` (`ADVISE: send-back`,
  `READER: opus-arch-review`). The held-key goal is unchanged. B1 is a
  separate encapsulation consent. B2 is library-only unwrap. B3 amends
  `guild-keyspaces` and states that IdentiKey can open a held member's PTK.
  B4 audits export and unwrap. Advise 2 (`reviews/2026-10-21-advise-2.md`,
  send-back) is reconciled: unwrap verifies the proof in the same
  transaction as the open, the consent binds the wrap digest, the
  transcript bytes and two SHA-256 vectors are pinned, revoke and climb
  share the lock, and a wrap-recipient rewrite nulls the seal. N1–N6 are
  in this contract. The campaign
  assumption that a reserved classical backend could transform this public
  stays rejected and is not decided here.
- Authority: Duke, 2026-10-21, “activate and run” on the recording intention.
  Bounds: classical cryptography, IdentiKey is the encryption key, ciphertext
  before Blob Door, recryption proxy is a Mjolnir VM that receives a
  recryption key, friends log in with IdentiKey. Non-goals: post-quantum,
  encrypting inside the door, login-as-key, Sign+Auth as wrap target, share
  without a recryption key. Blocked descendants stay unactivated. This grant
  does not choose a PRE scheme.
