# Design — held user X25519 encapsulation key

**Status:** ACTIVE BUILD. Revised after opus-arch-review send-back
`reviews/2026-10-21-advise.md`. Fresh advise still owed.
**Change:** `add-held-encapsulation-key`

## Problem

`POST /signup` builds a user `PrivateKeyBase`, passes its public into
`c2_native`, and then leaves that private to drop. `managed_key_blob`
holds only the Ed25519 operational seed. ADR-012 says the wrap target is
the user X25519 on the document, and that a row whose private is not held
cannot unwrap. That is the live behavior.

`OperationalEd25519::generate` also throws away an X25519 private. That
public is the operational key's encapsulation half. It is not
`c2_wrap_recipient`. Keeping it would encrypt to the wrong public.

## Decision 1 — Which private is kept

Keep the 32-byte scalar from `PrivateKeyBase::x25519_private_key()` whose
public equals `c2_wrap_recipient` of the document just created. Do not
seal the `PrivateKeyBase` bytes. bc-components derives the Schnorr Elect
key from those bytes.

Do not keep:

- the operational companion X25519
- the user's Elect/Schnorr private
- anything inside `managed_key_blob`

C1 has no user key. The seal is C2-only. C3 and C4 stay null, as the Sign
blob already does.

Rows written before this change have a null seal. Unwrap and export fail
closed. There is no backfill and no new key written onto an old document.

## Decision 2 — Separate envelope

New nullable column `custody_records.encapsulation_key_blob`.

Present only at C2, and still nullable there so existing rows migrate.
C0, C1, C3, and C4 must be null. Climb sets it null in the same update
that nulls `managed_key_blob`.

Envelope magic `IKEK`, version 1. Same keyring as `IKMK`
(`IDENTIKEY_MANAGED_WRAP_KEY`, current kid). Do not rotate that key.
Plaintext is the 32-byte X25519 scalar. Associated data is the distinct
tag `identikey-encapsulation-key-v1\n`, then the 32-byte XID, then the
32-byte recipient. Do not reuse `identikey-managed-key-v1\n`. The magic
bytes sit outside the AEAD, so the tag is what separates the two
envelopes under the same key. On open, the derived public must equal the
document's current `c2_wrap_recipient`. Wrong magic, truncated input,
swapped account, swapped recipient, or a public that no longer matches
fail closed. The `IKMK` opener must reject `IKEK`, and the reverse.

Zeroize the scalar after seal, after a failed open, and after the caller
finishes unwrap or export.

Signup seals this blob before `create_managed`. If seal or insert fails,
no account row is left behind. The in-memory user scalar is gone before
the handler returns.

## Decision 3 — Unwrap is not a new cipher

Unwrap implements identikey-keyspace-v1 §7 for
`x25519-xchacha20poly1305`: X25519 DH, the named Blake3 KDF, then
XChaCha20-Poly1305 over the 32-byte data key. The attacker chooses the
wrap's ephemeral. Reject a small-order ephemeral and an all-zero DH
output. An unknown `alg` is not a successful unwrap.

The library function takes the store, the keyring, the XID, the wrap
bytes, and the A3 assertion or A4 signature. It does not take a
`PrivateKeyBase`. That is the acceptance stand-in for "the creating
process has exited." In one transaction it checks the proof against the
begin row, checks expiry, purpose, and unused, takes the same
`FOR UPDATE` locks as revoke and climb, marks the row used, opens the
seal, unwraps, and writes the audit. A begun row is not enough. There is
no finished-but-unused row. This change has no live unwrap caller. Tests
call it. `add-recrypt-proxy-vm` is the first production caller. The data
key stays in-process. Begin for `unwrap` stores SHA-256 of the exact wrap
bytes, and that digest is in the transcript. A different wrap fails
before decrypt.

This is ordinary decryption by the holder. It is not proxy recryption.
No classical PRE scheme is selected. The held key is not an actor, an
admin, or a signer.

## Decision 4 — A separate consent, then export

The account cookie names the XID at begin. It does not open the seal.
The operator holds the wrap key, so this gate is policy in our code, not
a cryptographic absence of the scalar. Say that next to the ceremony.

Begin is `POST /account/encapsulation/begin` with purpose `export` or
`unwrap`. Anything else is rejected before insert. `unwrap` also takes
the wrap bytes and stores their SHA-256. The row stores a new WebAuthn
challenge and expires five minutes after `iat`. The transcript is the
byte layout in the delta, including the pinned SHA-256 vectors. It must
not use `identikey-managed-consent-v1\n`. A proof from the challenge
responder or a session-bind attempt is refused before decrypt.

Hosted finish is only `POST /account/encapsulation/export`, and it is the
whole export transaction: verify, lock, mark used, open, audit, return
the scalar. There is no second step and no hosted unwrap finish. Success
returns the 32-byte scalar, unpadded base64url, and leaves the server
copy. No HTML. Both routes send `Cache-Control: no-store` and are outside
`spa_cors` (merged after that layer, or skipped by path), so a registered
SPA origin gets no `Access-Control-Allow-Origin`. Immediately before
decrypt, export and unwrap recheck the credential row and the custody row
under the locks `revoke_device` and climb already take. There is no
account-page button in this change. A later change adds it. A same-origin
test is the caller for now.

A3 is the live path. Hosted signup does not keep Elect, so A4 cannot be
produced for these rows. A4 stays defined as a signature by the user's
Elect key over this transcript, for a test or a later wallet. The
managed Sign key is not A4. Do not "fix" the hosted path by accepting it.

Export and unwrap each write, in that same transaction, a consent-log
entry (`encapsulation_export` or `encapsulation_unwrap`) and a custody
event. The unwrap entry records the wrap digest.

An Elect rewrite that changes `c2_wrap_recipient` nulls the seal in that
write. The old scalar cannot open the new public, and we do not have the
new private. Open after that fails closed.

Climb still does not export. Export is the exit, and it has to be logged
before climb. A seal with no `encapsulation_export` entry makes climb
fail and leave the row alone.

## Why the server also holds it

C2 already means the operator holds Sign under the managed wrap key, and
the owner uses a passkey. Duke's live IdentiKey is that shape. A
download-only key would die with the browser, and the recording flow
needs the owner to mint a recryption key later. The server copy is what
a consenting owner can use. Export is how they leave with the scalar.
The recryption proxy is a different machine and is not given this blob.

## ADR note

When this lands, amend ADR-012 item 4's live-instance paragraph: new C2
signups seal the user X25519 scalar; older rows still cannot unwrap; do
not wrap to `managed_key_blob`; do not retain Elect. State the new
confidentiality fact in that paragraph and in the guild-keyspaces
requirement: with the wrap key and a valid consent, IdentiKey can open a
PTK wrapped to a held C2 member, including a house keyspace. Update the
`c2_native` doc comment ("We never had the user's private key") and the
discard comment on `OperationalEd25519::generate` so the first names
only Elect as unretained and the second still describes the operational
companion.
