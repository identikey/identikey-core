# Design — consent-gated managed challenge responder

**Status:** Proposed. PENDING. Revised 2026-09-24 after astra-arch-review send-back.
**Change:** `add-managed-challenge-responder`
**Bead:** `mjolnir-22ff.3.1`

## Problem

`POST /signup` stores `ours.as_bytes()` from `PrivateKeyBase::new()`
(BIP-340 Schnorr + X25519). Nothing signs with it. identikey-auth v1
accepts Ed25519 and P-256 only. Independent review of this node
flagged that mismatch as a prerequisite.

## Decision 1 — Switch the operational key, not the protocol

IdentiKey's Sign+Auth key is an identikey-auth Ed25519 software
signer. That public key is what goes on the XID document with Sign+Auth.
The blob stores that private in a form the signer can load.

User Elect remains the Gordian inception key (X25519 wrap-target
unchanged; `ikp-2l8` still owns native X25519 roster algs). Do not
wrap to `managed_key_blob`.

P-256 is the user-enclave path, not the server-held blob.

Existing Schnorr C2 rows: unused for Sign; Elect private was dropped
at signup; remint rather than in-place rotate.

## Decision 2 — Narrow signer

Accept only identikey-auth v1 Challenge bytes. Challenge fields are
`v, aud, nonce, iat, exp` — algorithm is **not** a Challenge field;
it is checked on the stored operational key. Reject unless
`Challenge::from_bytes(input).to_bytes() == input` (extra canonical
map keys must not parse-and-reencode). Admission: `v=1`, nonce
≥16 and ≤64 bytes, body ≤ 8KiB, `aud` is 64-lowercase-hex,
`exp-iat` ≤ 10 minutes, skew ±2 minutes. Recheck `exp` after
consent, before decrypt. No network fetch based on challenge
contents. No general signing API, no blob export.

This delivery is **C2 only**. C1 is tracked separately.

## Decision 3 — Consent is A3/A4, not our Sign

A long-lived account/login cookie does not authorize signing. Fresh
A3 WebAuthn or user-held A4, committed to a domain-separated digest
of the exact Challenge + request id. Persist that instruction.
Show edge/service, audience, expiry, initiating client, holder-key
fingerprint at consent.

Append `signing_instruction_authorized` before key use. Then
`signing_completed` or `signing_failed` with the same request id.

## Decision 4 — Response delivery

Release the Response only to the initiating client (state +
PKCE-like verifier or holder-key proof). Managed signing needs
hosted availability. Longer-lived offline delegation is a separate
explicit, revocable ceremony and never grants Elect.

## Decision 5 — Ceremony messages (R2, R7)

`begin` records an immutable attempt: account XID, exact edge
Challenge bytes, server request id, and a PKCE verifier commitment.
A holder public is not a retrieval proof. Supplying one fails closed.

The consent transcript is one byte string, in this order, with no
separators beyond the length prefix:

1. ASCII `identikey-managed-consent-v1\n` (the domain tag is inside the hash).
2. Account XID, 32 raw bytes. Not hex and not base58.
3. Request id, 16 raw bytes.
4. Edge Challenge: uint32 big-endian length, then the exact Challenge bytes.
5. Verifier commitment: SHA-256 of the PKCE verifier as UTF-8, 32 raw bytes.
6. Consent `iat`: uint64 big-endian Unix seconds. The server chooses it.

The consent digest is SHA-256 of that string. Consent `exp` is the
earlier of the edge Challenge `exp` and `iat` plus 300 seconds.

The A4 consent Challenge is identikey-auth v1 with `v=1`, `aud` the
64-lowercase-hex of the account XID, `nonce` the 32-byte digest,
and those server `iat` and `exp`. `begin` returns those exact Challenge
bytes. Finish rebuilds them from the stored attempt and requires the
Response to verify against that byte string. A client-rebuilt Challenge
that differs fails. Substitution of account, request, commitment, or
any consent-Challenge field fails before decrypt.

Vector: XID bytes `00..1f`, request id `00..0f`, edge Challenge
`0102`, commitment 32 bytes of `0xab`, `iat` `1700000000`. The digest
is `13ef62b41aa5240b246aec4d4bbb240fe5c94bb4a423c24898e2dee6a6844e35`.

A3 binds by a server row, not by rewriting the WebAuthn challenge.
`begin` stores the library challenge beside this attempt. `finish`
accepts the assertion only when it matches that stored challenge and
that attempt. A browser that only swaps the displayed challenge does
not match.

A4 is a user signature over a separate identikey-auth v1 Challenge,
not over the edge Challenge. That consent Challenge uses `aud` = the
account XID (64-lowercase-hex) and `nonce` = the 32-byte consent
digest. The signer must be a key on the account's current XID document
that holds Elect, and must not be the managed operational public.
Caller-supplied XID, the string `A4`, or a matching algorithm are not
authority. An unrelated user-held key fails. Hosted signup drops the
user Elect private, so A4 is unavailable until a later ceremony puts
an Elect public on the document. The managed key signing this consent
Challenge fails.

`retrieve` requires the PKCE verifier from `begin`. Replacing that
commitment after consent is rejected.

## Decision 6 — Durable attempt record (R3, R6)

Replay key is (account XID, challenge digest). A second request id
for the same digest fails. The attempt row is the integrity binding:
version, request id, digest, account XID, client commitment, state,
and terminal outcome. Today's `ConsentAppend` is not that row.

States:

- `authorized` — consent accepted. Key not claimed.
- `claimed` — one finish won the compare-and-swap. Key use has started
  or its outcome is unknown.
- `completed` — Response bytes and the completion audit committed in
  the same transaction.
- `failed` — a definite pre-sign refusal. The key was not used.
- `indeterminate` — `claimed` and no durable result. Terminal.

Crash before the claim commits: the row stays `authorized`. Finish may
claim and sign once. Crash after the claim commits and before the
result transaction commits: restart marks `indeterminate`. Finish and
retrieve must not sign again. Retrieve returns unresolved, not a
signature. A definite pre-sign failure commits `failed` with no
signature and no second key use. Concurrent finish: one claim wins.
The Response is not released until `completed` commits. This does not
promise both recovery of every authorized attempt and at-most-once key
use. Unknown key use is terminal.

## Decision 7 — Custody and credential races (R4, R8)

The ordering point is a recheck immediately before decrypt. Consent's
`authorized` commit releases its locks, so this recheck is mandatory.
The lock depends on the proof. A3 locks the custody row and the
credential row together. `revoke_device` takes that same pair. A4 does
not use a credential row. It locks the custody row and the current XID
document. The document is the authority: the consenting public must
still be on it, still hold Elect, and still not be the managed
operational public. No passkey row is required for A4. No schema is
mandated.

If revocation or exit commits before that recheck, finish commits
`failed` and does not sign. If the recheck commits first, signing may
finish and the result transaction may `complete` even if revocation or
exit lands during signing. A `completed` Response stays retrievable.
The blob is then destroyed on exit. A finish that lost the race does
not sign with a key the row no longer holds.

## Decision 8 — Blob format (R5)

Versioned envelope: `v=1`, AEAD (XChaCha20-Poly1305) wrapping a
32-byte Ed25519 seed, AAD = {account XID, operational public}.
Wrapping key is host-provisioned, identified by `kid`, not the
user Elect key. Decrypt then check seed→public matches the
current Sign+Auth public before `SoftwareSigner::from_ed25519_seed`.
Legacy Schnorr `PrivateKeyBase` bytes fail closed (remint). Missing
or wrong wrap key fails closed. A malformed envelope or an AAD for a
different account fails closed. Signup generates the seed, builds
the XID public via a PublicKeysProvider adapter, persists the
envelope, drops plaintext. After process restart the load must decrypt
that persisted envelope and verify the signature against the document's
operational public, not against a signer generated only in the test.
