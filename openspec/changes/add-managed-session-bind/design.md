# Design — managed session bind

**Change:** `add-managed-session-bind`
**Bead:** `mjolnir-22ff.3.2`
**Steer:** 2026-10-19 (user)

## Decision 1 — One ceremony

Extend `/managed-challenge` begin, finish, and retrieve. Do not add a second route. Do not sign an opaque digest. One fresh A3 or A4 consent covers the Challenge and the bind. One key-use claim signs both. The completion row stores both. Retrieve returns both or neither. If the bind signature fails, the Response is not released.

## Decision 2 — Channel is consented bytes

Begin stores the channel bytes the client submits. Those bytes are what the edge handed the client beside the Challenge. Begin returns them, and the caller renders them (Decision 6). The OP signs them. The OP does not contact the edge and does not recompute `Blake3(SPKI || conn_id)` or the Iroh channel. The edge verifier already does that, and a mismatch fails there.

## Decision 3 — Caller names the operation

Begin requires operation and resource as the caller states them. Consent shows both. The OP does not keep an allowlist and does not apply Mjolnir policy. The edge may still deny the operation after the signature verifies. This is the same bind a wallet would sign, not a login-only fixed string.

## Decision 4 — Domain is the edge's bytes

The OP ports `bind_signing_bytes` from Mjolnir `696fb00` (`native/mjolnir_biscuit/src/direct_challenge.rs`). identikey-core does not depend on `mjolnir_biscuit`. The joint vector below is the pin. The text `identikey-mjolnir/v1` is the version: an edge encoding change bumps that string and this port together. A later shared home is `identikey-auth`. This change does not move the encoder.

Canonical CBOR array of seven:

1. text `identikey-mjolnir/v1`
2. text `bind`
3. the stored Challenge bytes, as a byte string
4. the session key as a ClassicalPublicKey map `{alg, key}`
5. operation as a CanonicalTuple (array of text)
6. resource as a CanonicalTuple (array of text)
7. channel as a 32-byte byte string

This ceremony signs Ed25519 only. That is a subset of the edge, which also accepts P-256. A P-256 session key is refused at begin. The map is still the edge's map: `alg` text `ed25519`, `key` the 32 raw bytes.

A CanonicalTuple component is non-empty printable ASCII `0x21..=0x7e`. Begin takes operation and resource as arrays of those components. It does not split a string on `:`. `["vms","stop"]` and `["vms:stop"]` are different tuples. Begin refuses an empty tuple, a component outside that charset, more than 8 components, or a component longer than 64 bytes. Those caps are admission limits. The edge itself has no component cap.

Channel is exactly 32 bytes. Anything else is refused before the row is stored.

Joint vector, the edge test `direct_challenge_canonical_bind_vector`: challenge bytes `challenge`, session key 32 bytes of `0x11`, operation `["vms","stop"]`, resource `["vm","A"]`, channel 32 bytes of `0x22`. The signing bytes are hex

```text
87746964656e74696b65792d6d6a6f6c6e69722f76316462696e64496368616c6c656e6765a263616c676765643235353139636b6579582011111111111111111111111111111111111111111111111111111111111111118263766d736473746f708262766d614158202222222222222222222222222222222222222222222222222222222222222222
```

The identikey-auth signing payload is a different array, with its own domain. A unit assertion checks that payload is not these bytes. One seed signs both. Neither preimage is the other.

## Decision 5 — Transcript

The existing six fields stay first. Then:

7. The ClassicalPublicKey map bytes from Decision 4.
8. Operation: uint32 big-endian component count, then each component as uint32 big-endian length and bytes.
9. Resource, the same way.
10. Channel, exactly 32 raw bytes. No length prefix.

Vector, same account fixture as before, with the edge's tuples: XID `00..1f`, request id `00..0f`, edge Challenge `0102`, commitment 32 bytes of `0xab`, `iat` `1700000000`, session key 32 bytes of `0x11`, operation `["vms","stop"]`, resource `["vm","A"]`, channel 32 bytes of `0x22`. Digest `7efc1d284ac45ec66c928a750c701ed266ce28e3dab0e306588928c79dce8c03`. The pre-bind digest `13ef62b4…` is not this transcript.

## Decision 6 — Consent is shown by the caller, from bytes begin returns

No hosted page renders this ceremony. Begin returns the stored session key, operation, resource, and channel beside `consent_challenge`. An A3 caller renders those bytes. An A4 wallet recomputes the digest from them and refuses a mismatch before it signs. A malicious caller can misrender. That is not the OP checking the channel. The edge's channel check and its policy check are the backstop.

## Decision 7 — The bare responder is withdrawn

Bind fields are mandatory. A Challenge-only begin is refused and stores nothing. Mjolnir will not mint from a Response that has no bind, and a dual mode would let a bare attempt and a bind attempt share one ceremony. Attempts already stored without bind columns fail closed at finish. They are not completed by hashing empty bind fields.

## Decision 8 — What comes back, and what is audited

Retrieve, when completed, is JSON:

- `state`: `completed`
- `response`: unpadded base64url of the identikey-auth Response
- `bind`: unpadded base64url of the 64 raw Ed25519 signature bytes. Not a ClassicalSignature map. The client wraps those bytes as `{ "alg": "ed25519", "sig": <those bytes> }` before the edge sees them. The alg is fixed because begin refused P-256.
- `session_public_key`: `{ "alg": "ed25519", "key": <unpadded base64url of 32 bytes> }`
- `operation`: the component array
- `resource`: the component array
- `channel`: unpadded base64url of the 32 bytes

The echoed fields come from the stored row. A missing or wrong verifier returns neither signature. The completion audit commit stores both signatures, the operation, the resource, and `ClassicalPublicKey::fingerprint` from identikey-auth.

## Decision 9 — Edge Challenge audience is canonical base58

The Challenge this ceremony answers is the edge's. Its `aud` is the pinned edge XID at a text boundary: base58btc (Bitcoin alphabet) of the 32 raw bytes. Begin admits it only when decode yields 32 bytes and `to_base58` of those bytes equals the audience string. 64-lowercase-hex is withdrawn for this Challenge. It is diagnostics, and it is not what `EdgeKeys.edge_xid_text/1` emits.

The A4 consent Challenge is not that object. Its `aud` stays `xid_hex` of the account. It never reaches the edge. Do not "fix" it to base58. That would re-pin the consent vector.

`mjolnir-22ff.4` owes the matching issue rule: the edge puts that same canonical base58 text in `Challenge.aud`. This change does not build that issuer.

## Decision 10 — What stays put

C1 stays out. Schnorr blobs still fail closed. Retrieval stays the PKCE verifier. A holder public is not a retrieval proof. The OP does not consume the edge nonce.
