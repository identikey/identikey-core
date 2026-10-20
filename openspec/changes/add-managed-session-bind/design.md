# Design — managed session bind

**Change:** `add-managed-session-bind`
**Bead:** `mjolnir-22ff.3.2`
**Steer:** 2026-10-19 (user)

## Decision 1 — One ceremony

Extend `/managed-challenge` begin, finish, and retrieve. Do not add a second route. Do not sign an opaque digest. One fresh A3 or A4 consent covers the Challenge and the bind. One key-use claim signs both. The completion row stores both. Retrieve returns both or neither. If the bind signature fails, the Response is not released.

## Decision 2 — Channel is consented bytes

Begin stores the channel bytes the client submits. Those bytes are what the edge handed the client beside the Challenge. Consent shows them. The OP signs them. The OP does not contact the edge and does not recompute `Blake3(SPKI || conn_id)` or the Iroh channel. The edge verifier already does that, and a mismatch fails there.

## Decision 3 — Caller names the operation

Begin requires operation and resource as the caller states them. Consent shows both. The OP does not keep an allowlist and does not apply Mjolnir policy. The edge may still deny the operation after the signature verifies. This is the same bind a wallet would sign, not a login-only fixed string.

## Decision 4 — Domain

The bind payload is the folded tuple:

```text
["identikey-mjolnir/v1", "bind", chal_bytes, session_pub, operation, resource, channel]
```

Signed by the same Ed25519 operational key that signs the v1 Response. No managed-only prefix.

## Decision 5 — Transcript

The existing six fields stay first, so a reader can see what changed. Then, with no extra separators:

7. Session public key, 32 raw bytes.
8. Operation: uint32 big-endian length, then UTF-8 bytes.
9. Resource: uint32 big-endian length, then UTF-8 bytes.
10. Channel: uint32 big-endian length, then raw bytes.

The A4 consent Challenge is still rebuilt from the stored attempt. Its nonce is the digest of this longer transcript. Finish rejects any other bytes before decrypt.

Vector, extending the old one: XID `00..1f`, request id `00..0f`, edge Challenge `0102`, commitment 32 bytes of `0xab`, `iat` `1700000000`, session public key 32 bytes of `0x11`, operation `vms:stop`, resource `vm-1`, channel 32 bytes of `0x22`. Digest `88265dc6cca649d6aae7f1e73b92a402b143d9cbfe4fcbb059a543053d124edc`. The pre-bind digest `13ef62b4…` is not this transcript.

## Decision 6 — What stays put

C1 stays out. Schnorr blobs still fail closed. Retrieval stays the PKCE verifier. A holder public is not a retrieval proof. The OP does not consume the edge nonce.
