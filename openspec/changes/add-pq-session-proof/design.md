# Design — session proof

**Change:** `add-pq-session-proof`
**Bead:** `identikey-core-pgz.2`

## Opening

The caller supplies state-chain trust, one opening, the audience the
verifier expects, and the 32-byte challenge the verifier expects.
Those two expectations are not read out of the opening. The cited
digest must resolve through `Trust::resolve`: the accepted head, and
nothing after a fork. The opener is one ML-DSA-65 signature by that
head's control key. A classical signature does not open a session.

The unsigned opening is a canonical dCBOR map, same codec as the
state record:

```text
{ "v": 1, "xid": bstr(32), "state": bstr(32), "aud": tstr, "chal": bstr(32) }
```

Canonical key order is the encoded key, shorter first, so the wire
order is `v`, `aud`, `xid`, `chal`, `state`. The signed bytes are
the canonical CBOR array `[ "identikey-pq-session/v1", bstr(unsigned) ]`.
The ML-DSA context parameter stays empty. A non-canonical encoding,
a wrong length, or an unknown field fails before the challenge is
consumed.

Success consumes the challenge. Failure does not. A consumed or
unexpected challenge fails. The opening id is SHA-256 of `unsigned`.

A verifying signature is not a session. The caller then supplies a
32-byte key. The session retains the opening id, the XID, the state
digest, the audience, and that key.

## Follow-up check

The HMAC input is the canonical CBOR array
`[ "identikey-pq-session-mac/v1", bstr(body) ]`, where `body` is:

```text
{ "v": 1, "open": bstr(32), "aud": tstr, "state": bstr(32), "msg": bstr }
```

`open` is the opening id. The tag is 32 bytes, compared in constant
time. A different length fails. Verification does not take a
public-key signature. The same MAC verifies again. It is not a
fresh action, and the verifier does not consume it. Any holder of
the session key can produce it. The verifier writes no log.

`open` in the MAC stops one opening's proof from verifying against
another opening that shares the audience, the digest, and the key.

Each follow-up resolves the session's digest through current trust.
Rotation, a detected fork, or a missing head rejects the proof even
when the tag is correct. A successful MAC is not evidence of
authority after those events.

## What this does not choose

The opening signature does not establish the 32-byte key. The
precondition, which this verifier does not check, is that the caller
supplies a key only when establishment outside this change has bound
that key to this opening and to the peer. Two openings may be given
the same key bytes. The MAC still will not cross, because it names
the opening id.

## Unverified hypotheses

- `pq-session-secret` — the session check key comes from a
  transcript-bound ML-KEM exchange, not from a classical
  Diffie-Hellman signed by ML-DSA — unverified (medium, no
  synthesis). No `docs/spikes/pq-session-secret/finding.md`. Not
  started.

## Vector

Unsigned opening for xid `11`×32, state `33`×32, challenge `22`×32,
audience `rp.example`:

```text
a5617601636175646a72702e6578616d706c656378696458201111111111111111111111111111111111111111111111111111111111111111646368616c5820222222222222222222222222222222222222222222222222222222222222222265737461746558203333333333333333333333333333333333333333333333333333333333333333
```

Opening id: `5e124e342531dcc3a79cecc9d0256f963370e6f55bff579331be481472f66cbd`.

MAC input for message `hello` begins
`82781b6964656e74696b65792d70712d73657373696f6e2d6d61632f7631586c`.
