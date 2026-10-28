## ADDED Requirements

### Requirement: One control signature opens a session

The system SHALL open a session only when the cited state digest
resolves through `Trust::resolve` to the current unforked head for
that XID and the opening carries one verifying ML-DSA-65 signature by
that head's control key. The signed bytes SHALL be the canonical CBOR
array `[ "identikey-pq-session/v1", bstr(unsigned) ]`. `unsigned`
SHALL be the canonical dCBOR map `{ "v": 1, "xid": bstr(32), "state":
bstr(32), "aud": tstr, "chal": bstr(32) }`. The ML-DSA context
parameter SHALL be empty. A classical signature SHALL NOT open a
session. A forked chain SHALL NOT open a session. The proof SHALL
name the XID and SHALL NOT name a classical fingerprint.

The verifier SHALL supply the expected audience and the expected
32-byte challenge independently of the opening. The opening's `aud`
and `chal` SHALL equal those values. On success the verifier SHALL
consume that challenge before returning the verified opening. A
second use of a consumed challenge SHALL fail. An unexpected
challenge SHALL fail. A rejected opening SHALL NOT consume a
challenge. A verifying signature alone SHALL NOT be a session. A
session SHALL exist only when the caller also supplies a 32-byte key
under the binding precondition below.

#### Scenario: The current control key opens a session

- GIVEN an unforked head whose control key is ML-DSA-65, and a verifier-held audience and unused 32-byte challenge
- WHEN an opening for that XID and that head's digest matches that audience and challenge and verifies under that key, and the caller supplies a 32-byte key
- THEN a session exists, bound to that opening, and the challenge is consumed

#### Scenario: A classical signature does not open a session

- GIVEN an unforked head
- WHEN the opening is signed only by a classical key
- THEN no session exists and the challenge is not consumed

#### Scenario: An unexpected or reused challenge does not open a session

- GIVEN a verifying opening whose challenge is not the one the verifier currently holds, or was already consumed
- WHEN the opening is checked
- THEN no session exists

#### Scenario: The vector opening encodes one map

- GIVEN xid bytes `11` repeated, state bytes `33` repeated, challenge bytes `22` repeated, and audience `rp.example`
- WHEN the unsigned opening is encoded
- THEN the bytes are `a5617601636175646a72702e6578616d706c656378696458201111111111111111111111111111111111111111111111111111111111111111646368616c5820222222222222222222222222222222222222222222222222222222222222222265737461746558203333333333333333333333333333333333333333333333333333333333333333`
- AND a different field boundary, a non-canonical integer, or a wrong length fails before any challenge is consumed

### Requirement: The session key is bound to that opening

The opening signature SHALL NOT establish the 32-byte key. The
verifier's precondition SHALL be that the caller supplies a key only
when an establishment outside this change has already bound that key
to this verified opening and to the peer. The session SHALL retain
the SHA-256 of the unsigned opening, the XID, the state digest, the
audience, and that key. A MAC from one opening SHALL NOT verify for
another opening, even when the audience, the state digest, and the
supplied key are the same. This requirement SHALL NOT choose ML-KEM
or classical Diffie-Hellman.

#### Scenario: Two openings do not share a MAC

- GIVEN two verified openings with the same audience, the same state digest, and the same supplied key
- WHEN a follow-up MAC is built for the first opening
- THEN it fails verification for the second opening

### Requirement: A later proof is a session MAC

A proof after opening SHALL verify as HMAC-SHA-256 under the session
key. The HMAC input SHALL be the canonical CBOR array
`[ "identikey-pq-session-mac/v1", bstr(body) ]`, where `body` is the
canonical dCBOR map `{ "v": 1, "open": bstr(32), "aud": tstr,
"state": bstr(32), "msg": bstr }`. `open` SHALL be the SHA-256 of the
unsigned opening. The tag SHALL be exactly 32 bytes and SHALL be
compared in constant time. A shorter or longer tag SHALL fail.
Verification SHALL NOT require a second public-key signature. The
same MAC SHALL verify again. It SHALL NOT be treated as a fresh
action, and the verifier SHALL NOT consume it. Any holder of the
session key SHALL be able to produce a proof that verifies. The
verifier SHALL NOT append the proof to a log.

Before accepting the tag, the verifier SHALL resolve the session's
state digest through current trust. The proof SHALL fail when that
digest is no longer the current unforked head, including after
rotation, after a detected fork, and when authority is absent. A
successful MAC SHALL NOT be read as a claim that survives those
cases. A proof whose audience, opening id, or state digest differs
from the session SHALL fail.

#### Scenario: The follow-up check needs no public key

- GIVEN a session whose state digest is still the current unforked head
- WHEN a follow-up proof is the 32-byte HMAC of that session's opening id, audience, digest, and a message
- THEN the proof verifies, no public-key signature is checked, and the same proof verifies again

#### Scenario: Another audience fails

- GIVEN a session opened for one audience
- WHEN a follow-up proof names a different audience
- THEN the proof fails

#### Scenario: Rotation and a fork end the session

- GIVEN a session opened for digest H
- WHEN the current head is no longer H, or the chain is forked, or authority is absent
- THEN a correctly tagged follow-up for H fails

#### Scenario: The vector MAC names its opening

- GIVEN the vector opening above and message bytes `hello`
- WHEN the MAC input is encoded
- THEN the bytes begin `82781b6964656e74696b65792d70712d73657373696f6e2d6d61632f7631586c`
- AND the `open` field is SHA-256 of the unsigned opening, `5e124e342531dcc3a79cecc9d0256f963370e6f55bff579331be481472f66cbd`
