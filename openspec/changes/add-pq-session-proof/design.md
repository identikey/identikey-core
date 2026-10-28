# Design — session proof

**Change:** `add-pq-session-proof`
**Bead:** `identikey-core-pgz.2`

## Opening

The caller supplies the state-chain trust for one XID and one
opening. The cited digest must resolve through `Trust::resolve`: the
accepted head, and nothing after a fork. The opener is one ML-DSA-65
signature by that head's control key. A classical signature does not
open a session.

The signed bytes are a domain-separated payload naming
`identikey-pq-session/v1`, the XID, the 32-byte state digest, the
audience, and a fresh 32-byte challenge. The ML-DSA context
parameter stays empty. Domain separation sits inside the payload, as
it does for `identikey-pq-state/v1`.

## Follow-up check

The session key is 32 bytes the caller holds after opening. A
follow-up proof is HMAC-SHA-256 over the audience, the state digest,
and the message. Verification does not take a public-key signature.
The same MAC is valid for anyone who holds the session key. A proof
for another audience or another digest fails. The verifier writes no
log.

## What this does not choose

The opening signature does not itself establish the 32-byte key.
The agreed acceptance is the signature and the MAC. The source of
the key is the hypothesis below.

## Unverified hypotheses

- `pq-session-secret` — the session check key comes from a
  transcript-bound ML-KEM exchange, not from a classical
  Diffie-Hellman signed by ML-DSA — unverified (medium, no
  synthesis). No `docs/spikes/pq-session-secret/finding.md`. Not
  started.
