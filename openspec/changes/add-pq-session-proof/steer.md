# steer add-pq-session-proof

**When.** 2026-10-27
**Depth.** standard

## Decided

- Ordinary proofs are session-bound and small (user). One ML-DSA signature opens the session. Later checks are symmetric.
  Why: an ML-DSA signature on every proof is the cost Duke rejected.
- No proof log (user).
  Why: a transcript of ordinary proofs was rejected as harmful to the protocol.

## Skipped

- The key-source menu. Duke did not pick spike now, spike before act, or skip. The line stays unverified.

## Auto

- The state digest and the control key come from the state chain.
- The proof names the XID, not the classical fingerprint.
- Passkeys and classical OIDC signatures are not made post-quantum sound here.

## Feeds change

Scaffold PENDING. Do not activate while `pq-session-secret` is unverified. Do not implement key establishment.
