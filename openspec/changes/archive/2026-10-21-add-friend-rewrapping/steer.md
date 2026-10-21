# steer add-friend-rewrapping

**When.** 2026-10-21
**Depth.** standard

## Decided

- Classical share path: IdentiKey re-wraps (user)
  Why: the sealed key is X25519. BN254 and secp256k1 cannot transform a wrap to that public. Re-wrap uses the landed seal and returns a new §7 wrap. The VM does not see the data key because it is not in this change.

## Skipped

- Umbral on secp256k1 — not chosen
- AFGH on BN254 — not chosen

## Feeds change

Replace the proxy-recryption node with custodial re-wrap to a friend's published X25519. One consent, one friend, one source wrap. Do not implement a PRE backend.
