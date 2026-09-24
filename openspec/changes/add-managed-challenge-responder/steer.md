# steer add-managed-challenge-responder

**When.** 2026-09-24
**Depth.** explicit

## Decided
- Protocol: identikey-auth v1 unchanged; identikey-core is a claimant, not the edge verifier (user, parent node)
- Algorithm: Ed25519 operational Sign+Auth, not secp256k1 Schnorr, not P-256 for the blob (user)
  Why: blob is stored and unused; v1 already has Ed25519; adding Schnorr would fork the protocol; existing Schnorr rows remint.
- X25519 wrap-target on the user key is a different half and is not this fork (auto)

## Skipped
- none on this node (Schnorr fork closed)

## Feeds change
`c2_native` / signup mint Ed25519 for `ours`. Signer accepts only canonical Challenge bytes after fresh A3/A4. Audit before and after. Response only to the initiating client. Edge (Mjolnir) still consumes nonce atomically when minting.
