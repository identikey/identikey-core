# steer add-oidc-signing-rotation

**When.** 2026-10-28
**Depth.** standard

## Decided

- Publish the new key before signing with it, overlap at least the max token lifetime, then retire (user, on `identikey-core-ccf.9`)
  Why: relying parties still hold ID tokens from the old key.
- The overlap is the ID-token lifetime, 3600 seconds (auto)
  Why: access and refresh tokens are opaque. They are not verified through JWKS.
- The salt is structurally excluded (user, on `identikey-core-ccf.9`)
  Why: rotating it changes every pairwise `sub`.
- This is not XID rotation (user, on `identikey-core-ccf.9`)
  Why: the OP service key and a person's inception key must not share a path.

## Skipped

- None.

## Feeds change

Scaffold PENDING. Do not activate. The post-quantum grant does not cover this node.
