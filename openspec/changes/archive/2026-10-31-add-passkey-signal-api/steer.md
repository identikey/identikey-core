# steer add-passkey-signal-api

**When.** 2026-10-28
**Depth.** standard

## Decided

- Best-effort after success (user, 2026-09-26, on `identikey-core-5gh.3`)
  Why: a missing or failed signal must not fail registration or login. Unsupported browsers are a no-op.
- Accepted list is every credential id stored for that XID (auto)
  Why: a one-id list would ask the provider to drop the others.
- `signalCurrentUserDetails` waits (auto)
  Why: `user.name` is the XID and nothing renames it.
- Removal signaling waits (auto)
  Why: no passkey-removal route exists.
- Unknown credential is only `credential not found` (auto)
  Why: expiry and user cancel are not unknown credentials.

## Skipped

- None. No open HIGH fork. The key-source menu is not this change.

## Feeds change

Scaffold PENDING. Do not activate. The post-quantum grant does not cover this node. Do not change counter checks.
