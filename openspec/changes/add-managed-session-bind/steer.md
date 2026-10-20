# steer add-managed-session-bind

**When.** 2026-10-19
**Depth.** standard

## Decided
- Ceremony: one existing `/managed-challenge` consent signs the Challenge Response and the bind (user)
  Why: a second passkey tap is a worse login, and an opaque digest reopens a general signer.
- Channel: the OP signs the bytes the edge gave the client; the edge checks the live connection (user)
  Why: the hosted OP cannot see the Mjolnir TLS or Iroh session.
- Authority: the caller names operation and resource; edge policy is the limit (user)
  Why: wallet parity. A login-only fixed operation was the other option and was not chosen.

## Skipped
- none

## Feeds change
Extend the current ceremony. One claim, both signatures, both or neither on retrieve. Channel is consented bytes, not an edge callback. Operation and resource are caller-named and shown at consent. The domain tuple stays the folded Mjolnir bind.
