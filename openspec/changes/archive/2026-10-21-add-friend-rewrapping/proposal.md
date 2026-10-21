# add-friend-rewrapping

> **ACTIVE BUILD**

**Rigor:** architecture

## Why

Duke shares a recording with a friend who logs in with IdentiKey. The owner's X25519 scalar is sealed (`fcdb920`, folded `89fa644`). On 2026-10-21 he chose custodial re-wrap over a blind proxy: IdentiKey opens one data key under a fresh consent and wraps it again to that friend's published X25519. Recrypt's BN254 and secp256k1 backends do not consume that public, and this change does not invent a proxy-recryption scheme.

## What

- Capability `managed-custody`: purpose `rewrap`, one friend per attempt, HTTP returns the new keyspace §7 wrap.
- The data key and the scalar stay off the wire. The seal stays. Unwrap stays library-only.
- No keyspace roster write and no epoch. A house PTK wrap is still a §7 wrap, so consent on those bytes shares that data key.

## Impact

- Capabilities: MODIFIED `managed-custody` (held X25519 requirement); ADDED friend rewrap
- ADRs: amend ADR-012 item 4 only to name rewrap as the production open. Do not rewrite the live-instance paragraph from `fcdb920`.

## User journey & surfaces

No new UI because the owner creates a friend wrap with `POST /account/encapsulation/begin` (`purpose: rewrap`, the source wrap, the friend's base58btc XID) and `POST /account/encapsulation/rewrap`. The account-page button is a later change.

Working: the response is the new wrap, `text/plain`, `Cache-Control: no-store`, no HTML. Empty: the friend has no `c2_wrap_recipient`, so begin fails and inserts no row. Failed: cookie only, wrong wrap, rotated friend key, small-order recipient, null seal, or a second finish. Off: a null seal never opens.

## Preparation

Upstream is fold `89fa644` of `add-held-encapsulation-key`. Living anchors: `openspec/specs/managed-custody/spec.md` requirement "Held user X25519 encapsulation private"; `openspec/specs/guild-keyspaces/spec.md` requirement "Wrap-target is the user's X25519 encapsulation key"; `docs/LEARNINGS.md` 2026-10-21 (a sealed X25519 is openable by IdentiKey). Authority is "activate and run" for share-recording, bounded by the 2026-10-21 menu choice "IdentiKey re-wraps". Outcome: revised. `add-classical-pre` is not this change.

## Out of scope

- Blob Door storage of the recording or the friend wrap. Later node.
- A Mjolnir VM, whether or not it is called a recrypt proxy. Later node.
- Friend login. A published XID document is the recipient. An OIDC `sub` is not a key.
- Umbral, BN254, OpenFHE, and any new proxy-recryption scheme.
- An account-page button, a batch of friends, or returning the scalar or the data key.
- Changing export, climb, or the unwrap library's lack of an HTTP caller, except that begin accepts `rewrap`.
