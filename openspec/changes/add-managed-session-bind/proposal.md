# add-managed-session-bind

> **ACTIVE BUILD**

Bead `mjolnir-22ff.3.2`. Steer 2026-10-19. Parent ceremony is the folded C2 responder (`add-managed-challenge-responder`).

**Rigor:** architecture

## Why

A C2 user can already get an identikey-auth v1 Response from `/managed-challenge`. Mjolnir will not mint a direct-login capability from that Response alone. The edge also requires a same-holder session bind, and the Response is not consent for the bind.

## What

- Extend the existing begin / finish / retrieve ceremony so one fresh A3 or A4 consent covers the Challenge and the bind.
- One key-use claim signs both. Retrieve returns both or neither.
- The caller names operation and resource. Consent shows those plus the channel bytes.
- The hosted OP signs the channel bytes and does not check the Mjolnir connection. The edge does.
- Capability: MODIFIED `managed-custody`.

## Impact

- Capabilities: MODIFIED `managed-custody`
- ADRs: none in this repo. The bind domain stays Mjolnir `edge-auth` / ADR 0012's sibling contract. No new algorithm.

## User journey & surfaces

A native client that already calls `POST /managed-challenge/begin` now also sends the session public key, the operation, the resource, and the channel bytes the edge returned beside the Challenge. The person approves one passkey (or signs one A4 consent Challenge). Retrieve gives them the v1 Response and the bind, or an error and neither.

- **Working** — one consent, both signatures, same operational key, initiating client only.
- **Empty** — no C2 row, or no passkey and no Elect key → no signature.
- **Failed** — a Challenge-only begin, a swapped operation, or a second client with the request id.
- **Off** — C3/C4 sign the bind locally. C1 is not this ceremony. Browser `/authorize` is unchanged.

## Preparation — 2026-10-19

Outcome: revised. The folded responder signs the Challenge only. This node adds the bind to that ceremony. Upstream: identikey-core `8d29812` documents the gap; Mjolnir edge-auth already verifies the bind domain (folded `549e946` / `696fb00`). Authority: none. Banner stays PENDING. Bare `/run` is not a grant to implement.

## Out of scope

- Edge nonce consumption and Biscuit mint — Mjolnir `mjolnir-22ff.4`
- `mj login --direct` — Mjolnir `mjolnir-22ff.6`
- C1 managed keys
- A second ceremony, or signing an opaque digest
- The OP applying Mjolnir policy or dialing the edge
- Migrating pre-`35aee29` Schnorr blobs
