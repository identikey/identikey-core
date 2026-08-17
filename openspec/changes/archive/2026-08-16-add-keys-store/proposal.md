# add-keys-store

> **ACTIVE BUILD**

## Why

`identikey-keys` has a schema (`zan.1`) and an in-memory C2 privilege split
(`av9`, ADR-010). Neither is durable. Without a store, `authorize_elect` is a
function anyone can skip, and C2 is a document that vanishes on process exit.

## What

- `KeysStore` over sqlx / Postgres: accounts, passkeys, custody records
  (XID documents), consent log, custody events.
- Persist a key-graph update only after `authorize_elect` succeeds against
  the **stored** previous document.
- `identikey-server` requires `DATABASE_URL`, runs `MIGRATOR` at boot, holds
  the store. `/health` stays liveness-only.

Capability touched: `managed-custody` (ADDED — first living spec for this
repo).

## Impact

- Capabilities: ADDED `managed-custody`
- ADRs: none (ADR-006/010 already decided the access layer and the split)

## User journey & surfaces

No new UI because this is the persistence substrate. The only HTTP surface
is still `/health`. Account and consent screens are `identikey-core-ccf.11`.

## Out of scope

- Envelope-encrypt `managed_key_blob` (later; column is opaque)
- `query!` / `.sqlx/` CI gate (`identikey-core-xg2`)
- C2→C3 ceremony (`identikey-core-zan.2`)
- Device records (`identikey-core-zan.8`)
- OIDC clients / tokens / pairwise salt (`ccf.*`)
- WebAuthn ceremony (`identikey-core-5gh.1`)
- Guardian tables (`identikey-core-vt4`)
