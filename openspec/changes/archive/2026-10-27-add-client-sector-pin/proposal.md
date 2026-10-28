# add-client-sector-pin

> **ACTIVE BUILD**

Node `identikey-core-2zj.1` (epic `identikey-core-2zj`). Steer 2026-09-29.
Activated in chat 2026-09-29 ("activate" for this node only).

**Preparation:** still valid. No upstream node. `client_from_spec`
(`crates/identikey-server/src/main.rs`) sets the sector from
`sector_from_redirect(redirects.first())`; `Client.sector_identifier`
already exists in `identikey-oidc`. Live pairwise clients include the
primary `IDENTIKEY_CLIENT_ID` (taskmaster), `taskmaster-laptop`, Conduit
`localhost`, and `wtnf-web`. Authority: this node only; registry, owner
signing, and DCR stay PENDING in `.2`–`.4`.

## Why

A pairwise `sub` is `KDF(salt, XID, sector)`, and today the sector is the
host of whichever redirect happens to be listed first. Editing a client's
redirects is about to become routine (the `mlcp-negotiated` callback was
added by hand on 2026-09-29). Putting a different host first, or replacing
the first redirect, silently gives every person a new pairwise identity at
that RP. Nothing refuses it and nothing logs it.

## What

- `oidc-provider`: a pairwise client's sector is configuration, stored with
  the client (`sector` in `IDENTIKEY_CLIENTS`,
  `IDENTIKEY_CLIENT_SECTOR` for the primary client). Redirects never feed
  it.
- Boot refuses a pairwise client with no sector, naming the client. Public
  clients need none.
- Operator backfill: freeze each live pairwise client's current derived
  sector into escrow before the new binary runs, so no live `sub` moves.

## Impact

- Capabilities: ADDED `Pairwise sector is registered, not derived`
  (oidc-provider)
- ADRs: none. `docs/ARCHITECTURE.md` already defines
  `sub_rp = KDF(salt, XID, sector_identifier)`; this makes the identifier
  explicit.

## User journey & surfaces

No new UI because the outcome reaches the operator through boot output and
the client configuration they already edit (`IDENTIKEY_CLIENTS` in the
IdentiKey escrow). People signing in see nothing: their pairwise `sub` at
each RP stays the same. Failed state: a pairwise client missing `sector`
stops boot with a message naming that client, before any request is served.

## Out of scope

- Storing clients in Postgres — `identikey-core-2zj.2`.
- Owner-signed client changes — `identikey-core-2zj.3`.
- Dynamic registration — `identikey-core-2zj.4`.
- `sector_identifier_uri` fetch/validation (OIDC Core §8.1); the sector is
  an operator-set string.
