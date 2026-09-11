# Design — Apply identikey-keyspace-v1 in identikey-keys

ADR-012 is the mapping. This file is how identikey-keys consumes the
wire without becoming a second standard.

Protocol source: identikey-protocol
`docs/standards/identikey-keyspace-v1.md`. identikey-log types nothing
inside `Op.body`; this crate does.

## Log dep

Pin `identikey-log` from the same identikey-protocol git rev pattern as
`identikey-auth` (`Cargo.toml` workspace.dependencies). LEARNINGS
2026-08-19: `cargo deny` `[sources] unknown-git = deny` needs
`allow-git` for that repo.

Do not import `identikey-storage-auth` or recrypt (LEARNINGS 2026-07-28).
Do not amend identikey-log. Body remains opaque CBOR to the log.

## Apply, not coordinate

The crate is a replica. A caller hands it verified ops (identikey-log
already checks signature, canonical body, actor). identikey-keys:

1. Decodes the body as the protocol §9 map for that kind.
2. Checks the consumer rule (protocol §6.1 admin / genesis exception /
   nest against the **outer** applied roster).
3. Refuses IdentiKey's C2 Sign+Auth public as `Op.actor` and as a wrap
   `recipient`.
4. Updates the in-memory view; optionally writes Postgres.

Postgres, if present, is a cache of applied roster/epoch/wraps. Holders
who still have `admin: true` keys continue from log replicas if the
cache is deleted. `consent_log` stays C2 access-credential proofs.

## PUK selector

Wrap-target is the member's latest **user** identity key (Ed25519 via
X25519, or P-256) per protocol §5 / §7. Exclude the C2 Sign+Auth
operational key (`IDENTIKEY_C2_PRIVILEGES` in `privilege.rs`). Elect
privilege is not automatically the wrap-target; at C2 it usually is
the PUK.

Devices stay `credentials` rows. `revoke_device` does not edit the PTK
wrap-list. Rewrap is `keyspace.epoch-begin` then `epoch-commit`. There
is no `keyspace.rewrap` kind. `ChangeBody` has no wraps.

## Nest and fade

Inner genesis (`keyspace.nest`) is signed by an outer admin (protocol
§6.1). Do not authorize nest against the inner roster in the nest body.

Last admin leave: further administering ops fail. Ciphertext keyed to
the last committed PTK still unwraps. identikey-keys denies against the
applied roster/blacklist. It does not serve bytes and does not invent a
guardian.

## Epoch conflict

Two concurrent `epoch-begin` ops (neither an ancestor of the other):
do not merge, do not apply either, until an admin `nacks` one
(identikey-log `nacks`) or a later begin parents exactly one.
identikey-log surfaces concurrency (`lib.rs`); this crate implements
the consumer rule.

## Profiles

Protocol `profile` strings `"house"` | `"access-node"`. Access-node
join/leave MUST NOT rotate PTK. Wrap-on-login is `identikey-core-trr.2`,
not this change. `assign-node` `node` is opaque 32 bytes.

## HTTP

None. No new route. Holders (CLI, later Lightning Admin v2) present
ops. `/authorize` wrap-on-login waits on trr.2.
