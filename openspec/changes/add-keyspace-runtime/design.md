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

On a stored C2 document from `c2_native` + `PrivateKeyBase::new()`, the
wrap-target is the **X25519 encapsulation half** of the user's
`PublicKeys`, not Schnorr, not Sign+Auth, not a passkey, not
`managed_key_blob`. Protocol §7.2 (Ed25519→X25519) is not the selector.
C1 rows and rows with no user key have no wrap-target and cannot join.

Signup drops the user private. A wrap to that X25519 public is named
membership; the member cannot unwrap until Elect export or a wallet
holds that private. Do not assume "at C2 it usually is the PUK" means
the member can decrypt today.

Schnorr cannot be `Op.actor`. Admin Ed25519 is a later named surface.
Today's C2 rows are wrap-target-only (`admin: false`).

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
