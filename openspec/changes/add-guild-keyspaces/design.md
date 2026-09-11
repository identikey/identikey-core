# Design — Guilds as shared keyspaces (ADR-012)

Steer 2026-08-31 / 2026-09-01 is the source. Send-back 2026-09-01
amends this file to **cite** protocol, not re-specify it.

Protocol source: identikey-protocol
`docs/standards/identikey-keyspace-v1.md`. ADR-002 already split that
repo. This ADR maps it onto identikey-keys.

## What a guild is

A guild (product) is a **keyspace** (protocol): a distributed object,
the keys that comprise it. It is not housed at identikey-core, on one
mesh node, or in Postgres.

**Id** is the identikey-log `content_hash` of the genesis op
(protocol §3): outer genesis is the first admin `keyspace.join`; inner
genesis is `keyspace.nest`. No second identifier. No eighth kind.

**Admin** is the roster boolean `admin` (protocol §6). After genesis,
only a current admin's Ed25519 `Op.actor` may append administering
kinds. Genesis exception: the first join is valid iff that actor
appears as `admin: true` in the same body.

XID stays who-I-am. Join/leave is not an Elect rewrite of the member
XID. The root identikey still Elects its own keys (ADR-001, ADR-010).

The 2026-09-01 02:10 "separate guild document with XID-shaped
inception" comment is superseded. The replicated artifact (roster,
wraps, nested ids) is evidence, not a home.

## Methods (FOKS, not FOKS-the-product)

Protocol §2.1. Do not run FOKS servers. Do not replace XID with
`user@host`.

| Layer | Name | In this crate |
|---|---|---|
| Device | device key | `credentials` row. Not a wrap-target. Not a `keyspace.*` op. |
| User | PUK | Wrap-target: user's latest identity key (Ed25519 via X25519, or P-256). |
| Keyspace | PTK | 32-byte secret; wraps are protocol §7 CBOR maps. |

**Cascade.** Device revoke → user rotates PUK → keyspace rewraps PTK to
the latest PUK (protocol §2.1). Revoking a `credentials` row does not
by itself edit the PTK wrap-list.

Envelope rewrap (KMS-style): do not rewrite every blob keyed to the
PTK.

## C2 mapping

`authorize_elect` continues to gate the **member XID document**
(`crates/identikey-keys/src/privilege.rs`). Keyspace join does not
call it on that document.

| Key | Role in a keyspace |
|---|---|
| User Elect (Schnorr secp256k1 on `c2_native`) | Identity control. Not a wrap-target. Not `Op.actor`. Rotating the encapsulation half of this `PublicKeys` is an Elect rewrite. |
| User X25519 encapsulation half (same `PublicKeys`) | **The C2 PUK.** Wrap-target. Protocol §7 `x25519-xchacha20poly1305`. Not derived via §7.2. |
| IdentiKey Sign+Auth (C2) | **Not** a wrap-target. **Not** a keyspace admin. Must not appear on the roster. `managed_key_blob` is not a wrap-target. |
| identikey-log `Op.actor` | Raw 32-byte Ed25519. Authors `keyspace.*`. **Not present** on today's C2 rows. |
| Passkey / A4 `device_public_key` | `credentials` row. Not a wrap-target. Not the admin companion. Passkey revoke does not rotate PUK (the passkey never held it). |
| C1 row | No user key. Cannot be a member. |

`admin: true` requires an Ed25519 `actor` (protocol §5). That companion is
wallet-held Ed25519 or a later second document key — not this crate's
passkey, not A4 device keys. Until it exists, C2 members of this store are
wrap-target-only (`admin: false`, `actor` omitted).

Signup drops the user `PrivateKeyBase`. The wrap names the public X25519;
unwrap waits on Elect export or a wallet that holds that private.

## Two words

Protocol, op kinds, this crate's log consumer: **keyspace**.
Lightning Mesh UI and Admin: **guild**. Kinds are protocol §4.1
(`keyspace.join` / `change` / `leave` / `assign-node` / `nest` /
`epoch-begin` / `epoch-commit`). Not `guild.*`. No `rename` kind.

identikey-oidc MUST NOT emit a claim named `guilds`. Today's tokens
are iss/sub/aud/iat/exp + optional nonce; userinfo is `{sub}`.

## Log is transport

`identikey-log`: signed, actor-attributed, content-addressed,
causally ordered, body opaque, concurrency surfaced not merged.
This crate types bodies per protocol §9. It does not amend the log.

Postgres / identikey-core is a cache of applied ops, not the
coordinator. `consent_log` stays C2 access-credential proofs. Do
not reuse it as the keyspace log.

## Hybrid eviction and epoch

Protocol §8. Instant: roster deny / blacklist field on `leave` or
`change`. Cryptographic: `epoch-begin` / `epoch-commit`, all-or-none,
matching begin in parent hashes. Concurrent `epoch-begin` ops that
are not ancestors: do not merge, do not apply either, until an admin
`nacks` one or a later begin parents exactly one. identikey-keys
implements that consumer rule; it does not invent a merge.

## Fade vs remaining wraps

If the last `admin: true` entry leaves, administering fades: further
administering ops do not verify (protocol §6.1). Ciphertext keyed to
the last PTK still decrypts until an epoch commits. Fade is liveness
of the object, not cryptographic death.

## Two profiles

Protocol `profile`: `"house"` | `"access-node"`.

- **House:** configurable epoch; kick MAY begin an epoch.
- **Access-node:** long epoch; join/leave MUST NOT rotate PTK per
  event. Nested after `keyspace.assign-node` then `keyspace.nest`.
  Wrap-on-login is `identikey-core-trr.2`, not this act.

`keyspace.assign-node` carries an opaque 32-byte `node` id
(protocol §9). identikey-keys stores it uninterpreted. Lightning
Mesh fills it with its node id.

## Three layers stay uncollapsed

Identity: XID + this keyspace membership. Agency: Biscuit. Data:
Recrypt. Mixing any two is a protocol error. `mjolnir-mesh-6t7`
stays deferred.

## Radio and Admin (not this capability)

D1 orthogonality stands: SSID is a public network name; association
is not membership. Those SHALLs live in lightning-mesh
`client-network-name` and `mjolnir-mesh-st1.3` / `st1.5`. This
capability does not claim radio or Lightning Admin behavior.

## What identikey-keys does at runtime

`add-keyspace-runtime`: apply `keyspace.*` ops from holders'
replicas; optional Postgres materialization of roster/epoch/wraps;
refuse IdentiKey Sign as keyspace admin; leave `authorize_elect` on
the member XID path alone.
