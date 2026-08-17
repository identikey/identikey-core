# add-device-records

> **ACTIVE BUILD**

Activated from `nod-device-records` (`identikey-core-zan.8`).

**Rigor:** change

## Why

The TS/Keycloak device model (`is_master`, `device_trust` in every
token) leaks posture to relying parties and predates the custody
ladder. What matters now is which privileges a device key holds, not
a master/temp boolean. Credentials already persist passkeys and A4
device keys; the store does not yet list or revoke them as devices.

## What

- Treat a `credentials` row as the device record (no second table).
- `KeysStore` list (non-revoked) and revoke (`revoked_at`).
- Registration already inserts; nickname / `last_used_at` may be set.
- Never emit a `device_trust` claim from this crate.
- Capability `managed-custody` (ADDED requirement).

## Impact

- Capabilities: ADDED requirement on `managed-custody`
- ADRs: none (corrects the pre-ADR device model; ADR-009 instinct)

## User journey & surfaces

No new UI because this is the keys-crate API. The account device list
is `identikey-core-ccf.11`. Token claims and refresh-token kill are
`ccf`.

Intended path: a credential is registered; list returns it; revoke
sets `revoked_at` and it disappears from the list; nothing in this
crate advertises master/temporary.

## Out of scope

- `device_trust` / `device_id` token claims — `ccf`
- Refresh-token invalidation on revoke — `ccf`
- `is_master` (deliberately not revived)
- Passkey registration ceremony — `identikey-core-5gh.1`
- AAGUID as policy (still a UX hint only)
