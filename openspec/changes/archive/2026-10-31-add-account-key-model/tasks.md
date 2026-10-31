# Tasks

- [x] Record the surviving-access decision in this change's delta before activation: which non-revoked credential kinds still count as access when the last passkey would be removed

The device-record rule is already the living requirement "Devices are listable, revocable credentials." This change does not edit `list_devices` or `revoke_device`.

## Owed from architecture advise (2026-10-31)

- [x] Reconcile the last-access enforcement boundary across proposal, design, and delta: identify whether the shared store primitive or an account-management operation enforces confirmation, name the downstream enforcement owner for all counted kinds, reconcile the existing unconditional revocation contract/test, and record the delivery/fold dependency so model completion does not claim unbuilt behavior. See `reviews/2026-10-31-advise.md`, finding 1. Documentation only on this node.
- [x] Pin surviving-access evaluation and revocation to one atomic account-scoped decision, preserve custody-before-credential lock ordering, and add the concurrent two-credential/unconfirmed-revokes scenario with downstream verification ownership. See `reviews/2026-10-31-advise.md`, finding 2. No runtime implementation on this node.

Fresh advise is the next reader. The 2026-10-31 send-back does not cover the amended boundary.
