# Tasks

- [x] Choose the native enrollment journey. Papyrus is chosen. A standalone Linux enclave enrollment is not this journey.

The account-binding route that inserts the `identikey_auth` row is a later node. This change does not create protocol beads.

## Owed from architecture review (2026-10-31)

- [x] R1: Reconcile proposal, design, and delta with the living surviving-access rule: retain unconditional `revoke_device` as the primitive, but require Papyrus account-access revocation to use the existing `revoke_account_access` policy. Add a scenario that leaves the last `identikey_auth` login active without explicit last-access confirmation. Documentation only; no new revocation implementation or protocol bead. See `reviews/2026-10-31-advise.md`.
- [x] R2: Carry the delivery boundary into the delta: this node selects Papyrus and records existing local behavior; OP account binding and native account login remain future work. Label their constraints as deferred, state that folding this decision does not claim those behaviors are delivered, and require later work to establish usable native login before relying on the rows as surviving access. Do not implement the route or create protocol beads. See `reviews/2026-10-31-advise.md`.
