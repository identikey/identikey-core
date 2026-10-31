# add-recovery-authority

## Decided

The mailbox ceremony is the limited step. It may write one ordinary
`kind=passkey` row. That row has no purpose-limited flag and no
upgrade assertion. List, revoke, and consent match a signup passkey.

A1 proof and the recovery session do not read `managed_key_blob` and
do not grant Elect or Transfer. C2 signing after recovery is a fresh
assertion of the enrolled passkey.

## Open

None on this node. Activation is the human gate. The email ceremony
and the drill are other nodes.
