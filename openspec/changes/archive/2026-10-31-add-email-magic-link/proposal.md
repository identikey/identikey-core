# add-email-magic-link

> **ACTIVE BUILD**

Node `identikey-core-zlf.7`. Depends on the folded account key model.
Activation needs a human. The first-wave grant does not cover it.
`identikey-core-vt4.6` is this node, not a second plan.

## Why

The account has an email column and no ceremony that proves an
address belongs to that XID. A magic link is that proof. It stores
the address. It does not become a device or a key.

## What

- Capability `account-recovery`.
- A single-use link verifies an email address and stores it on
  `accounts.email` for that XID.
- Writing the column does not insert a credentials row.
- The existing unique index on `lower(email)` still decides which
  accounts may store the same address. A second account cannot take
  an address already stored.
- Redeeming the link does not read `managed_key_blob`, does not sign
  a Challenge, and does not mint Elect.
- SMS stays outside this DAG.

## Impact

- Capabilities: ADDED `account-recovery`.
- ADRs: none.
- `add-a1-account-recovery` is a separate PENDING architecture
  change for the recovery-crate proof types, including SMS. This
  change is the hosted email link only. It does not absorb that
  change.

## User journey & surfaces

Who: the account holder, from the account, asking to set the
recovery address.

Working: the link redeems once onto the same XID and the address
is stored.

Empty: no address yet. Redeeming stores one.

Failed: a second redeem does nothing. A link for one XID does not
write another account. An address already stored on a different
account is refused. The link does not touch key material.

Off: SMS is not offered.

## Out of scope

- SMS OTP (`identikey-core-vt4.4`).
- The recovery-crate proof matrix in `add-a1-account-recovery`
  (`identikey-core-vt4.5`), except that this link must not become a
  way to read key bytes.
- What the enrolled passkey may do (`identikey-core-zlf.2`).
- The lose-every-passkey drill (`identikey-core-zlf.10`).
