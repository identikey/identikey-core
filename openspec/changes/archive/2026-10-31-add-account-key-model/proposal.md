# add-account-key-model

> **ACTIVE BUILD**

Node `identikey-core-zlf.1`. Activated 2026-10-31. Living
`managed-custody` already requires a `credentials` row to be the
device record (`list_devices`, `revoke_device`; the list type has no
`device_trust`, `is_master`, or master/temporary). Current kinds are
`passkey`, `oidc_apple`, `oidc_google`, `identikey_auth`, and
`ssh_git`. `accounts.email` is the A1 column, unique on
`lower(email)` where it is not null, and it is not a credentials
kind. `managed_key_blob` is the server-held Ed25519 operational Sign
key. Surviving access counts a live passkey, `oidc_apple`,
`oidc_google`, `identikey_auth`, or a password row when that kind
exists. `ssh_git` does not count. `revoke_device` stays an unconditional
soft-revoke. A separate kind-generic account-access revocation
operation enforces the last-access confirmation.
`identikey-core-zlf.6` owns that operation for every counted kind.
This model does not claim the store already does.

## Why

Later account work needs one place that says what an account lists,
what `revoke_device` may change, and what a mailbox or a password
must not do with the server-held Sign key. The device-record rule
already landed. The channel and the managed key are still easy to
treat as devices.

## What

- Capability `managed-custody`.
- `accounts.email` is the A1 recovery destination. It is not a
  `credentials` kind and `list_devices` does not return it. Writing
  the column does not insert a credential.
- `managed_key_blob` is not a device record. `list_devices` does not
  return it. `revoke_device` does not clear or rotate it.
- An A0 password proof and an A1 email or SMS proof do not decrypt
  `managed_key_blob`, do not sign an identikey-auth Challenge with
  it, and do not mint an Elect key.
- The OP signing key, the pairwise salt, and an Elect private key
  discarded at hosted signup are not credentials rows. The cookie
  and the mailbox do not reconstruct that Elect private key.
- Account access is a non-revoked `passkey`, `oidc_apple`,
  `oidc_google`, `identikey_auth`, or password credentials row.
  `ssh_git` is a device row and is not account access.
  `revoke_device` does not apply that count. Account-access
  revocation does, atomically for the XID, with the custody row
  locked before the credential row. Another counted row keeps the
  revoke ordinary. The last counted row stays until an explicit
  last-access confirmation.

## Impact

- Capabilities: ADDED `managed-custody`.
- ADRs: none. `docs/custody-ladder.md` already separates the access
  axis from custody. This change does not amend it.

## User journey & surfaces

No new UI because this change names which records exist. The account
page already lists passkey rows. Showing the server-held operational
public key is `add-managed-key-visibility`. Adding, renaming, and
removing passkeys is `add-passkey-account-management`.

## Out of scope

- Building the account-access revocation operation and its
  confirmation. The rule is this change. `identikey-core-zlf.6`
  owns the kind-generic operation, the passkey confirmation
  surface, and the concurrent-revoke verification. Folding this
  model is not that landing.
- Whether a recovery-enrolled passkey is purpose-limited. That is
  `add-recovery-authority` (`identikey-core-zlf.2`).
- Whether a password credential is in this intention, and the
  password hasher. That is `add-password-credential`
  (`identikey-core-zlf.9`). If that node adds the kind, the living
  device requirement already lists and revokes the row.
- The account-page presentation of the managed public key
  (`identikey-core-zlf.8`).
- The email magic-link ceremony (`identikey-core-zlf.7`).
- Native enrollment (`identikey-core-zlf.11`).
- SMS OTP (`identikey-core-vt4.4`), OP JWKS rotation
  (`identikey-core-ccf.9`), guild keyspaces (`identikey-core-trr`),
  guardian and successor key recovery, a `devices` table,
  `device_trust`, `is_master`, and minting Elect from an account
  cookie or a mailbox.
