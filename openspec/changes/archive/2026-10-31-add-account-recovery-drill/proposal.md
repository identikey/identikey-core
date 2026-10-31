# add-account-recovery-drill

> **ACTIVE BUILD**

Node `identikey-core-zlf.10`. Activated 2026-10-31. The authority
matrix, the email link, and passkey management have landed.

## Why

The pieces exist separately. This journey is the one that proves a
person who has lost every passkey comes back to the same XID and
that the next signing attempt follows the recovery matrix.

## What

- Capability `account-recovery`.
- Remove every passkey through account-access revocation, including
  the last-access confirmation.
- Redeem the email magic link for that XID.
- Enroll one replacement passkey. It is an ordinary passkey.
- The next C2 signing attempt with only the recovery session does
  not sign. A fresh assertion of the replacement passkey does, on
  ordinary consent terms.
- No second token store and no devices table. The email link's
  token store is the one already landed.

## Impact

- Capabilities: ADDED `account-recovery`.
- ADRs: none.

## User journey & surfaces

Who: the account holder who no longer has a passkey, and who already
has a verified recovery address.

Working: confirm removal of the last passkey, redeem the email link,
save a new passkey, sign a Challenge with that passkey.

Failed: the recovery session alone does not sign. A second account
does not receive the new passkey.

Off: notifications and a waiting period were not recorded by the
authority node, so this journey does not add them.

## Out of scope

- A new mailer. Begin still returns the redeem URL to the signed-in
  caller.
- Password login (`identikey-core-zlf.9`).
- SMS.
- Choosing the native enrollment journey (`identikey-core-zlf.11`).
