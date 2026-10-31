# add-password-credential

> **PENDING**

Node `identikey-core-zlf.9`. The key model, the email link, and
passkey management have landed. This node was not in the
2026-10-31 activate-and-run grant. The hasher spike is go:
Argon2id m=19456 KiB, t=2, p=1 (`docs/spikes/password-hasher/finding.md`).
This node stays pending until a human activates it.

## Why

An account that already has a passkey may also have a password that
logs into the same XID. The password is a credential row, not a
second identity and not consent for the server-held Sign key.

## What

- Capability `oidc-provider`.
- A password is a new `credentials` kind. The row stores a hash, not
  the password.
- It is listed and revoked with the other devices.
- Password login uses authorization-code plus PKCE and resolves to
  the same XID as the passkey.
- There is no resource-owner password grant, no new signup, and no
  reset in this node.
- An A0 password proof does not consent to C2 signing.

## Impact

- Capabilities: ADDED `oidc-provider`.
- ADRs: none.

## User journey & surfaces

Who: a person who already has a passkey and a verified email.

Working: attach a password, sign in with it, and reach the same
XID. Revoking the row hides it.

Failed: the password does not sign a Challenge. A missing hasher
finding means this journey is not built.

Off: this change stays pending while the hasher spike is unverified.

## Out of scope

- The hasher recipe until the spike says go.
- Password reset.
- SMS.
- Native enrollment.
