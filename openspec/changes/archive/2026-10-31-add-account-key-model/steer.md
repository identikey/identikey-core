# steer add-account-key-model

**When.** 2026-10-30
**Depth.** explicit

## Decided

- Surviving access: account logins (user)
  Why: a live passkey, Apple or Google login, native `identikey_auth`
  key, or a password row (only if that kind exists) can still sign
  the person into the account. An `ssh_git` row cannot. Removing the
  last passkey while one of those remains is an ordinary revoke.

## Skipped

- None on this node.

## Feeds change

Record the account-login rule in the delta. Kinds that count:
`passkey`, `oidc_apple`, `oidc_google`, `identikey_auth`, and a
password kind only when that row exists. `ssh_git` does not count.
Recovery authority and the password spike were decided on their own
nodes, not in this change.

## Activation

2026-10-31. The human activated this node. The account-login rule is
in the delta. The banner is ACTIVE BUILD.
