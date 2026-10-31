# add-passkey-signal-api

> **ACTIVE BUILD**

Bead `identikey-core-5gh.3`. Passkey add, rename, and
`revoke_device` are `identikey-core-5gh.6`, not this change.
Depends on the passkey ceremonies and hosted pages already in the
living spec. Preparation 2026-10-30: `openspec/specs/passkeys/spec.md`
still names this slice as later work. `finish_assert` returns
`FinishedAssertion` and the login page reads only `redirect`
(`json_redirect`). Unknown credentials still fail as
`credential not found` (`CeremonyError::UnknownCredential`).
`pages-login.js` still shows "Try another passkey" for that
message. Signup and device approval are the other success pages.
Passkey removal is `revoke_device` on the `kind = passkey`
credentials row, owned by `identikey-core-5gh.6`. WebAuthn `user.id` is
`xid_user_id` (UUID v5). Outcome: revised. Amended 2026-10-30 after
`reviews/2026-10-30-advise.md` (send-back, `opus-arch-review`):
encodings are unpadded base64url, an empty list is not signaled,
the call cannot hang navigation, a foreign XID is a different
error, and `localhost` does not call `signalUnknownCredential`.
Authority: the account-keys first-wave grant on
`identikey-core-zlf` ("activate first wave"). It covers this node
and does not include act. It supersedes the 2026-10-28 note that
the post-quantum grant left activation off.

## Why

A provider keeps offering passkeys this server no longer stores, and
it keeps a passkey that never belonged to an account. The WebAuthn
Signal APIs are how the page tells the provider. They are hints. A
missing function or a throw must not change whether the person got
in.

## What

- Capability `passkeys`.
- After registration or assertion succeeds, the page calls
  `signalAllAcceptedCredentials` with the RP ID, the same WebAuthn
  user handle `xid_user_id` already uses, and every credential id
  stored for that XID.
- The success JSON carries that handle and those ids beside the
  existing redirect or `next` field. Device approval has no redirect;
  it still receives the list.
- When assert finish fails with `credential not found`, the page calls
  `signalUnknownCredential` for the id it just sent.
- Any other failure calls neither function.
- `signalCurrentUserDetails` is not called. Nothing renames the XID.

## Impact

- Capabilities: MODIFIED `passkeys` (one added requirement). The
  preamble's "later slice" sentence is fold's to update.
- ADRs: none.

## User journey & surfaces

The person is on `/authorize/passkey`, `/signup`, or the device
approval page. Those pages stay as they are.

Working: the ceremony succeeds, the page tells the provider the full
stored id list, and then the page does what it already does. Login
follows `redirect`. Signup with an app returns to the passkey page.
Signup without an app opens `next` or `/account`. Device approval
shows "Approved".

Empty: an assertion with no stored passkey still fails before a
success signal. The first saved passkey signals that one id.

Failed: `credential not found` reports that id as unknown and still
shows the existing failure, including "Try another passkey" on the
login page. Expired ceremonies, user cancel, and other errors show
the existing failure and do not signal.

Off: a browser without the functions, or a call that throws, still
redirects, navigates, or shows "Approved" exactly as it does now.

## Out of scope

- `signalCurrentUserDetails`. No surface renames `user.name`.
- Signaling after a passkey is removed. Removal is
  `identikey-core-5gh.6` (`revoke_device` on the passkey row).
- Synced-passkey counter policy (`identikey-core-5gh.4`,
  `add-passkey-counter-policy`). This change does not edit the
  counter checks.
- Whether a provider actually drops the passkey. The owed check is
  the page call and an unchanged ceremony result.
- Passkey login, the URN grant, and classical OIDC token signatures.
