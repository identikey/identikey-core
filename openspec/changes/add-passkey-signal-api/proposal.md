# add-passkey-signal-api

> **PENDING**

Bead `identikey-core-5gh.6`, extracted from `identikey-core-5gh.3`.
Depends on the passkey ceremonies and hosted pages already in the
living spec. Preparation 2026-10-28: `openspec/specs/passkeys/spec.md`
names this slice as later work. `finish_assert` returns
`FinishedAssertion` and the login page reads only `redirect`
(`json_redirect`). Unknown credentials already fail as
`credential not found` (`CeremonyError::UnknownCredential`).
`pages-login.js` already shows "Try another passkey" for that
message. Signup and device approval are the other success pages.
No passkey-removal route exists. WebAuthn `user.id` is
`xid_user_id` (UUID v5). Outcome: new contract. Authority: none.
The post-quantum campaign grant does not cover this node.
Activation stays off.

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
- Signaling after a passkey is removed. No removal control exists.
- Synced-passkey counter policy (`identikey-core-5gh.4`). A counter
  that does not increase still fails closed in `finish_assert`.
- Whether a provider actually drops the passkey. The owed check is
  the page call and an unchanged ceremony result.
- Passkey login, the URN grant, and classical OIDC token signatures.
