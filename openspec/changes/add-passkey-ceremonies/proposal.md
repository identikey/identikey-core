# add-passkey-ceremonies

> **PENDING**

Drafted from `identikey-core-5gh.1`. Unblocked: ADR-004 (`pdt`) and
boot config (`62j`) / related origins (`2js`) have landed.

**Rigor:** change

## Why

Production login at `/authorize` is still the flag-gated XID paste.
A3 is a passkey. Port registration and assertion to `webauthn-rs`,
differential-tested against the TypeScript at tag `pre-rust-pivot`.

## What

- Registration ceremony (create options + verify attestation)
- Assertion ceremony (request options + verify assertion)
- Store credentials in existing `credentials` rows (passkey shape)
- Complete `/authorize` with a verified assertion (not the URN grant)
- Differential tests vs `pre-rust-pivot`
- Capability `passkeys` (ADDED); `oidc-provider` (ADDED login path)

## Impact

- Capabilities: ADDED `passkeys`; ADDED on `oidc-provider`
- ADRs: none (implements ADR-004)

## User journey & surfaces

Intended path: RP hits `/authorize` → user registers or asserts a
passkey → redirect with `code`. Dev-login remains a separate
flag-gated route.

No production account UI because listing/nicknames are `5gh.2` /
`ccf.11`. Ceremonies may be JSON endpoints plus a minimal page if
the browser must see WebAuthn; that page is this change's surface.

## Out of scope

- AAGUID nicknames — `5gh.2`
- Signal APIs — `5gh.3`
- Synced-passkey counter policy — `5gh.4`
- caBLE / QR temporary device — `5gh.5`
- URN grant — `add-urn-grant`
- Passwords as default
- `device_trust` / `is_master` claims
