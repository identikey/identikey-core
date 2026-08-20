# add-urn-grant

> **ACTIVE BUILD**

Activated from `identikey-core-ccf.5`. Unblocked: `identikey-core-h4p`
is closed (ADR-005).

**Rigor:** change

## Why

`urn:identikey:params:oauth:grant-type:challenge-response` is how a
C4 user who holds their own key talks to ordinary OAuth RPs without
the OP ever holding that key. The ladder joins here. A WebAuthn
assertion must never satisfy this grant (ADR-005 / I2).

## What

- Write or cite the grant wire format in
  `identikey-protocol` (`docs/standards/`) before minting tokens
- `/token` accepts the URN grant with an `identikey-auth` `Response`
  only
- Refuse a WebAuthn assertion at this grant
- Mint tokens through the existing `sub()` seam
- Capability `oidc-provider` (ADDED)

## Impact

- Capabilities: ADDED on `oidc-provider`
- ADRs: none (implements ADR-005)

## User journey & surfaces

No new UI because the client is an A4 signer, not a browser form.
Intended path: native/enclave signs an `identikey-auth` Response →
POST `/token` with the URN grant → standard tokens.

## Out of scope

- Accepting WebAuthn at this grant — ADR-005 forbids it
- Authorization-code passkey login — `add-passkey-ceremonies`
- Confidential clients — `add-confidential-clients`
- Account UI — `ccf.11`
