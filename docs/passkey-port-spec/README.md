# Passkey port spec

**Status:** Reference material, not a plan. Kept deliberately; everything else from the
BMAD-era `_bmad-output/` was deleted on 2026-08-07 (`identikey-core-sbw.1`).

These five documents are the acceptance criteria and edge-case notes for the WebAuthn
work that shipped in TypeScript — challenge storage, registration and authentication
challenge generation, attestation validation, and assertion verification. They are the
**specification** for `identikey-core-5gh.1`, the port to `webauthn-rs`.

They survive because the hard part of WebAuthn was never the code; it was working out
which cases matter. That reasoning is expensive to re-derive and cheap to keep.

## How to read them

They describe the TypeScript implementation at tag `pre-rust-pivot`, whose source is in
`src/lib/passkey/`. Read them for **what must be true**, not for how it was structured.
The Rust port has different bones: `webauthn-rs` owns the ceremony state machine, so
several things these documents hand-roll are handled by the library.

## What has changed since they were written

Do not follow these documents where they conflict with the decisions below.

- **RP ID is `auth.identikey.me`** (ADR-004). These predate that call. Configuration is
  a strict allowlist with no wildcards — `identikey-core-62j`.
- **Keycloak is gone.** Any reference to storing credentials via the Keycloak Admin API
  is dead. Postgres is the store — `identikey-core-zan.1`.
- **Passkeys are access level A3 only** (`docs/custody-ladder.md`) — authentication to a
  remote party at C1/C2. They are not a custody rung, and at C3/C4 a passkey is at most
  a key-wrapping mechanism via the `prf` extension, never a proof of identity.
- **A WebAuthn assertion cannot obtain tokens through the URN grant** (ADR-005). The
  grant accepts only an `identikey-auth` `Response`. These documents were written when
  that boundary was still open.
- **9-6 (credential CRUD) was cancelled**, not lost. It returns in Rust as
  `identikey-core-5gh.2` and `5gh.3`, with AAGUID resolution and Signal API hygiene that
  the original story did not cover.

The canonical architecture is `docs/ARCHITECTURE.md`. The canonical rung definitions are
`docs/custody-ladder.md`. Where either disagrees with a document in this directory, they win.
