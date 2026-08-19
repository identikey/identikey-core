# Design — WebAuthn ceremonies in Rust

Security: use `webauthn-rs` (already in the workspace, MPL-2.0).
RP ID and origins come from `parse_webauthn_config` (`62j`). No
wildcards. Related origins already served (`2js`).

## Proof vs URN grant

A passkey assertion proves Auth to the party holding the key
(A3, C1/C2). It completes `/authorize`. It MUST NOT be accepted
as the URN grant (ADR-005).

## Storage

Existing `credentials` passkey columns (`webauthn_credential_id`,
`cose_public_key`, `sign_counter`, `aaguid`). Do not add a
`devices` table. Do not emit `device_trust`.

## Differential tests

Tag `pre-rust-pivot` holds the TS ceremonies. New tests should
match challenge/verify outcomes on shared fixtures where the TS
vectors still apply. Do not import Keycloak.

## Login finish

After a verified assertion, call the existing `issue_code` path
with the account XID. Dev-login stays flag-gated and separate.
