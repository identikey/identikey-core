# improve-passkey-recovery

> **ACTIVE BUILD**

Archived 2026-09-19. Folded into `openspec/specs/passkeys/spec.md`.

## Why

Hosted sign-in currently shows raw API errors and reuses a consumed challenge
after a failed assertion. Users cannot tell whether to retry, find another
passkey, or sign up. Signup retries can create unnecessary accounts.

## User journey & surfaces

On `/authorize/passkey`, existing users choose a passkey. Failures explain what
to do, offer another attempt with a fresh challenge, and expose help for another
manager/device. New users can create an account without losing authorization
context. Technical details remain collapsed and selectable. `/signup` explains
the new-account consequence and allows returning to sign-in with that context.
Cancellation does not imply a missing account. Local installs identify themselves.

## Scope

Hosted HTML/JS/CSS, browser regression checks, and the passkeys specification.
OAuth JSON errors and server verification rules remain unchanged. Account
recovery, passkey synchronization, deletion, and automatic account merging are
not implemented here.
