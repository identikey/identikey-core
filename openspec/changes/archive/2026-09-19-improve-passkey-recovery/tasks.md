# Tasks

Completed locally 2026-09-19; production deployment is not part of this change.

- [x] Add actionable failure feedback, contextual passkey help and optional diagnostics.
- [x] Renew consumed assertion challenges without losing OIDC context.
- [x] Reuse the pending signup account on cancellation/failure retries.
- [x] Verify browser failures, successful integration, keyboard/mobile behavior and Rust checks.
- [x] Fold behavior into the passkeys specification and archive.

Evidence: nine browser checks pass, including an actual unregistered virtual
authenticator. Complete Taskmaster signup/login/logout/isolation passes. Rust
page tests and hosted page/routing checks pass; build and JavaScript syntax checks
pass. Two existing Rust SoftPasskey tests reject required resident keys with
NotSupported; the browser integration covers these paths without relaxing policy.
