//! OIDC provider — the bridge between the custody ladder and relying parties that
//! only speak OAuth.
//!
//! # What belongs here
//!
//! The standard endpoints (`/authorize`, `/token`, `/userinfo`, `/introspect`,
//! `/revoke`, discovery, JWKS), the `urn:identikey:params:oauth:grant-type:challenge-response`
//! grant, and token minting.
//!
//! # Two boundaries this crate must not cross
//!
//! **It never holds a private key.** Token minting is a projection of an identity
//! this crate does not own. Key custody lives in [`identikey_keys`]; a C4
//! sole-custody user has a `sub` here that no key in this process could ever
//! produce a signature for. If key material appears in this crate, the custody
//! ladder has collapsed.
//!
//! **The URN grant accepts only an `identikey-auth` `Response` — never a WebAuthn
//! assertion** (ADR-005). A WebAuthn assertion proves "I hold a passkey registered
//! against an account"; the grant needs "I hold the key." Accepting the weaker
//! proof at the token boundary would defeat the privilege separation that makes
//! managed custody (C2) different from custodial (C1), and would let an
//! account-recovery path reach key authority — the merge that invariant I2 makes
//! a release blocker.
//!
//! Pairwise salt is loaded at boot (`PairwiseSalt`). `sub` is still a single
//! seam to be added (`identikey-core-duw`). See `docs/oidc-implementation-checklist.md`.

pub mod salt;
pub mod subject;

pub use salt::{PairwiseSalt, SaltError};
pub use subject::{Client, SubjectError, SubjectType, subject};
