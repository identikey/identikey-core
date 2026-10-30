# add-a1-account-recovery

> **PENDING**

Bead `identikey-core-vt4.5`, from `identikey-core-vt4.4`. Steer 2026-10-30.
**Rigor:** architecture

**Preparation:** 2026-10-30. Upstream artifact is `identikey-core-vt4.1`
(closed): `AccountRecoveryProof` cannot reach key bytes, and
`restore_key` accepts only `KeyRecoveryProof`. `ProofKind::EmailLink`
and `ProofKind::SmsOtp` exist on the consent hash and have no ceremony.
`KeysStore::create_managed` already rejects a rung that does not hold a
managed key. Outcome: new contract. Authority: none. The
`identikey-core-pgz` grant does not cover this node.

## Why

A lost passkey on a managed account has no in-repo way back on. The
custody ladder already names email and SMS as access level A1, for
account bootstrap and account recovery at C1 and C2. The recovery crate
holds that line as marker types only. `AccountRecoveryProof::granted`
succeeds without checking a factor.

## What

- Add the email and SMS factor ceremony to `identikey-recovery`.
- Success returns `AccountRecoveryProof` and consumes the factor.
- Bootstrap authorizes creating a managed account. Recovery authorizes
  passkey enrollment on the bound C1/C2 XID.
- The proof never carries key bytes. C3 and C4 do not recover.
- Capability: ADDED `account-recovery`.

## Impact

- Capabilities: ADDED `account-recovery`
- ADRs: none

## User journey & surfaces

No new UI because this change is a library. It does not add a page, an
HTTP route, or a mail or SMS transport. A later route change is what a
person would open. Working: a matching factor returns a proof tagged
bootstrap or recover. Empty: an unknown destination or an unknown
factor fails. Failed: a wrong, expired, replayed, or C3/C4 factor
returns no proof. Off: the caller does not send a factor, and no
account is created.

## Out of scope

- HTTP routes, hosted pages, and the mail or SMS vendor. Not this change.
- Social re-verification. `identikey-core-ccf.6`, still PENDING.
- Guardian selection and SSKR. `identikey-core-vt4.3` and `identikey-core-vt4.2`.
- Pre-rotation and superseding recovery. `identikey-core-zan.5` and `identikey-core-wzr`.
- Generating or returning `managed_key_blob`. Signup already seals that blob.
- Post-quantum session proofs. `add-pq-session-proof`.
