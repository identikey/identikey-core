# Independent blind take — add-a1-account-recovery

Written before reading the change delta, design, or tasks; inputs: proposal Why, living account-recovery spec, and `crates/identikey-recovery/src/lib.rs:20-103`.

1. Pin the library boundary: hosted email recovery already exists; this node must make the library's currently unchecked proof meaningful.
2. Pin account identity and allowed recovery purpose to each issued factor, verified proof, and resulting managed access.
3. Pin C1/C2 eligibility and refuse any path from an A1 proof to key recovery, raw keys, Elect keys, or challenge signing.
4. Refuse publicly forgeable success proofs, including keeping `AccountRecoveryProof::granted()` as a production bypass.
5. Pin email and SMS as supported library channels, with delivery separated from verification and no requirement to replace the hosted journey.
6. Pin the authority that chooses a recovery destination: possession of an arbitrary caller-supplied address must not recover someone else's account.
7. Pin expiration, cryptographic unpredictability, bounded guesses, and atomic single use, including concurrent redemption and failed attempts.
8. Pin persistence and clock responsibilities so restart, multiple workers, and caller-controlled timestamps cannot silently weaken verification.
9. Preserve hosted email uniqueness, same-XID replacement passkeys, and the prohibition on signing from a recovery session; integration scope must be explicit.
10. Tradeoff: a small synchronous store/delivery abstraction is reasonable, provided security-critical atomicity and caller trust obligations are testable contracts.
