1. Pin recovery authority to restoring account access; an A0 or A1 proof must never directly exercise the managed Sign key.
2. Pin the recovered passkey to the ordinary signup credential model, with identical listing, login, consent, and revocation behavior.
3. Require an explicit boundary between a recovery proof and subsequent ordinary passkey authentication before operational signing authority is available.
4. Bind every recovery authorization to one account, one purpose, a bounded lifetime, and one successful credential-registration ceremony.
5. Refuse replay, cross-account substitution, and concurrent double redemption; proof consumption and credential creation must have a defined atomic outcome.
6. Keep verified email on accounts.email under its existing case-insensitive uniqueness rule; recovery must not synthesize an email credential or device.
7. Refuse any recovery path that silently decrypts, signs with, rotates, or replaces managed_key_blob, or mints Elect from A0/A1 proof alone.
8. Preserve existing access unless an explicitly specified operation revokes it; recovery must not invent a second surviving-access policy or alter revoke_device.
9. Require failed, expired, or conflicting recovery attempts to leave account access and operational key material unchanged, with testable negative cases.
10. Accept the tradeoff that mailbox recovery can establish a new ordinary login, provided its proof cannot be reused as an operational signing credential.
