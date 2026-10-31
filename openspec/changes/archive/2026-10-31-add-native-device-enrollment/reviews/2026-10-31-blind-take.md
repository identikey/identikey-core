# Independent blind take — add-native-device-enrollment

1. Pin Papyrus as the first native client, with an explicit boundary between local identity creation and enrollment into an OP account.
2. Pin the OP device record to an ordinary `credentials` row with a supported login kind, rather than introduce a separate device authority.
3. Require authenticated account authorization and fresh possession of the exact native public key before attaching that key to the account.
4. Bind enrollment proof to the intended account, OP, operation, key, and expiring single-use attempt so it cannot be substituted or replayed.
5. Refuse to treat Papyrus `device_enroll` as remote enrollment: it currently returns local identity metadata without contacting the OP.
6. Refuse to infer hardware protection from the `enclave` feature; `device_signer` may return Secure Enclave, TPM, or persisted software.
7. Require explicit software-fallback behavior and honest backend labels; a reported backend alone must not become trusted hardware attestation.
8. Pin how the new credential actually authenticates an account, so its inclusion in surviving-access counts cannot conceal an unusable login.
9. Preserve unconditional `revoke_device`, use the shared account-access revocation policy for account UI, and make revoked native keys fail authentication.
10. Accept a narrow Papyrus-first integration as a tradeoff against multi-client scope, provided retry, cancellation, duplicate enrollment, and authority boundaries are specified.
