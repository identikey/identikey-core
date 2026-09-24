1. Pin this node to C2 operational Sign+Auth; any C1 authorization policy needs its own explicit contract.
2. Pin Ed25519 private/public correspondence across persisted material, the C2 document, and the identikey-auth software signer; refuse Schnorr protocol expansion.
3. Preserve the user's Elect/Transfer privileges and X25519 wrap target; changing our operational key must not silently reassign management authority.
4. Accept only bounded, canonical v1 Challenge bytes and bind authorization to their exact digest; refuse arbitrary signing payloads or public blob access.
5. A fresh account-bound A3 assertion or genuinely user-held A4 proof must authorize this instruction; a cookie or our own Sign key cannot supply consent.
6. Bind the ceremony to the initiating client, challenge, account, expiration, and one-time use so swapped inputs, stolen identifiers, and retries cannot redirect a Response.
7. Serialize key use against custody exit, document changes, and credential revocation; a previously approved instruction must not outlive the authority it relied on.
8. Persist authorization before private-key use and completion/failure afterward, with explicit fail-closed and crash/retry semantics that never release an unaudited Response.
9. Keep verifier duties at the edge while enforcing local challenge validity and user-visible intent; test the real signup blob through an independent verifier.
10. Tradeoff: reminting legacy Schnorr identities avoids migration ambiguity but changes identity; make rejection explicit and keep Elect export and existing OIDC behavior outside this slice.
