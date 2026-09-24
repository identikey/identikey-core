# Independent blind take — add-managed-challenge-responder

Written before opening design.md, tasks.md, or the delta; evidence limited to the packet's Why, living specs, cited code, and named learning.

1. Pin Ed25519 for the managed operational Sign+Auth key, with an explicit stored format and a public key that matches the current XID document.
2. Preserve the user's Elect privileges and X25519 wrap target; changing the operational algorithm must not grant the server management authority.
3. Refuse legacy Schnorr blobs explicitly and remint through signup; never reinterpret old bytes as an Ed25519 private key.
4. Accept only a parsed canonical identikey-auth v1 Challenge and return its protocol Response; refuse arbitrary-byte signing and private-key export.
5. Bind fresh A3 or user-held A4 authorization to the exact challenge digest, account, and signing ceremony; neither a cookie nor our Sign key authorizes C2 use.
6. Pin expiry, replay, credential revocation, and one-use authorization behavior, including concurrent attempts and challenge substitution.
7. Persist signing_instruction_authorized before private-key use, correlate completed/failed outcomes, and fail closed when the audit cannot be persisted.
8. Recheck custody and operational-key authority at use so rotation or C2→C3 exit cannot leave a stale signing capability available.
9. Release the Response only to the initiating client; define that binding without turning core into the edge's verifier or an arbitrary callback sender.
10. Tradeoff: fresh challenge-bound consent adds a ceremony and retry complexity, but preserves the C2 privilege boundary while keeping the edge custody-agnostic.
