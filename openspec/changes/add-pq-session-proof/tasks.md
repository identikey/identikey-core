# Tasks

- [ ] Session open accepts one ML-DSA-65 signature by the control key of the cited unforked head, over the XID, that digest, an audience, and a fresh challenge
- [ ] A classical signature does not open a session, and a forked chain does not
- [ ] A follow-up proof verifies as HMAC-SHA-256 under the session key and does not require a public-key signature
- [ ] A proof for another audience or another state digest fails
- [ ] The verifier writes no proof log

## Owed from advise — astra-arch-review, 2026-10-27

- [x] R1: The verifier supplies the expected audience and challenge. Success consumes the challenge. Failure, an unexpected challenge, and a consumed challenge do not open a session. A follow-up MAC is reusable and is not a fresh action.
- [x] R2: The signature does not establish the key. The caller supplies a key only when establishment outside this change bound it to that opening and peer. The MAC names the opening id, so two openings with the same audience, digest, and key do not share a proof. The ML-KEM spike stays out of scope.
- [x] R3: A follow-up resolves the session digest through current trust. Rotation, a fork, or missing authority rejects it. A successful MAC does not outlive those events.
- [x] R4: Opening and MAC bytes are canonical dCBOR with the domains `identikey-pq-session/v1` and `identikey-pq-session-mac/v1`. The tag is 32 bytes, compared in constant time. The delta includes the vector and rejects a non-canonical encoding.
- [ ] Fresh advise after preparation

## Out of scope

- Key establishment. `pq-session-secret` stays unverified. Do not start it.
