# Tasks

- [ ] Session open accepts one ML-DSA-65 signature by the control key of the cited unforked head, over the XID, that digest, an audience, and a fresh challenge
- [ ] A classical signature does not open a session, and a forked chain does not
- [ ] A follow-up proof verifies as HMAC-SHA-256 under the session key and does not require a public-key signature
- [ ] A proof for another audience or another state digest fails
- [ ] The verifier writes no proof log

## Owed from advise — astra-arch-review, 2026-10-27

- [ ] R1: Specify verifier expectations for audience/challenge, ownership and atomic consumption of challenge freshness, and follow-up replay semantics; add unexpected/consumed challenge and wrong expected-audience scenarios. Caller-managed freshness is permitted. See `reviews/2026-10-27-advise.md`.
- [ ] R2: Specify the external authenticated-secret binding precondition and how a session binds its supplied key to the accepted opening; prevent cross-opening MAC reuse and cover distinct openings with the same audience/digest. Keep key establishment and the unverified ML-KEM spike out of scope.
- [ ] R3: Choose current-authority or opening-time authority semantics for established sessions; define the lifetime/revocation boundary and add follow-up scenarios after rotation, loss of authority, and a detected fork. Correct the older-digest scenario to test the chosen semantics.
- [ ] R4: Pin exact versioned, domain-separated opening and MAC byte encodings, field validation, full tag length, and constant-time tag verification; include a byte-level vector and malformed/ambiguous-encoding checks.
- [ ] Obtain fresh advise after reconciling R1–R4 and before implementation.

## Out of scope

- Key establishment. `pq-session-secret` stays unverified. Do not start it.
