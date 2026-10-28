# Tasks

- [ ] Session open accepts one ML-DSA-65 signature by the control key of the cited unforked head, over the XID, that digest, an audience, and a fresh challenge
- [ ] A classical signature does not open a session, and a forked chain does not
- [ ] A follow-up proof verifies as HMAC-SHA-256 under the session key and does not require a public-key signature
- [ ] A proof for another audience or another state digest fails
- [ ] The verifier writes no proof log

## Out of scope

- Key establishment. `pq-session-secret` stays unverified. Do not start it.
