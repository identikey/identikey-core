# Tasks

- [x] Fresh advise after preparation (accept, reviews/2026-10-21-advise.md; proposal 1b0de51cc142, design 8f5b1266e298, spec managed-custody c5b8ff193364)
- [x] Allow purpose `rewrap` on `encapsulation_attempts`, and store the friend XID and the 32-byte recipient only for that purpose. Export stays without them. Unwrap stays digest-only.
- [x] Extend the encapsulation transcript so `rewrap` appends the wrap digest and then the recipient. Pin `c5266850c16f4ed35cbddb4a37a4bbac6faf6a421690dc7c110c3c876302caa7`. Keep the export and unwrap pins.
- [x] Begin loads the friend's document and stores that recipient. Reject a missing recipient, a small-order recipient, and a friend equal to the owner before insert.
- [x] Rewrap, in one transaction, verifies the A3 or A4 proof, reloads the friend, refuses a changed recipient before open, opens the seal, and returns a new §7 wrap. Zeroize the data key. No HTTP body returns the data key or the scalar.
- [x] `POST /account/encapsulation/rewrap` returns that wrap as unpadded base64url, `text/plain`, `Cache-Control: no-store`, no HTML, outside SPA CORS. A cookie alone is refused.
- [x] The same transaction writes `encapsulation_rewrap` and a custody event. Audience is the friend's base58btc XID. Purpose is the hex wrap digest.
- [x] Tests cover the pinned digest, a restarted caller that does not hold `PrivateKeyBase`, wrong wrap, rotated friend key, small-order recipient, null seal, cookie-only, SPA origin, second finish, and a body that is the wrap.
- [x] Regenerate `.sqlx` against `identikey-core-sqlx`. Do not migrate `identikey-core-test`.
- [x] Amend ADR-012 item 4 so the production open is this rewrap. Do not rewrite the `fcdb920` live-instance paragraph.
