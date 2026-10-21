# add-friend-rewrapping

## Decisions

1. **Purpose `rewrap`.** It is not `unwrap` and not `export`. Begin requires the source wrap and the friend's XID as base58btc. The server loads that XID's current `c2_wrap_recipient` and stores those 32 bytes plus the friend's 32-byte XID. The client does not supply the public. Begin rejects a missing document, a missing recipient, a small-order recipient, and a friend XID equal to the owner, and it inserts no row.

2. **Transcript.** Same domain and prefix as export. Purpose ASCII is `rewrap`. After `exp`, append the 32-byte wrap digest, then the 32-byte recipient. Pinned SHA-256 with the export vector's XID, attempt id, challenge, `iat`, and `exp`, wrap digest thirty-two `0x44` bytes, and recipient thirty-two `0x55` bytes: `c5266850c16f4ed35cbddb4a37a4bbac6faf6a421690dc7c110c3c876302caa7`. The existing export and unwrap pins stay.

3. **Finish rechecks the friend.** In the same transaction, after the proof matches and before the seal opens, reload the friend's document. If `c2_wrap_recipient` is missing or differs from the stored recipient, return before open. Then open, reject a wrong wrap digest and a small-order ephemeral or all-zero DH, wrap the 32-byte data key to the stored recipient with `wrap_data_key`, zeroize the data key, and return only the new wrap.

4. **HTTP.** `POST /account/encapsulation/rewrap` returns unpadded base64url of that wrap, `text/plain; charset=utf-8`, `Cache-Control: no-store`, no HTML. Begin, export, and rewrap stay outside SPA CORS. A cookie without an A3 assertion or an A4 Elect signature is refused. There is still no hosted unwrap route.

5. **Audit.** Same transaction writes consent-log action `encapsulation_rewrap`, result `signed`, audience the friend's base58btc XID, purpose the lowercase hex of the source wrap digest, plus a custody event. `encapsulation_attempts.purpose` gains `rewrap`. A `rewrap` row stores the wrap digest, the friend XID, and the recipient. Export still stores none of those. Unwrap still stores only the digest.

6. **Not a proxy.** The operator who holds the managed wrap key can perform this open. Consent is policy. The Mjolnir VM is not in this change and must not receive the scalar. Rewrap does not write a keyspace op. Sharing a house PTK is possible only when the caller already has that wrap and a matching consent.

## Preparation

Still the note in `proposal.md`. Contract matches the menu choice. Fresh advise is owed before implementation.
