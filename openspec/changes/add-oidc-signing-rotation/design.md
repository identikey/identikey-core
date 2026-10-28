# add-oidc-signing-rotation

## Overlap

`SigningKey` today is the key that signs. Rotation adds a retiring
public key beside it. JWKS is the union: the current public key, and
the retiring public key while `now < retired_at + 3600s`.
`retired_at` is the instant the new key became the signer.

New ID tokens carry the new `kid`. Verification of an old ID token
uses the key still in JWKS. When the window ends, JWKS omits the old
key. Restart during the window still serves it, so the public key and
`retired_at` are stored next to `signing.jwk`, not in memory only.

The old private key is not part of that record. Signing has already
moved.

## Salt

`PairwiseSalt` stays the type in `salt.rs`, loaded from
`pairwise.salt` or `IDENTIKEY_PAIRWISE_SALT`. The rotation function
takes a `SigningKey` and does not take a `PairwiseSalt`. It does not
open `pairwise.salt`. A test captures `as_bytes` before and after.

## Not XID rotation

No call into Elect, the state chain, or `bc-xid` document updates.
The OP service key and a person's inception key do not share a
function.
